//! Fixer: proposes and applies auto-fixes for detected violations.
//!
//! The write path is CHP-gated (see `cac-chp`): `apply_gated` runs the
//! deterministic parity pre-check, the adversary, R0, the human-lock flow,
//! and the decision ledger for every proposal. Ungated writes are
//! structurally refused — `apply` only executes in dry-run mode; real
//! writes must go through the gate.

use cac_chp::{parity_precheck, post_write_verify};
use cac_chp::{
    Assessment, ChpError, ChpGate, FixContext, LockPolicy, ParityEvidence, R0Evaluation,
};
use cac_core::violation::{FixProposal, Violation};
use regex::Regex;
use serde_json::json;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FixError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no auto-fix available for rule {0}")]
    NotFixable(String),
    #[error("ungated write refused: fix writes must pass through the CHP gate (apply_gated)")]
    GateRequired,
    #[error("gate error: {0}")]
    Gate(#[from] ChpError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Per-proposal result of the gated pipeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GatedOutcome {
    pub violation_id: String,
    pub decision_id: String,
    /// "applied" | "refused" | "pending_human_lock"
    pub result: String,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct GatedApplyReport {
    pub applied: usize,
    pub refused: usize,
    pub pending: usize,
    pub outcomes: Vec<GatedOutcome>,
}

pub struct Fixer {
    root: PathBuf,
    dry_run: bool,
}

impl Fixer {
    pub fn new(root: impl Into<PathBuf>, dry_run: bool) -> Self {
        Self {
            root: root.into(),
            dry_run,
        }
    }

    pub fn propose(&self, violations: &[Violation]) -> Vec<FixProposal> {
        violations
            .iter()
            .filter(|v| v.auto_fixable)
            .filter_map(|v| self.propose_for(v).ok())
            .collect()
    }

    /// UNGATED apply is disabled for real writes: dry-run previews stay
    /// allowed, any real write returns `GateRequired`. This makes the gate
    /// structurally mandatory rather than a matter of caller discipline.
    pub fn apply(&self, proposals: &[FixProposal]) -> Result<usize, FixError> {
        if !self.dry_run {
            return Err(FixError::GateRequired);
        }
        let mut matched = 0usize;
        for proposal in proposals {
            if self.matches(proposal)? {
                matched += 1;
            }
        }
        Ok(matched)
    }

    /// CHP-gated apply: the only path that writes to disk.
    ///
    /// `confirmed_by` semantics under `LockPolicy::RequireHuman` (the
    /// default): `None` stages every fix as PROVISIONAL_LOCK and records a
    /// pending-human-lock decision — nothing is written. A named confirmer
    /// locks via CHP third-party validation, then the write lands only if
    /// the post-write re-scan resolves the violation (otherwise it is
    /// reverted and refused). Under `AutoConfirm` the lock is attributed to
    /// the opt-out; under `ProposeBranch` the write lands on an isolated
    /// fix branch owned by the caller (webhook) and the human PR merge is
    /// the confirmation.
    pub fn apply_gated(
        &self,
        proposals: &[FixProposal],
        gate: &ChpGate,
        lock_policy: LockPolicy,
        confirmed_by: Option<&str>,
    ) -> Result<GatedApplyReport, FixError> {
        let mut report = GatedApplyReport::default();
        for proposal in proposals {
            let outcome = self.gate_one(proposal, gate, lock_policy, confirmed_by)?;
            match outcome.result.as_str() {
                "applied" => report.applied += 1,
                "refused" => report.refused += 1,
                _ => report.pending += 1,
            }
            report.outcomes.push(outcome);
        }
        Ok(report)
    }

    fn gate_one(
        &self,
        proposal: &FixProposal,
        gate: &ChpGate,
        lock_policy: LockPolicy,
        confirmed_by: Option<&str>,
    ) -> Result<GatedOutcome, FixError> {
        let policy_dir = gate.policy_dir().to_path_buf();
        let ctx = FixContext::new(
            &proposal.file_path,
            &proposal.original_snippet,
            &proposal.fixed_snippet,
            &proposal.description,
            &proposal.rule_id,
            &proposal.policy_id,
            violation_line(proposal),
            true,
        );

        // Every fix applied AND refused gets a decision record; gate errors
        // are recorded as refusals (fail-closed) instead of propagating.
        match self.gate_one_inner(proposal, gate, lock_policy, confirmed_by, &ctx, &policy_dir) {
            Ok(outcome) => Ok(outcome),
            Err(err) => {
                let reason = format!("gate error: {err}");
                gate.record_decision(refusal_record(
                    &ctx,
                    &reason,
                    None,
                    None,
                    None,
                    confirmed_by,
                    json!({"error": reason}),
                ))?;
                Ok(GatedOutcome {
                    violation_id: proposal.violation_id.clone(),
                    decision_id: ctx.decision_id,
                    result: "refused".to_string(),
                    detail: reason,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn gate_one_inner(
        &self,
        proposal: &FixProposal,
        gate: &ChpGate,
        lock_policy: LockPolicy,
        confirmed_by: Option<&str>,
        ctx: &FixContext,
        policy_dir: &Path,
    ) -> Result<GatedOutcome, FixError> {
        // 1. Deterministic parity pre-check on an isolated copy.
        let parity = parity_precheck(&self.root, policy_dir, ctx)?;
        // 2. Deterministic adversary over executed evidence (fatal on
        //    parity or guardrail failure).
        let assessment = gate.assess(ctx, &parity)?;
        if assessment.fatal {
            let reason = format!("adversary fatal: {}", assessment.findings.join("; "));
            return self
                .refuse(gate, ctx, &reason, &parity, &assessment, confirmed_by)
                .map(|_| self.outcome(proposal, &ctx.decision_id, "refused", &reason));
        }
        // 3. R0: is this fix scoped and solvable from the violation state?
        let r0 = gate.evaluate_r0(ctx)?;
        if !r0.passed() {
            let reason = format!("R0 FATAL: {}", r0.failed_keys().join(", "));
            return self
                .refuse(gate, ctx, &reason, &parity, &assessment, confirmed_by)
                .map(|_| self.outcome(proposal, &ctx.decision_id, "refused", &reason));
        }
        // 4. Open the decision case: PROVISIONAL_LOCK with stored proposals.
        gate.open_session(ctx, &r0, &assessment, &parity)?;

        match lock_policy {
            // Webhook fix-PR mode: write to the checked-out repo (the
            // caller commits it to an isolated cac-fix/* branch) and record
            // the decision as a proposal — the human PR merge is the lock.
            LockPolicy::ProposeBranch => self.verify_and_record(
                gate,
                proposal,
                ctx,
                &r0,
                &assessment,
                policy_dir,
                None,
                "fix_pr_proposed",
                "provisional_lock",
                "fix_pr_branch",
            ),
            // Default: nothing lands without a named human confirmer.
            LockPolicy::RequireHuman if confirmed_by.is_none() => {
                let detail = format!(
                    "fix staged as {}; nothing written until `cac confirm --decision-id {} --confirmed-by <who>`",
                    ctx.decision_id, ctx.decision_id
                );
                gate.record_decision(cac_chp::DecisionRecord {
                    decision_id: &ctx.decision_id,
                    title: &ctx.title,
                    outcome: "pending_human_lock",
                    rule_id: &ctx.rule_id,
                    policy_id: &ctx.policy_id,
                    file_path: &ctx.file_path,
                    violation_line: ctx.violation_line,
                    fix_description: &ctx.description,
                    session_status: Some("provisional_lock"),
                    r0_verdict: Some(&r0.verdict),
                    r0_results: Some(r0.results.clone()),
                    foundation_verdict: Some(&assessment.verdict),
                    foundation_score: Some(assessment.score),
                    parity: Some(parity.to_json()),
                    refusal_reason: None,
                    confirmed_by: None,
                    landed_via: "none",
                    artifacts: json!({"assessment_findings": assessment.findings}),
                })?;
                Ok(self.outcome(proposal, &ctx.decision_id, "pending_human_lock", &detail))
            }
            // Named confirmer (RequireHuman) or explicit opt-out
            // (AutoConfirm): lock via CHP third-party validation, then write.
            LockPolicy::RequireHuman | LockPolicy::AutoConfirm => {
                let confirmer = confirmed_by.unwrap_or("cac-auto-confirm (REQUIRE_HUMAN_LOCK=0)");
                let confirmed = gate.confirm(&ctx.decision_id, confirmer)?;
                if confirmed.status != "locked" {
                    let reason = format!("lock flow ended in {}", confirmed.status);
                    return self
                        .refuse(gate, ctx, &reason, &parity, &assessment, Some(confirmer))
                        .map(|_| self.outcome(proposal, &ctx.decision_id, "refused", &reason));
                }
                self.verify_and_record(
                    gate,
                    proposal,
                    ctx,
                    &r0,
                    &assessment,
                    policy_dir,
                    Some(confirmer),
                    "applied",
                    "locked",
                    "chp_gated_write",
                )
            }
        }
    }

    /// Shared tail of the confirmed write path: write, post-write
    /// verification re-scan (revert on failure), then the decision record.
    /// The pre-write parity evidence was already recorded with the staged
    /// decision; the record here carries the post-write verification.
    #[allow(clippy::too_many_arguments)]
    fn verify_and_record(
        &self,
        gate: &ChpGate,
        proposal: &FixProposal,
        ctx: &FixContext,
        r0: &R0Evaluation,
        assessment: &Assessment,
        policy_dir: &Path,
        confirmed_by: Option<&str>,
        outcome_name: &str,
        session_status: &str,
        landed_via: &str,
    ) -> Result<GatedOutcome, FixError> {
        self.write(proposal)?;
        let verify = post_write_verify(&self.root, policy_dir, ctx)?;
        if !verify.resolved {
            self.revert(proposal)?;
            let reason = "post-write parity failed — fix reverted".to_string();
            self.refuse(gate, ctx, &reason, &verify, assessment, confirmed_by)?;
            return Ok(self.outcome(proposal, &ctx.decision_id, "refused", &reason));
        }
        gate.record_decision(cac_chp::DecisionRecord {
            decision_id: &ctx.decision_id,
            title: &ctx.title,
            outcome: outcome_name,
            rule_id: &ctx.rule_id,
            policy_id: &ctx.policy_id,
            file_path: &ctx.file_path,
            violation_line: ctx.violation_line,
            fix_description: &ctx.description,
            session_status: Some(session_status),
            r0_verdict: Some(&r0.verdict),
            r0_results: Some(r0.results.clone()),
            foundation_verdict: Some(&assessment.verdict),
            foundation_score: Some(assessment.score),
            parity: Some(verify.to_json()),
            refusal_reason: None,
            confirmed_by,
            landed_via,
            artifacts: json!({"assessment_findings": assessment.findings}),
        })?;
        let detail = match confirmed_by {
            Some(who) => format!("{outcome_name} and locked by {who}"),
            None => format!("{outcome_name}; human confirmation pending"),
        };
        let result = if outcome_name == "applied" {
            "applied"
        } else {
            "pending_human_lock"
        };
        Ok(self.outcome(proposal, &ctx.decision_id, result, &detail))
    }

    fn refuse(
        &self,
        gate: &ChpGate,
        ctx: &FixContext,
        reason: &str,
        parity: &ParityEvidence,
        assessment: &Assessment,
        confirmed_by: Option<&str>,
    ) -> Result<(), FixError> {
        gate.record_decision(refusal_record(
            ctx,
            reason,
            Some((parity.to_json(), &assessment.verdict, assessment.score)),
            None,
            None,
            confirmed_by,
            json!({"assessment_findings": assessment.findings}),
        ))?;
        Ok(())
    }

    fn outcome(
        &self,
        proposal: &FixProposal,
        decision_id: &str,
        result: &str,
        detail: &str,
    ) -> GatedOutcome {
        GatedOutcome {
            violation_id: proposal.violation_id.clone(),
            decision_id: decision_id.to_string(),
            result: result.to_string(),
            detail: detail.to_string(),
        }
    }

    /// Write a gated proposal. Only reached after R0, parity, and the
    /// adversary have passed and the lock flow allowed the write.
    fn write(&self, proposal: &FixProposal) -> Result<bool, FixError> {
        let path = self.root.join(&proposal.file_path);
        if !path.exists() {
            return Ok(false);
        }
        let content = std::fs::read_to_string(&path)?;
        if !content.contains(&proposal.original_snippet) {
            return Ok(false);
        }
        let updated = content.replace(&proposal.original_snippet, &proposal.fixed_snippet);
        std::fs::write(path, updated)?;
        Ok(true)
    }

    /// Revert a write whose post-write verification failed.
    fn revert(&self, proposal: &FixProposal) -> Result<bool, FixError> {
        let path = self.root.join(&proposal.file_path);
        if !path.exists() {
            return Ok(false);
        }
        let content = std::fs::read_to_string(&path)?;
        if !content.contains(&proposal.fixed_snippet) {
            return Ok(false);
        }
        let reverted = content.replace(&proposal.fixed_snippet, &proposal.original_snippet);
        std::fs::write(path, reverted)?;
        Ok(true)
    }

    fn matches(&self, proposal: &FixProposal) -> Result<bool, FixError> {
        let path = self.root.join(&proposal.file_path);
        if !path.exists() {
            return Ok(false);
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(content.contains(&proposal.original_snippet))
    }

    fn propose_for(&self, violation: &Violation) -> Result<FixProposal, FixError> {
        match violation.rule_id.as_str() {
            id if id.starts_with("secret-") => self.propose_secret_fix(violation),
            id if id.starts_with("gdpr-") => self.propose_gdpr_fix(violation),
            id if id.starts_with("soc2-") => self.propose_soc2_fix(violation),
            _ => Err(FixError::NotFixable(violation.rule_id.clone())),
        }
    }

    fn propose_secret_fix(&self, violation: &Violation) -> Result<FixProposal, FixError> {
        let re =
            Regex::new(r#"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['"]?[^'"\s]+['"]?"#)
                .unwrap();
        let fixed = re.replace(
            &violation.snippet,
            "${1}=std::env::var(\"${1}\").expect(\"${1} must be set\")",
        );
        Ok(FixProposal {
            violation_id: format!("{}:{}", violation.file_path, violation.line),
            file_path: violation.file_path.clone(),
            original_snippet: violation.snippet.clone(),
            fixed_snippet: fixed.into_owned(),
            description: "Replace hardcoded secret with environment variable lookup".into(),
            rule_id: violation.rule_id.clone(),
            policy_id: violation.policy_id.clone(),
        })
    }

    fn propose_gdpr_fix(&self, violation: &Violation) -> Result<FixProposal, FixError> {
        let annotation = "/// @gdpr personal-data — requires lawful basis and retention policy\n";
        Ok(FixProposal {
            violation_id: format!("{}:{}", violation.file_path, violation.line),
            file_path: violation.file_path.clone(),
            original_snippet: violation.snippet.clone(),
            fixed_snippet: format!("{annotation}{}", violation.snippet),
            description: "Add GDPR data-classification annotation above PII field".into(),
            rule_id: violation.rule_id.clone(),
            policy_id: violation.policy_id.clone(),
        })
    }

    fn propose_soc2_fix(&self, violation: &Violation) -> Result<FixProposal, FixError> {
        Ok(FixProposal {
            violation_id: format!("{}:{}", violation.file_path, violation.line),
            file_path: violation.file_path.clone(),
            original_snippet: violation.snippet.clone(),
            fixed_snippet: format!(
                "audit_log::record(\"sensitive_operation\", &{{ \"file\": \"{}\", \"line\": {} }});",
                violation.file_path, violation.line
            ),
            description: "Insert SOC2 audit trail call for sensitive operation".into(),
            rule_id: violation.rule_id.clone(),
            policy_id: violation.policy_id.clone(),
        })
    }
}

/// Gated proposals carry the violation line for the decision record; the
/// proposal id encodes `file:line`.
fn violation_line(proposal: &FixProposal) -> u32 {
    proposal
        .violation_id
        .rsplit(':')
        .next()
        .and_then(|l| l.parse().ok())
        .unwrap_or(0)
}

/// Build a refusal/pending decision record; `foundation` carries
/// (parity, verdict, score) when the adversary ran before the refusal.
#[allow(clippy::too_many_arguments)]
fn refusal_record<'a>(
    ctx: &'a FixContext,
    reason: &'a str,
    foundation: Option<(serde_json::Value, &'a str, u32)>,
    r0_verdict: Option<&'a str>,
    session_status: Option<&'a str>,
    confirmed_by: Option<&'a str>,
    artifacts: serde_json::Value,
) -> cac_chp::DecisionRecord<'a> {
    let (parity, foundation_verdict, foundation_score) = match foundation {
        Some((p, v, s)) => (Some(p), Some(v), Some(s)),
        None => (None, None, None),
    };
    cac_chp::DecisionRecord {
        decision_id: &ctx.decision_id,
        title: &ctx.title,
        outcome: "refused",
        rule_id: &ctx.rule_id,
        policy_id: &ctx.policy_id,
        file_path: &ctx.file_path,
        violation_line: ctx.violation_line,
        fix_description: &ctx.description,
        session_status,
        r0_verdict,
        r0_results: None,
        foundation_verdict,
        foundation_score,
        parity,
        refusal_reason: Some(reason),
        confirmed_by,
        landed_via: "none",
        artifacts,
    }
}

pub fn group_by_file(violations: &[Violation]) -> Vec<(String, Vec<&Violation>)> {
    let mut files: Vec<String> = violations.iter().map(|v| v.file_path.clone()).collect();
    files.sort();
    files.dedup();
    files
        .into_iter()
        .map(|f| {
            let items: Vec<_> = violations.iter().filter(|v| v.file_path == f).collect();
            (f, items)
        })
        .collect()
}

pub fn root_path(root: &Path) -> PathBuf {
    root.to_path_buf()
}
