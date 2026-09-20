//! CHP gate for auto-fix writes (consensus-hardening-protocol 0.1.1).
//!
//! The scan side of the agent is ungated; every auto-fix WRITE passes through
//! [`ChpGate`] first: R0 evaluation, parity pre-check (re-scan of a fixed
//! copy against the real policy definitions), deterministic adversary
//! scoring, human lock (PROVISIONAL_LOCK → third-party validation → LOCKED),
//! and a decision record in an append-only JSONL ledger with body_sha256
//! integrity re-validated on read.
//!
//! Integration path: subprocess bridge to the pure-Python CHP package
//! (`bridge/chp_gate.py`), chosen because chp-rust-pack is a Node asset pack
//! (no native Rust crate exists) and an MCP client would add a network
//! server dependency to a local, deterministic gate. Fail-closed: any gate
//! error refuses the fix.

mod parity;

pub use parity::{parity_precheck, post_write_verify, ParityEvidence};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChpError {
    #[error("CHP gate script not found — set CAC_CHP_GATE or place bridge/chp_gate.py beside the checkout")]
    GateScriptMissing,
    #[error("gate interpreter failed: {0}")]
    Interpreter(String),
    #[error("gate protocol error (exit {code}): {detail}")]
    Protocol { code: i32, detail: String },
    #[error("scan error: {0}")]
    Scan(#[from] cac_scanner::ScanError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Lock policy for the write path. `CAC_CHP_REQUIRE_HUMAN_LOCK` (default ON)
/// selects [`LockPolicy::RequireHuman`]; `=0`/`false` opts out to
/// [`LockPolicy::AutoConfirm`] (still fully gated and recorded, but writes
/// land without a named confirmer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPolicy {
    /// Writes never land without `cac confirm --session <id> --confirmed-by <who>`.
    RequireHuman,
    /// Writes land immediately under a LOCKED decision attributed to the
    /// opt-out (recorded, not silent).
    AutoConfirm,
    /// Webhook fix-PR mode: writes land on an isolated fix branch and the
    /// case stays PROVISIONAL_LOCK — the human PR merge is the confirmation.
    ProposeBranch,
}

impl LockPolicy {
    pub fn from_env() -> Self {
        match std::env::var("CAC_CHP_REQUIRE_HUMAN_LOCK") {
            Ok(v) if matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "off") => {
                LockPolicy::AutoConfirm
            }
            _ => LockPolicy::RequireHuman,
        }
    }
}

/// The per-fix facts the gate evaluates. Built from a `FixProposal` plus the
/// violation state it came from.
#[derive(Debug, Clone, Serialize)]
pub struct FixContext {
    pub decision_id: String,
    pub title: String,
    pub rule_id: String,
    pub policy_id: String,
    pub file_path: String,
    pub violation_line: u32,
    pub description: String,
    pub original_snippet: String,
    pub fixed_snippet: String,
    pub auto_fixable: bool,
}

impl FixContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_file: &str,
        proposal_snippet: &str,
        proposal_fixed: &str,
        proposal_description: &str,
        rule_id: &str,
        policy_id: &str,
        line: u32,
        auto_fixable: bool,
    ) -> Self {
        let decision_id = format!(
            "fix-{}",
            &hash_of(&format!(
                "{rule_id}|{proposal_file}|{line}|{proposal_snippet}"
            ))[..12]
        );
        Self {
            decision_id,
            title: format!("Auto-fix {rule_id} in {proposal_file}"),
            rule_id: rule_id.to_string(),
            policy_id: policy_id.to_string(),
            file_path: proposal_file.to_string(),
            violation_line: line,
            description: proposal_description.to_string(),
            original_snippet: proposal_snippet.to_string(),
            fixed_snippet: proposal_fixed.to_string(),
            auto_fixable,
        }
    }
}

fn hash_of(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)
}

/// R0 gate evaluation. Result keys are capitalized (`Solvable`, `Scoped`,
/// `Valid`, `Worth_it`) with `FATAL` values per the CHP spec; any FATAL is a
/// HALT refusal.
#[derive(Debug, Clone, Deserialize)]
pub struct R0Evaluation {
    pub results: BTreeMap<String, String>,
    pub verdict: String,
}

impl R0Evaluation {
    pub fn passed(&self) -> bool {
        self.verdict == "PASS"
    }

    pub fn failed_keys(&self) -> Vec<String> {
        self.results
            .iter()
            .filter(|(_, v)| v.as_str() != "PASS")
            .map(|(k, _)| k.clone())
            .collect()
    }
}

/// Deterministic adversary assessment over executed-check evidence.
#[derive(Debug, Clone, Deserialize)]
pub struct Assessment {
    pub score: u32,
    pub domain: String,
    pub floor: u32,
    pub verdict: String,
    pub fatal: bool,
    pub findings: Vec<String>,
    pub parity: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenOutcome {
    pub decision_id: String,
    pub status: String,
    pub r0_verdict: String,
    pub foundation_verdict: String,
    pub foundation_score: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Confirmed {
    pub decision_id: String,
    pub status: String,
    pub proposals: Vec<Value>,
}

/// The gate client: resolves the Python interpreter and the bridge script,
/// then exposes the protocol commands. All calls are blocking subprocesses.
pub struct ChpGate {
    root: PathBuf,
    policy_dir: PathBuf,
    script: PathBuf,
    python: String,
}

impl ChpGate {
    /// Resolve the gate from the environment. Script lookup order:
    /// `CAC_CHP_GATE`, `bridge/chp_gate.py` under the current directory, and
    /// `../../bridge/chp_gate.py` relative to this crate (test builds).
    pub fn new(root: impl Into<PathBuf>, policy_dir: impl Into<PathBuf>) -> Self {
        let python = std::env::var("CAC_PYTHON").unwrap_or_else(|_| "python3".to_string());
        let script = Self::resolve_script();
        Self {
            root: root.into(),
            policy_dir: policy_dir.into(),
            script,
            python,
        }
    }

    fn resolve_script() -> PathBuf {
        if let Ok(path) = std::env::var("CAC_CHP_GATE") {
            return PathBuf::from(path);
        }
        let candidates = [
            PathBuf::from("bridge/chp_gate.py"),
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../bridge/chp_gate.py"
            )),
        ];
        for candidate in candidates {
            if candidate.exists() {
                return candidate;
            }
        }
        PathBuf::from("bridge/chp_gate.py")
    }

    pub fn script_path(&self) -> &Path {
        &self.script
    }

    pub fn policy_dir(&self) -> &Path {
        &self.policy_dir
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Run one gate command. Returns the parsed stdout and the exit code so
    /// callers can distinguish refusals (3) from errors (2).
    fn call(&self, command: &str, payload: &Value) -> Result<(i32, Value), ChpError> {
        if !self.script.exists() {
            return Err(ChpError::GateScriptMissing);
        }
        let mut child = Command::new(&self.python)
            .arg(&self.script)
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|err| ChpError::Interpreter(err.to_string()))?;
        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            serde_json::to_writer(&mut *stdin, payload)?;
            writeln!(*stdin)?;
        }
        let output = child.wait_with_output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let code = output.status.code().unwrap_or(-1);
        if code == 0 || code == 3 {
            let parsed = serde_json::from_str(stdout.trim()).map_err(|err| ChpError::Protocol {
                code,
                detail: format!("unparsable gate output ({err}): {stdout}"),
            })?;
            Ok((code, parsed))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(ChpError::Protocol {
                code,
                detail: if stdout.trim().is_empty() {
                    stderr.trim().to_string()
                } else {
                    stdout.trim().to_string()
                },
            })
        }
    }

    /// Pre-write R0 gate: is this fix scoped and solvable from the violation
    /// state? Inputs are computed from real filesystem/policy state.
    pub fn evaluate_r0(&self, ctx: &FixContext) -> Result<R0Evaluation, ChpError> {
        let (solvable, scoped, valid, worth_it) = self.r0_inputs(ctx);
        let (_, out) = self.call(
            "r0",
            &json!({
                "solvable": solvable,
                "scoped": scoped,
                "valid": valid,
                "worth_it": worth_it,
            }),
        )?;
        Ok(serde_json::from_value(out)?)
    }

    /// R0 inputs from real state:
    /// - solvable: a concrete remediation exists (non-empty, changed, described)
    /// - scoped: the write is bounded to the flagged file inside the root
    /// - valid: the flagged file still contains the violation snapshot
    /// - worth_it: the violation is auto-fixable and the remediation family
    ///   matches the flagged rule family
    fn r0_inputs(&self, ctx: &FixContext) -> (bool, bool, bool, bool) {
        let solvable = !ctx.fixed_snippet.trim().is_empty()
            && ctx.fixed_snippet != ctx.original_snippet
            && !ctx.description.trim().is_empty()
            && !ctx.rule_id.is_empty();

        let scoped = path_within_root(Path::new(&self.root), &ctx.file_path);

        let target = self.root.join(&ctx.file_path);
        let valid = target.is_file()
            && std::fs::read_to_string(&target)
                .map(|content| content.contains(&ctx.original_snippet))
                .unwrap_or(false);

        let remediation = |marker: &str| ctx.fixed_snippet.contains(marker);
        let worth_it = ctx.auto_fixable
            && (ctx.rule_id.starts_with("secret-") && remediation("env::var(")
                || ctx.rule_id.starts_with("gdpr-") && remediation("@gdpr")
                || ctx.rule_id.starts_with("soc2-") && remediation("audit_log"));

        (solvable, scoped, valid, worth_it)
    }

    /// Deterministic adversary over executed-check evidence. Refusal exits
    /// (fatal parity, floor failure) surface as an `Assessment` with
    /// `fatal: true` — the caller must refuse the fix.
    pub fn assess(
        &self,
        ctx: &FixContext,
        parity_evidence: &parity::ParityEvidence,
    ) -> Result<Assessment, ChpError> {
        let (_, out) = self.call(
            "assess",
            &json!({
                "domain": "general",
                "guardrail_checks": {
                    "path_within_root": path_within_root(Path::new(&self.root), &ctx.file_path),
                    "snippet_anchored": true,
                    "single_file_write": true,
                },
                "parity": parity_evidence.to_json(),
            }),
        )?;
        Ok(serde_json::from_value(out)?)
    }

    /// Open the decision case as PROVISIONAL_LOCK with the pending proposals
    /// stored in the session state.
    pub fn open_session(
        &self,
        ctx: &FixContext,
        r0: &R0Evaluation,
        assessment: &Assessment,
        parity_evidence: &parity::ParityEvidence,
    ) -> Result<OpenOutcome, ChpError> {
        let (_, out) = self.call(
            "open",
            &json!({
                "root": self.root.display().to_string(),
                "decision_id": ctx.decision_id,
                "title": ctx.title,
                "domain": "general",
                "owner": "cac-fixer-agent",
                "dossier": {
                    "core_problem": format!(
                        "Resolve the flagged {} violation in {}",
                        ctx.rule_id, ctx.file_path
                    ),
                    "current_state": [format!(
                        "{}:{} flagged by {}/{}",
                        ctx.file_path, ctx.violation_line, ctx.policy_id, ctx.rule_id
                    )],
                    "constraints": [
                        "single-file write",
                        "snippet-anchored replacement",
                        "parity re-scan against the policy definitions",
                    ],
                    "scope": [ctx.file_path.clone()],
                },
                "proposals": [{
                    "violation_id": ctx.decision_id,
                    "file_path": ctx.file_path,
                    "original_snippet": ctx.original_snippet,
                    "fixed_snippet": ctx.fixed_snippet,
                    "description": ctx.description,
                    "rule_id": ctx.rule_id,
                    "policy_id": ctx.policy_id,
                }],
                "r0": { "verdict": r0.verdict, "results": r0.results },
                "assessment": { "score": assessment.score, "findings": assessment.findings },
                "parity": parity_evidence.to_json(),
            }),
        )?;
        Ok(serde_json::from_value(out)?)
    }

    /// Human confirmation: PROVISIONAL_LOCK → LOCKED via CHP third-party
    /// validation. Returns the locked proposals for the write stage.
    pub fn confirm(&self, decision_id: &str, confirmed_by: &str) -> Result<Confirmed, ChpError> {
        let (_, out) = self.call(
            "confirm",
            &json!({
                "root": self.root.display().to_string(),
                "decision_id": decision_id,
                "confirmed_by": confirmed_by,
            }),
        )?;
        let mut confirmed: Confirmed = serde_json::from_value(out)?;
        // CHP protocol statuses are upper-case (PROVISIONAL_LOCK / LOCKED);
        // normalize so downstream comparisons match the recorded
        // session_status vocabulary.
        confirmed.status = confirmed.status.to_ascii_lowercase();
        Ok(confirmed)
    }

    /// Seal a decision (applied or refused) into the append-only ledger.
    pub fn record_decision(&self, record: DecisionRecord<'_>) -> Result<Value, ChpError> {
        let mut payload = serde_json::to_value(record)?;
        // The bridge resolves the ledger path from the scan root.
        payload["root"] = json!(self.root.display().to_string());
        let (_, out) = self.call("record", &payload)?;
        Ok(out)
    }

    /// Read the ledger with envelope and body integrity re-validated;
    /// `integrity_valid` is exposed per record.
    pub fn read_decisions(&self, limit: Option<usize>) -> Result<Value, ChpError> {
        let (_, out) = self.call(
            "read",
            &json!({ "root": self.root, "limit": limit.map(|l| l as u64) }),
        )?;
        Ok(out)
    }
}

/// Input to `ChpGate::record_decision`.
pub struct DecisionRecord<'a> {
    pub decision_id: &'a str,
    pub title: &'a str,
    pub outcome: &'a str,
    pub rule_id: &'a str,
    pub policy_id: &'a str,
    pub file_path: &'a str,
    pub violation_line: u32,
    pub fix_description: &'a str,
    pub session_status: Option<&'a str>,
    pub r0_verdict: Option<&'a str>,
    pub r0_results: Option<BTreeMap<String, String>>,
    pub foundation_verdict: Option<&'a str>,
    pub foundation_score: Option<u32>,
    pub parity: Option<Value>,
    pub refusal_reason: Option<&'a str>,
    pub confirmed_by: Option<&'a str>,
    pub landed_via: &'a str,
    pub artifacts: Value,
}

impl Serialize for DecisionRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        json!({
            "decision_id": self.decision_id,
            "title": self.title,
            "outcome": self.outcome,
            "rule_id": self.rule_id,
            "policy_id": self.policy_id,
            "file_path": self.file_path,
            "violation_line": self.violation_line,
            "fix_description": self.fix_description,
            "session_status": self.session_status,
            "r0_verdict": self.r0_verdict,
            "r0_results": self.r0_results,
            "foundation_verdict": self.foundation_verdict,
            "foundation_score": self.foundation_score,
            "parity": self.parity,
            "refusal_reason": self.refusal_reason,
            "confirmed_by": self.confirmed_by,
            "landed_via": self.landed_via,
            "artifacts": self.artifacts,
        })
        .serialize(serializer)
    }
}

/// Path-safety: the fix write may only target a relative path inside the
/// scan root (no `..`, no absolute escapes).
pub fn path_within_root(root: &Path, file_path: &str) -> bool {
    let rel = Path::new(file_path);
    if rel.is_absolute() {
        return false;
    }
    if rel.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let joined = root.join(rel);
    // `apply_one` only ever writes root.join(rel), so a lexical check against
    // the (canonical) root is sufficient; root itself must exist to scan it.
    match root.canonicalize() {
        Ok(root_canonical) => joined.starts_with(&root_canonical),
        Err(_) => joined.starts_with(root),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_scope_rejects_escapes() {
        let base = std::env::temp_dir().join("cac-chp-scope-test");
        std::fs::create_dir_all(&base).unwrap();
        assert!(path_within_root(&base, "src/main.rs"));
        assert!(!path_within_root(&base, "../outside.txt"));
        assert!(!path_within_root(&base, "/etc/hosts"));
    }

    #[test]
    fn decision_id_is_deterministic() {
        let a = FixContext::new(
            "src/main.rs",
            "orig",
            "fixed",
            "d",
            "secret-api-key",
            "p",
            7,
            true,
        );
        let b = FixContext::new(
            "src/main.rs",
            "orig",
            "fixed",
            "d",
            "secret-api-key",
            "p",
            7,
            true,
        );
        let c = FixContext::new(
            "src/main.rs",
            "orig",
            "fixed",
            "d",
            "secret-api-key",
            "p",
            8,
            true,
        );
        assert_eq!(a.decision_id, b.decision_id);
        assert_ne!(a.decision_id, c.decision_id);
        assert!(a.decision_id.starts_with("fix-"));
    }
}
