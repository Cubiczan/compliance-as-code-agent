use crate::config::WebhookConfig;
use crate::git;
use crate::payload::{PrContext, ProviderKind, PullRequestEvent};
use crate::provider::ProviderClient;
use cac_chp::{ChpGate, LockPolicy};
use cac_core::{
    audit::{default_ledger_path, AuditLedger, AuditPhase, LedgerConfig},
    violation::ScanReport,
};
use cac_fixer::Fixer;
use cac_scanner::{ScanConfig, Scanner};
use cac_validator::Validator;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("git error: {0}")]
    Git(#[from] git::GitError),
    #[error("scan error: {0}")]
    Scan(#[from] cac_scanner::ScanError),
    #[error("fix error: {0}")]
    Fix(#[from] cac_fixer::FixError),
    #[error("validate error: {0}")]
    Validate(#[from] cac_validator::ValidateError),
    #[error("provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),
    #[error("audit error: {0}")]
    Audit(#[from] cac_core::audit::AuditError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct WebhookHandler {
    config: Arc<WebhookConfig>,
    provider: ProviderClient,
}

impl WebhookHandler {
    pub fn new(config: WebhookConfig) -> Self {
        let provider =
            ProviderClient::new(config.github_token.clone(), config.codeberg_token.clone());
        Self {
            config: Arc::new(config),
            provider,
        }
    }

    pub async fn handle_pull_request(&self, ctx: PrContext) -> Result<(), HandlerError> {
        info!(
            provider = ?ctx.provider,
            pr = ctx.pr_number,
            repo = %format!("{}/{}", ctx.owner, ctx.repo),
            action = %ctx.action,
            "processing pull request webhook"
        );

        let ledger = AuditLedger::new(LedgerConfig {
            signing_key: self.config.signing_key.clone(),
            ledger_path: default_ledger_path(&self.config.work_dir),
        });

        ledger.record(
            AuditPhase::Webhook,
            "webhook-agent",
            "pr_received",
            None,
            None,
            None,
            serde_json::json!({
                "provider": format!("{:?}", ctx.provider),
                "owner": ctx.owner,
                "repo": ctx.repo,
                "pr_number": ctx.pr_number,
                "head_sha": ctx.head_sha,
                "action": ctx.action,
            }),
        )?;

        let _ = self
            .provider
            .set_pending(
                ctx.provider,
                &ctx.owner,
                &ctx.repo,
                &ctx.head_sha,
                &self.config.status_context,
            )
            .await;

        let token = self.token_for(ctx.provider);
        let clone_target = if ctx.head_clone_url != ctx.clone_url {
            &ctx.head_clone_url
        } else {
            &ctx.clone_url
        };
        let repo_dir = git::checkout_pr(
            &self.config.work_dir,
            clone_target,
            ctx.pr_number,
            token.as_deref(),
        )?;

        let scan = self.scan_repo(&repo_dir)?;
        ledger.record(
            AuditPhase::Detect,
            "detector-agent",
            "pr_scan_complete",
            None,
            None,
            None,
            serde_json::json!({
                "violations": scan.violation_count(),
                "files_scanned": scan.files_scanned,
                "pr_number": ctx.pr_number,
            }),
        )?;

        let mut fix_pr_url = None;
        if self.config.auto_fix_pr && !scan.violations.is_empty() {
            if let Ok(url) = self
                .create_fix_pr(&ctx, &repo_dir, &scan, token.as_deref())
                .await
            {
                if !url.is_empty() {
                    fix_pr_url = Some(url);
                }
            }
        }

        let passed = scan.violations.is_empty();
        let description = if passed {
            "No compliance violations detected".into()
        } else {
            format!("{} compliance violation(s) detected", scan.violations.len())
        };

        let target_url = fix_pr_url
            .clone()
            .or_else(|| self.config.public_url.clone())
            .or(ctx.pr_url.clone());

        self.provider
            .set_result(
                ctx.provider,
                &ctx.owner,
                &ctx.repo,
                &ctx.head_sha,
                &self.config.status_context,
                passed,
                description,
                target_url,
            )
            .await?;

        let comment = format_pr_comment(&scan, fix_pr_url.as_deref());
        if let Err(err) = self
            .provider
            .comment_on_pr(ctx.provider, &ctx.owner, &ctx.repo, ctx.pr_number, &comment)
            .await
        {
            warn!(error = %err, "failed to post PR comment");
        }

        ledger.record(
            AuditPhase::Webhook,
            "webhook-agent",
            if passed { "pr_passed" } else { "pr_failed" },
            None,
            None,
            None,
            serde_json::json!({
                "passed": passed,
                "violations": scan.violation_count(),
            }),
        )?;

        Ok(())
    }

    pub fn parse_event(
        provider: ProviderKind,
        body: &[u8],
    ) -> Result<Option<PrContext>, HandlerError> {
        let event: PullRequestEvent = serde_json::from_slice(body)?;
        Ok(event.into_context(provider))
    }

    fn scan_repo(&self, repo_dir: &std::path::Path) -> Result<ScanReport, HandlerError> {
        let scanner = Scanner::from_config(ScanConfig::new(repo_dir, &self.config.policies_dir))?;
        Ok(scanner.scan()?)
    }

    async fn create_fix_pr(
        &self,
        ctx: &PrContext,
        repo_dir: &std::path::Path,
        scan: &ScanReport,
        token: Option<&str>,
    ) -> Result<String, HandlerError> {
        let fixer = Fixer::new(repo_dir, false);
        let proposals = fixer.propose(&scan.violations);
        // The fix-PR write shares the CHP gate: every proposal passes R0,
        // parity, and the adversary before landing on the isolated fix
        // branch, and every refusal is recorded. The human PR merge is the
        // lock surface, so branch mode applies under either lock flag.
        let gate = ChpGate::new(repo_dir, &self.config.policies_dir);
        let gated = fixer.apply_gated(&proposals, &gate, LockPolicy::ProposeBranch, None)?;
        let applied = gated.applied;
        if gated.pending == 0 {
            warn!(
                "auto-fix PR skipped: no proposal passed the CHP gate ({} refused)",
                gated.refused
            );
            return Ok(String::new());
        }
        if applied == 0 {
            warn!("auto-fix PR skipped: no fixes applied");
            return Ok(String::new());
        }
        // Keep CHP gate state (sessions, decision ledger) out of the fix
        // PR diff — it is recorded locally, not part of the proposal.
        let exclude = repo_dir.join(".git/info/exclude");
        match std::fs::read_to_string(&exclude) {
            Ok(existing) if !existing.lines().any(|l| l.trim() == ".cac/") => {
                std::fs::write(&exclude, format!("{existing}.cac/\n"))
                    .map_err(|err| warn!(error = %err, "could not exclude .cac from fix PR"))
                    .ok();
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "could not read .git/info/exclude"),
        }

        let validator = Validator::new(repo_dir, &self.config.policies_dir);
        let validation = validator.validate_after_fix(scan, applied)?;
        if !validation.passed {
            warn!("auto-fix PR skipped: validation failed after fixes");
            return Ok(String::new());
        }

        let fix_branch = format!(
            "cac-fix/pr-{}-{}",
            ctx.pr_number,
            &ctx.head_sha[..7.min(ctx.head_sha.len())]
        );
        let committed = git::commit_all(
            repo_dir,
            &format!("fix(compliance): auto-fix {} violation(s) [CAC]", applied),
        )?;
        if !committed {
            warn!("auto-fix PR skipped: nothing to commit");
            return Ok(String::new());
        }
        git::push_branch(repo_dir, &fix_branch, token)?;

        let title = format!("fix(compliance): auto-fix PR #{} violations", ctx.pr_number);
        let body = format!(
            "Automated compliance fixes from Compliance-as-Code Agent.\n\n\
             - Original PR: #{}\n\
             - Violations fixed: {}\n\
             - Validator: passed\n\n\
             Please review and merge if acceptable.",
            ctx.pr_number, applied
        );

        self.provider
            .open_fix_pr(
                ctx.provider,
                &ctx.owner,
                &ctx.repo,
                &fix_branch,
                &ctx.base_ref,
                &title,
                &body,
            )
            .await
            .map_err(Into::into)
    }

    fn token_for(&self, provider: ProviderKind) -> Option<String> {
        match provider {
            ProviderKind::GitHub => self.config.github_token.clone(),
            ProviderKind::Gitea => self.config.codeberg_token.clone(),
        }
    }
}

fn format_pr_comment(scan: &ScanReport, fix_pr_url: Option<&str>) -> String {
    let mut lines = vec![
        "## Compliance-as-Code Scan".into(),
        String::new(),
        format!(
            "**Result:** {} violation(s) across {} file(s)",
            scan.violations.len(),
            scan.files_scanned
        ),
    ];

    if let Some(url) = fix_pr_url {
        lines.push(String::new());
        lines.push(format!("**Auto-fix PR:** {url}"));
    }

    if scan.violations.is_empty() {
        lines.push(String::new());
        lines.push("All policy checks passed.".into());
        return lines.join("\n");
    }

    lines.push(String::new());
    lines.push("### Violations".into());
    for v in scan.violations.iter().take(20) {
        lines.push(format!(
            "- **[{:?}]** `{}:{}` — {} (`{}`)",
            v.severity, v.file_path, v.line, v.message, v.rule_id
        ));
    }
    if scan.violations.len() > 20 {
        lines.push(format!(
            "\n_...and {} more violation(s)._",
            scan.violations.len() - 20
        ));
    }

    lines.join("\n")
}

pub fn spawn_pr_job(handler: Arc<WebhookHandler>, ctx: PrContext) {
    tokio::spawn(async move {
        if let Err(err) = handler.handle_pull_request(ctx).await {
            error!(error = %err, "PR webhook job failed");
        }
    });
}
