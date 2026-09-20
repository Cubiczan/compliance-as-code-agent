//! Parity pre-check: does the proposed fix actually resolve the flagged
//! violation against the policy definitions? Verified by writing the fixed
//! content to an isolated temp copy and re-scanning it with the real
//! scanner — the real tree is untouched until the gate opens.

use crate::{ChpError, FixContext};
use cac_scanner::{ScanConfig, Scanner};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ParityEvidence {
    pub ran: bool,
    pub resolved: bool,
    pub files_scanned: usize,
    pub rule_id: String,
    pub file_path: String,
    /// The snippets that must NOT be flagged after the fix: the original
    /// violation line and every line the fix introduces.
    pub checked_snippets: Vec<String>,
    pub still_flagged: Vec<String>,
    pub error: Option<String>,
}

impl ParityEvidence {
    pub fn to_json(&self) -> Value {
        json!({
            "ran": self.ran,
            "resolved": self.resolved,
            "files_scanned": self.files_scanned,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "checked_snippets": self.checked_snippets,
            "still_flagged": self.still_flagged,
            "error": self.error,
        })
    }
}

/// Re-scan a fixed copy of the flagged file against the policy definitions.
/// `resolved` means no violation of the same rule flags the original
/// snippet OR any line the fix introduces — a fix that merely rewrites the
/// violation into a new pattern fails parity (fatal downstream).
pub fn parity_precheck(
    root: &Path,
    policy_dir: &Path,
    ctx: &FixContext,
) -> Result<ParityEvidence, ChpError> {
    let mut checked = vec![ctx.original_snippet.clone()];
    checked.extend(ctx.fixed_snippet.lines().map(str::trim).map(str::to_string));

    let target = root.join(&ctx.file_path);
    if !target.is_file() {
        return Ok(ParityEvidence {
            ran: false,
            resolved: false,
            files_scanned: 0,
            rule_id: ctx.rule_id.clone(),
            file_path: ctx.file_path.clone(),
            checked_snippets: checked,
            still_flagged: Vec::new(),
            error: Some(format!("flagged file not found: {}", ctx.file_path)),
        });
    }
    let content = std::fs::read_to_string(&target)?;
    if !content.contains(&ctx.original_snippet) {
        return Ok(ParityEvidence {
            ran: false,
            resolved: false,
            files_scanned: 0,
            rule_id: ctx.rule_id.clone(),
            file_path: ctx.file_path.clone(),
            checked_snippets: checked,
            still_flagged: Vec::new(),
            error: Some("violation snapshot no longer present in the flagged file".to_string()),
        });
    }

    // Isolated copy: only the flagged file, at its relative path, with the
    // fix applied. The real tree is untouched.
    let temp = tempfile::tempdir()?;
    let temp_target = temp.path().join(&ctx.file_path);
    if let Some(parent) = temp_target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let fixed_content = content.replace(&ctx.original_snippet, &ctx.fixed_snippet);
    std::fs::write(&temp_target, fixed_content)?;

    let scanner = Scanner::from_config(ScanConfig::new(temp.path(), policy_dir))?;
    let report = scanner.scan()?;

    let still_flagged = flagged_snippets(&report, ctx);

    Ok(ParityEvidence {
        ran: true,
        resolved: still_flagged.is_empty(),
        files_scanned: report.files_scanned,
        rule_id: ctx.rule_id.clone(),
        file_path: ctx.file_path.clone(),
        checked_snippets: checked,
        still_flagged,
        error: None,
    })
}

/// Post-write verification on the real tree: the flagged instance must be
/// gone and the fix must not have introduced a new flag of the same rule in
/// the same file.
pub fn post_write_verify(
    root: &Path,
    policy_dir: &Path,
    ctx: &FixContext,
) -> Result<ParityEvidence, ChpError> {
    let scanner = Scanner::from_config(ScanConfig::new(root, policy_dir))?;
    let report = scanner.scan()?;
    let still_flagged = flagged_snippets(&report, ctx);

    Ok(ParityEvidence {
        ran: true,
        resolved: still_flagged.is_empty(),
        files_scanned: report.files_scanned,
        rule_id: ctx.rule_id.clone(),
        file_path: ctx.file_path.clone(),
        checked_snippets: vec![ctx.original_snippet.clone()],
        still_flagged,
        error: None,
    })
}

fn flagged_snippets(report: &cac_core::ScanReport, ctx: &FixContext) -> Vec<String> {
    report
        .violations
        .iter()
        .filter(|v| {
            v.rule_id == ctx.rule_id
                && v.file_path == ctx.file_path
                && (v.snippet == ctx.original_snippet
                    || ctx
                        .fixed_snippet
                        .lines()
                        .any(|line| line.trim() == v.snippet))
        })
        .map(|v| v.snippet.clone())
        .collect()
}
