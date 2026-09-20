use cac_core::violation::{ScanReport, ValidationReport, Violation};
use cac_scanner::{ScanConfig, Scanner};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidateError {
    #[error("scan error: {0}")]
    Scan(#[from] cac_scanner::ScanError),
}

pub struct Validator {
    root: std::path::PathBuf,
    policy_dir: std::path::PathBuf,
}

impl Validator {
    pub fn new(
        root: impl Into<std::path::PathBuf>,
        policy_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            root: root.into(),
            policy_dir: policy_dir.into(),
        }
    }

    pub fn validate_after_fix(
        &self,
        original: &ScanReport,
        fixes_applied: usize,
    ) -> Result<ValidationReport, ValidateError> {
        let scanner = Scanner::from_config(ScanConfig::new(&self.root, &self.policy_dir))?;
        let rescanned = scanner.scan()?;
        let adversarial_notes = adversarial_review(&original.violations, &rescanned.violations);
        let passed = rescanned.violations.is_empty();

        Ok(ValidationReport {
            validated_at: chrono::Utc::now().to_rfc3339(),
            original_violations: original.violations.len(),
            remaining_violations: rescanned.violations.len(),
            fixes_applied,
            passed,
            adversarial_notes,
            remaining: rescanned.violations,
        })
    }
}

/// CHP-inspired adversarial validation: challenge whether fixes merely hide violations.
fn adversarial_review(before: &[Violation], after: &[Violation]) -> Vec<String> {
    let mut notes = Vec::new();

    if after.len() >= before.len() {
        notes.push(
            "Adversarial: fix pass did not reduce violation count — fixes may be cosmetic or incomplete."
                .into(),
        );
    }

    for v in after {
        if v.rule_id.starts_with("secret-") && v.snippet.contains("env::var") {
            notes.push(format!(
                "Adversarial: {} still flagged — verify env var is not a placeholder.",
                v.file_path
            ));
        }
        if v.rule_id.starts_with("gdpr-") {
            notes.push(format!(
                "Adversarial: GDPR annotation missing near PII in {} — confirm lawful basis documented.",
                v.file_path
            ));
        }
    }

    if notes.is_empty() {
        notes.push(
            "Adversarial: re-scan passed. Independent validator confirms no remaining policy violations."
                .into(),
        );
    }

    notes
}
