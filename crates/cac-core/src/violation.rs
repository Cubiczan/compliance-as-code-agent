use crate::policy::PolicySeverity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Violation {
    pub rule_id: String,
    pub policy_id: String,
    pub policy_name: String,
    pub framework: String,
    pub severity: PolicySeverity,
    pub file_path: String,
    pub line: u32,
    pub column: u32,
    pub snippet: String,
    pub message: String,
    pub auto_fixable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanned_at: String,
    pub root: String,
    pub files_scanned: usize,
    pub violations: Vec<Violation>,
}

impl ScanReport {
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    pub fn has_critical(&self) -> bool {
        self.violations
            .iter()
            .any(|v| v.severity == PolicySeverity::Critical)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixProposal {
    pub violation_id: String,
    pub file_path: String,
    pub original_snippet: String,
    pub fixed_snippet: String,
    pub description: String,
    /// Rule that flagged the violation — carried into CHP decision records.
    #[serde(default)]
    pub rule_id: String,
    /// Policy that owns the rule — carried into CHP decision records.
    #[serde(default)]
    pub policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub validated_at: String,
    pub original_violations: usize,
    pub remaining_violations: usize,
    pub fixes_applied: usize,
    pub passed: bool,
    pub adversarial_notes: Vec<String>,
    pub remaining: Vec<Violation>,
}
