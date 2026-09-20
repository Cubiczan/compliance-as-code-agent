mod rules;

use cac_core::{
    policy::{CompiledRule, PolicyPack, RuleKind},
    violation::{ScanReport, Violation},
};
use chrono::Utc;
use glob::Pattern;
use std::path::PathBuf;
use thiserror::Error;
use walkdir::WalkDir;

pub use rules::DEFAULT_SKIP_DIRS;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("policy error: {0}")]
    Policy(#[from] cac_core::policy::PolicyError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub root: PathBuf,
    pub policy_dir: PathBuf,
    pub max_file_size: u64,
}

impl ScanConfig {
    pub fn new(root: impl Into<PathBuf>, policy_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            policy_dir: policy_dir.into(),
            max_file_size: 512 * 1024,
        }
    }
}

pub struct Scanner {
    config: ScanConfig,
    rules: Vec<CompiledRule>,
}

impl Scanner {
    pub fn from_config(config: ScanConfig) -> Result<Self, ScanError> {
        let pack = PolicyPack::load_dir(&config.policy_dir)?;
        let rules = pack.compile_rules()?;
        Ok(Self { config, rules })
    }

    pub fn scan(&self) -> Result<ScanReport, ScanError> {
        let mut violations = Vec::new();
        let mut files_scanned = 0usize;

        for entry in WalkDir::new(&self.config.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !rules::should_skip_entry(e.path(), &self.config.root))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if rules::is_binary_or_large(path, self.config.max_file_size) {
                continue;
            }
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            files_scanned += 1;
            let rel = path
                .strip_prefix(&self.config.root)
                .unwrap_or(path)
                .display()
                .to_string();

            for rule in &self.rules {
                violations.extend(evaluate_rule(rule, &rel, &content));
            }
        }

        Ok(ScanReport {
            scanned_at: Utc::now().to_rfc3339(),
            root: self.config.root.display().to_string(),
            files_scanned,
            violations,
        })
    }
}

fn evaluate_rule(rule: &CompiledRule, file_path: &str, content: &str) -> Vec<Violation> {
    match rule.rule.kind {
        RuleKind::SecretPattern => evaluate_regex_matches(rule, file_path, content, true),
        RuleKind::CustomRegex => evaluate_regex_matches(rule, file_path, content, false),
        RuleKind::ForbiddenFile => evaluate_forbidden_file(rule, file_path),
        RuleKind::RequiredAnnotation => evaluate_required_annotation(rule, file_path, content),
        RuleKind::RequiredCall => evaluate_required_call(rule, file_path, content),
    }
}

fn evaluate_regex_matches(
    rule: &CompiledRule,
    file_path: &str,
    content: &str,
    auto_fixable: bool,
) -> Vec<Violation> {
    let Some(regex) = &rule.regex else {
        return Vec::new();
    };

    if let Some(glob) = &rule.rule.file_glob {
        if !glob_matches(glob, file_path) {
            return Vec::new();
        }
    }

    let mut violations = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        for mat in regex.find_iter(line) {
            if rules::is_likely_false_positive(line, mat.as_str()) {
                continue;
            }
            violations.push(Violation {
                rule_id: rule.rule.id.clone(),
                policy_id: rule.policy_id.clone(),
                policy_name: rule.policy_name.clone(),
                framework: rule.framework.clone(),
                severity: rule.rule.severity.clone(),
                file_path: file_path.to_string(),
                line: (line_idx + 1) as u32,
                column: (mat.start() + 1) as u32,
                snippet: line.trim().to_string(),
                message: rule.violation_message(),
                auto_fixable,
            });
        }
    }
    violations
}

fn evaluate_forbidden_file(rule: &CompiledRule, file_path: &str) -> Vec<Violation> {
    let pattern = rule
        .rule
        .file_glob
        .as_deref()
        .or(rule.rule.pattern.as_deref());
    let Some(pattern) = pattern else {
        return Vec::new();
    };
    if !glob_matches(pattern, file_path) {
        return Vec::new();
    }
    vec![Violation {
        rule_id: rule.rule.id.clone(),
        policy_id: rule.policy_id.clone(),
        policy_name: rule.policy_name.clone(),
        framework: rule.framework.clone(),
        severity: rule.rule.severity.clone(),
        file_path: file_path.to_string(),
        line: 1,
        column: 1,
        snippet: file_path.to_string(),
        message: rule.violation_message(),
        auto_fixable: false,
    }]
}

fn evaluate_required_annotation(
    rule: &CompiledRule,
    file_path: &str,
    content: &str,
) -> Vec<Violation> {
    let Some(pii_regex) = &rule.regex else {
        return Vec::new();
    };
    let annotation = rule.rule.annotation.as_deref().unwrap_or("@gdpr");
    let mut violations = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        if !pii_regex.is_match(line) {
            continue;
        }
        let window_start = line_idx.saturating_sub(3);
        let window_end = (line_idx + 4).min(content.lines().count());
        let context: String = content
            .lines()
            .skip(window_start)
            .take(window_end - window_start)
            .collect::<Vec<_>>()
            .join("\n");
        if context.contains(annotation) {
            continue;
        }
        violations.push(Violation {
            rule_id: rule.rule.id.clone(),
            policy_id: rule.policy_id.clone(),
            policy_name: rule.policy_name.clone(),
            framework: rule.framework.clone(),
            severity: rule.rule.severity.clone(),
            file_path: file_path.to_string(),
            line: (line_idx + 1) as u32,
            column: 1,
            snippet: line.trim().to_string(),
            message: rule.violation_message(),
            auto_fixable: true,
        });
    }
    violations
}

fn evaluate_required_call(rule: &CompiledRule, file_path: &str, content: &str) -> Vec<Violation> {
    let sensitive = rule.regex.as_ref();
    let required = rule.rule.required_call.as_deref().unwrap_or("audit_log");
    if let Some(sensitive_re) = sensitive {
        if !sensitive_re.is_match(content) {
            return Vec::new();
        }
    }
    if content.contains(required) {
        return Vec::new();
    }
    vec![Violation {
        rule_id: rule.rule.id.clone(),
        policy_id: rule.policy_id.clone(),
        policy_name: rule.policy_name.clone(),
        framework: rule.framework.clone(),
        severity: rule.rule.severity.clone(),
        file_path: file_path.to_string(),
        line: 1,
        column: 1,
        snippet: format!("missing required call: {required}"),
        message: rule.violation_message(),
        auto_fixable: true,
    }]
}

fn glob_matches(glob: &str, path: &str) -> bool {
    Pattern::new(glob).map(|p| p.matches(path)).unwrap_or(false)
}
