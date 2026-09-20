use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicySeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    SecretPattern,
    ForbiddenFile,
    RequiredAnnotation,
    RequiredCall,
    CustomRegex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub kind: RuleKind,
    pub description: String,
    pub severity: PolicySeverity,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub file_glob: Option<String>,
    #[serde(default)]
    pub annotation: Option<String>,
    #[serde(default)]
    pub required_call: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub framework: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPack {
    pub version: String,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse policy YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid regex in rule {rule_id}: {source}")]
    InvalidRegex {
        rule_id: String,
        #[source]
        source: regex::Error,
    },
}

impl PolicyPack {
    pub fn load_dir(dir: &Path) -> Result<Self, PolicyError> {
        let mut policies = Vec::new();
        if !dir.exists() {
            return Ok(Self {
                version: "1.0".into(),
                policies,
            });
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml")
                || path.extension().and_then(|e| e.to_str()) == Some("yml")
            {
                let content = std::fs::read_to_string(&path)?;
                let policy: Policy = serde_yaml::from_str(&content)?;
                policies.push(policy);
            }
        }

        policies.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self {
            version: "1.0".into(),
            policies,
        })
    }

    pub fn compile_rules(&self) -> Result<Vec<CompiledRule>, PolicyError> {
        let mut compiled = Vec::new();
        for policy in &self.policies {
            for rule in &policy.rules {
                let regex = match rule.kind {
                    RuleKind::SecretPattern | RuleKind::CustomRegex => {
                        let pattern =
                            rule.pattern
                                .as_ref()
                                .ok_or_else(|| PolicyError::InvalidRegex {
                                    rule_id: rule.id.clone(),
                                    source: regex::Error::Syntax("missing pattern".into()),
                                })?;
                        Some(
                            Regex::new(pattern).map_err(|source| PolicyError::InvalidRegex {
                                rule_id: rule.id.clone(),
                                source,
                            })?,
                        )
                    }
                    RuleKind::RequiredAnnotation | RuleKind::RequiredCall => rule
                        .pattern
                        .as_ref()
                        .map(|p| {
                            Regex::new(p).map_err(|source| PolicyError::InvalidRegex {
                                rule_id: rule.id.clone(),
                                source,
                            })
                        })
                        .transpose()?,
                    RuleKind::ForbiddenFile => None,
                };

                compiled.push(CompiledRule {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    framework: policy.framework.clone(),
                    rule: rule.clone(),
                    regex,
                });
            }
        }
        Ok(compiled)
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub policy_id: String,
    pub policy_name: String,
    pub framework: String,
    pub rule: PolicyRule,
    pub regex: Option<Regex>,
}

impl CompiledRule {
    pub fn violation_message(&self) -> String {
        self.rule
            .message
            .clone()
            .unwrap_or_else(|| self.rule.description.clone())
    }
}
