use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    Detect,
    Fix,
    Validate,
    Scan,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub phase: AuditPhase,
    pub agent: String,
    pub action: String,
    pub policy_id: Option<String>,
    pub rule_id: Option<String>,
    pub file_path: Option<String>,
    pub details: serde_json::Value,
    pub content_hash: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LedgerConfig {
    pub signing_key: Option<String>,
    pub ledger_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct AuditLedger {
    config: LedgerConfig,
}

impl AuditLedger {
    pub fn new(config: LedgerConfig) -> Self {
        Self { config }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        phase: AuditPhase,
        agent: &str,
        action: &str,
        policy_id: Option<&str>,
        rule_id: Option<&str>,
        file_path: Option<&str>,
        details: serde_json::Value,
    ) -> Result<AuditEvent, AuditError> {
        let timestamp = Utc::now();
        let canonical = serde_json::json!({
            "phase": phase,
            "agent": agent,
            "action": action,
            "policy_id": policy_id,
            "rule_id": rule_id,
            "file_path": file_path,
            "details": details,
            "timestamp": timestamp.to_rfc3339(),
        });
        let content_hash = hash_payload(&canonical);
        let signature = self
            .config
            .signing_key
            .as_ref()
            .map(|key| sign_payload(key, &content_hash));

        let event = AuditEvent {
            id: format!("cac-{}", &content_hash[..16]),
            timestamp,
            phase,
            agent: agent.to_string(),
            action: action.to_string(),
            policy_id: policy_id.map(str::to_string),
            rule_id: rule_id.map(str::to_string),
            file_path: file_path.map(str::to_string),
            details,
            content_hash,
            signature,
        };

        self.append(&event)?;
        Ok(event)
    }

    pub fn read_all(&self) -> Result<Vec<AuditEvent>, AuditError> {
        if !self.config.ledger_path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.config.ledger_path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            events.push(serde_json::from_str(&line)?);
        }
        Ok(events)
    }

    fn append(&self, event: &AuditEvent) -> Result<(), AuditError> {
        if let Some(parent) = self.config.ledger_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.ledger_path)?;
        writeln!(file, "{}", serde_json::to_string(event)?)?;
        Ok(())
    }
}

pub fn hash_payload(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn sign_payload(key: &str, content_hash: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(content_hash.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn default_ledger_path(root: &Path) -> PathBuf {
    root.join(".cac").join("audit.jsonl")
}
