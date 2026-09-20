//! CHP-gated write path integration tests.
//!
//! These drive the real subprocess bridge (`bridge/chp_gate.py`) against the
//! real policy definitions in `policies/`. The bridge needs the pure-Python
//! `consensus-hardening-protocol` package: install it and point `CAC_PYTHON`
//! at the interpreter (e.g. a venv) before running.

use cac_chp::{ChpGate, LockPolicy};
use cac_core::violation::{FixProposal, Violation};
use cac_fixer::Fixer;
use cac_scanner::{ScanConfig, Scanner};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn chp_python() -> String {
    std::env::var("CAC_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

/// Skip the test with a clear message when the CHP package is unavailable —
/// this keeps `cargo test` usable on machines without the Python dep, while
/// CI (which provisions CHP and sets CAC_PYTHON) always runs them.
fn chp_available() -> bool {
    Command::new(chp_python())
        .arg("-c")
        .arg("import chp")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn policy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policies")
}

const SECRET_LINE: &str = r#"let api_key = "sk-abc12345678";"#;

/// Seed a repo with one hardcoded-secret violation of secret-api-key.
fn seed_repo() -> (TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("config.rs"),
        format!("fn connect() {{\n    {SECRET_LINE}\n    // ...\n}}\n"),
    )
    .unwrap();
    let root = tmp.path().to_path_buf();
    (tmp, root)
}

fn scan_violations(root: &Path) -> Vec<Violation> {
    Scanner::from_config(ScanConfig::new(root, policy_dir()))
        .expect("scanner")
        .scan()
        .expect("scan")
        .violations
}

fn vault_proposal() -> FixProposal {
    // Parity passes (the vault lookup no longer matches the secret rule)
    // but the remediation family is wrong: no env::var() -> R0 Worth_it FATAL.
    FixProposal {
        violation_id: "src/config.rs:2".to_string(),
        file_path: "src/config.rs".to_string(),
        original_snippet: SECRET_LINE.to_string(),
        fixed_snippet: r#"let api_key = vault.read("api_key");"#.to_string(),
        description: "Read the key from a vault".to_string(),
        rule_id: "secret-api-key".to_string(),
        policy_id: "no-hardcoded-secrets".to_string(),
    }
}

fn still_secret_proposal() -> FixProposal {
    // "Fix" swaps one hardcoded secret for another: parity must fail.
    FixProposal {
        violation_id: "src/config.rs:2".to_string(),
        file_path: "src/config.rs".to_string(),
        original_snippet: SECRET_LINE.to_string(),
        fixed_snippet: r#"let api_key = "sk-ZZZ99988877";"#.to_string(),
        description: "Rotate the hardcoded key".to_string(),
        rule_id: "secret-api-key".to_string(),
        policy_id: "no-hardcoded-secrets".to_string(),
    }
}

fn ledger(root: &Path) -> Vec<Value> {
    let path = root.join(".cac/chp/decisions.jsonl");
    let raw = std::fs::read_to_string(&path).expect("decision ledger exists");
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("ledger line is JSON"))
        .collect()
}

/// The CHP envelope stores the decision body as a canonical JSON string;
/// parse it for assertion on body-level fields (r0_results, parity, ...).
fn body_of(record: &Value) -> Value {
    let body = record["body"].as_str().expect("body is a JSON string");
    serde_json::from_str(body).expect("body parses")
}

#[test]
fn ungated_apply_is_refused() {
    let (_tmp, root) = seed_repo();
    let fixer = Fixer::new(&root, false);
    let err = fixer
        .apply(&[])
        .expect_err("real writes must not bypass the gate");
    assert!(
        err.to_string().contains("CHP gate"),
        "unexpected error: {err}"
    );
}

#[test]
fn r0_refusal_records_decision() {
    if !chp_available() {
        panic!("CHP package unavailable: install consensus-hardening-protocol==0.1.1 and set CAC_PYTHON");
    }
    let (tmp, root) = seed_repo();
    let gate = ChpGate::new(&root, policy_dir());
    let fixer = Fixer::new(&root, false);
    let proposals = vec![vault_proposal()];

    let report = fixer
        .apply_gated(&proposals, &gate, LockPolicy::RequireHuman, None)
        .expect("gated run");

    assert_eq!(report.refused, 1);
    assert_eq!(report.applied, 0);
    assert_eq!(report.pending, 0);
    assert!(report.outcomes[0].detail.contains("R0 FATAL"));
    // Nothing was written.
    let content = std::fs::read_to_string(tmp.path().join("src/config.rs")).unwrap();
    assert!(content.contains(SECRET_LINE));
    // The refusal is on the ledger.
    let records = ledger(&root);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(records[0]["rule_id"], "secret-api-key");
    assert!(body_of(&records[0])["refusal_reason"]
        .as_str()
        .unwrap()
        .contains("R0 FATAL"));
}

#[test]
fn parity_failure_is_fatal_and_recorded() {
    if !chp_available() {
        panic!("CHP package unavailable: install consensus-hardening-protocol==0.1.1 and set CAC_PYTHON");
    }
    let (tmp, root) = seed_repo();
    let gate = ChpGate::new(&root, policy_dir());
    let fixer = Fixer::new(&root, false);
    let proposals = vec![still_secret_proposal()];

    // Even a named confirmer cannot carry a parity failure through the gate.
    let report = fixer
        .apply_gated(&proposals, &gate, LockPolicy::RequireHuman, Some("shyam"))
        .expect("gated run");

    assert_eq!(report.refused, 1);
    assert!(report.outcomes[0].detail.contains("parity"));
    let content = std::fs::read_to_string(tmp.path().join("src/config.rs")).unwrap();
    assert!(content.contains(SECRET_LINE), "file must be untouched");
    let records = ledger(&root);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(records[0]["confirmed_by"], "shyam");
}

#[test]
fn human_lock_flow_stages_then_applies() {
    if !chp_available() {
        panic!("CHP package unavailable: install consensus-hardening-protocol==0.1.1 and set CAC_PYTHON");
    }
    let (tmp, root) = seed_repo();
    let gate = ChpGate::new(&root, policy_dir());
    let fixer = Fixer::new(&root, false);

    let violations = scan_violations(&root);
    let proposals = fixer.propose(&violations);
    assert_eq!(proposals.len(), 1, "the secret should be auto-fixable");

    // Default policy: stage only — nothing lands without a named confirmer.
    let staged = fixer
        .apply_gated(&proposals, &gate, LockPolicy::RequireHuman, None)
        .expect("staging run");
    assert_eq!(staged.pending, 1);
    assert_eq!(staged.applied, 0);
    let decision_id = staged.outcomes[0].decision_id.clone();

    let content = std::fs::read_to_string(tmp.path().join("src/config.rs")).unwrap();
    assert!(
        content.contains(SECRET_LINE),
        "no write before the human lock"
    );

    let session =
        std::fs::read_to_string(root.join(format!(".cac/chp/sessions/{decision_id}.json")))
            .expect("session staged");
    let session: Value = serde_json::from_str(&session).unwrap();
    // The session file stores the CHP protocol status (upper-case).
    assert_eq!(session["status"], "PROVISIONAL_LOCK");

    // The human confirms: CHP third-party validation locks the decision,
    // the write lands, and post-write verification must pass.
    let confirmed = fixer
        .apply_gated(&proposals, &gate, LockPolicy::RequireHuman, Some("shyam"))
        .expect("confirm run");
    assert_eq!(confirmed.applied, 1);

    let content = std::fs::read_to_string(tmp.path().join("src/config.rs")).unwrap();
    assert!(
        content.contains(r#"std::env::var("api_key")"#),
        "fix must be applied: {content}"
    );
    assert!(!content.contains(SECRET_LINE));

    let records = ledger(&root);
    let applied: Vec<&Value> = records
        .iter()
        .filter(|r| r["outcome"] == "applied")
        .collect();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0]["confirmed_by"], "shyam");
    assert_eq!(applied[0]["session_status"], "locked");
    let body = body_of(applied[0]);
    assert_eq!(body["r0_results"]["Solvable"], "PASS");
    // Parity was re-verified after the write.
    assert_eq!(body["parity"]["resolved"], true);
}

#[test]
fn auto_confirm_opt_out_lands_with_record() {
    if !chp_available() {
        panic!("CHP package unavailable: install consensus-hardening-protocol==0.1.1 and set CAC_PYTHON");
    }
    let (tmp, root) = seed_repo();
    let gate = ChpGate::new(&root, policy_dir());
    let fixer = Fixer::new(&root, false);
    let violations = scan_violations(&root);
    let proposals = fixer.propose(&violations);

    let report = fixer
        .apply_gated(&proposals, &gate, LockPolicy::AutoConfirm, None)
        .expect("auto-confirm run");
    assert_eq!(report.applied, 1);

    let content = std::fs::read_to_string(tmp.path().join("src/config.rs")).unwrap();
    assert!(content.contains("env::var("));
    let records = ledger(&root);
    let applied: Vec<&Value> = records
        .iter()
        .filter(|r| r["outcome"] == "applied")
        .collect();
    assert_eq!(applied.len(), 1);
    assert_eq!(
        applied[0]["confirmed_by"],
        "cac-auto-confirm (REQUIRE_HUMAN_LOCK=0)"
    );
}

#[test]
fn ledger_round_trip_and_tamper_detection() {
    if !chp_available() {
        panic!("CHP package unavailable: install consensus-hardening-protocol==0.1.1 and set CAC_PYTHON");
    }
    let (_tmp, root) = seed_repo();
    let gate = ChpGate::new(&root, policy_dir());
    // Two staged (pending) decisions give the ledger content.
    let fixer = Fixer::new(&root, false);
    let proposals = vec![vault_proposal(), still_secret_proposal()];
    fixer
        .apply_gated(&proposals, &gate, LockPolicy::RequireHuman, None)
        .expect("gated run");

    let out = gate.read_decisions(None).expect("ledger read");
    let records = out["records"].as_array().expect("records array");
    assert_eq!(records.len(), 2);
    assert_eq!(out["all_integrity_valid"], true);
    assert_eq!(records[0]["integrity_valid"], true);
    assert_eq!(records[0]["envelope_valid"], true);

    // Tamper with the first record's body: the digest check must flag it.
    // The body is a JSON string — rewrite it as a different canonical body
    // while leaving body_sha256 untouched.
    let ledger_path = root.join(".cac/chp/decisions.jsonl");
    let raw = std::fs::read_to_string(&ledger_path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    let mut first: Value = serde_json::from_str(&lines[0]).unwrap();
    let mut body: Value = serde_json::from_str(first["body"].as_str().unwrap()).unwrap();
    body["outcome"] = Value::String("applied".to_string());
    first["body"] = Value::String(serde_json::to_string(&body).unwrap());
    lines[0] = serde_json::to_string(&first).unwrap();
    let mut tampered = lines.join("\n");
    tampered.push('\n');
    std::fs::write(&ledger_path, tampered).unwrap();

    let out = gate.read_decisions(None).expect("ledger read after tamper");
    assert_eq!(out["all_integrity_valid"], false);
    let records = out["records"].as_array().unwrap();
    // Read order is newest-first: records[0] is the untouched second
    // decision, records[1] is the tampered first one.
    assert_eq!(records[0]["integrity_valid"], true);
    assert_eq!(records[1]["integrity_valid"], false);
}

#[test]
fn scan_fix_record_integration() {
    if !chp_available() {
        panic!("CHP package unavailable: install consensus-hardening-protocol==0.1.1 and set CAC_PYTHON");
    }
    let (tmp, root) = seed_repo();
    let gate = ChpGate::new(&root, policy_dir());
    let fixer = Fixer::new(&root, false);

    // scan → fix (auto-confirm so the test is self-contained) → re-scan.
    let violations = scan_violations(&root);
    assert!(violations
        .iter()
        .any(|v| v.rule_id == "secret-api-key" && v.auto_fixable));
    let proposals = fixer.propose(&violations);
    let report = fixer
        .apply_gated(&proposals, &gate, LockPolicy::AutoConfirm, None)
        .expect("gated apply");
    assert_eq!(report.applied, 1);

    let after = scan_violations(&root);
    assert!(
        !after.iter().any(|v| v.rule_id == "secret-api-key"),
        "the fix must resolve the flagged violation"
    );
    let _ = tmp.keep();
}
