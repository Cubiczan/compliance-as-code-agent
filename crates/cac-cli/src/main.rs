use anyhow::{bail, Context, Result};
use cac_chp::{ChpGate, LockPolicy};
use cac_core::{
    audit::{default_ledger_path, AuditLedger, AuditPhase, LedgerConfig},
    violation::{FixProposal, ScanReport},
};
use cac_fixer::Fixer;
use cac_scanner::{ScanConfig, Scanner};
use cac_validator::Validator;
use cac_webhook::{run_server, WebhookConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cac",
    about = "Compliance-as-Code Agent — scan, fix, and validate codebases against organizational policies",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    globals: GlobalOpts,
}

#[derive(Parser)]
struct GlobalOpts {
    /// Repository root to scan
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,

    /// Directory containing policy YAML files
    #[arg(long, global = true, default_value = "policies")]
    policies: PathBuf,

    /// HMAC signing key for audit ledger (or set CAC_LEDGER_SIGNING_KEY)
    #[arg(long, global = true, env = "CAC_LEDGER_SIGNING_KEY")]
    signing_key: Option<String>,

    /// Output format: json or text
    #[arg(long, global = true, default_value = "text")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Detector agent: scan codebase for policy violations
    Scan,
    /// Fixer agent: propose and apply auto-fixes (CHP-gated writes)
    Fix {
        /// Preview fixes without writing files
        #[arg(long)]
        dry_run: bool,
        /// Named human confirmer: locks the staged decisions via CHP
        /// third-party validation and applies them. Omitted (with the
        /// default REQUIRE_HUMAN_LOCK policy) fixes are staged as
        /// PROVISIONAL_LOCK and nothing is written until `cac confirm`.
        #[arg(long)]
        confirmed_by: Option<String>,
    },
    /// Validator agent: re-scan and adversarially validate fixes
    Validate {
        /// Number of fixes applied in prior step
        #[arg(long, default_value_t = 0)]
        fixes_applied: usize,
    },
    /// Full pipeline: detect → fix (CHP-gated) → validate
    Run {
        #[arg(long)]
        dry_run: bool,
        /// Named human confirmer for the fix stage (see `fix`)
        #[arg(long)]
        confirmed_by: Option<String>,
    },
    /// Human lock: apply fixes staged as PROVISIONAL_LOCK by a prior `fix`
    Confirm {
        /// Decision id reported by the earlier `fix` run
        #[arg(long)]
        decision_id: String,
        /// Name of the human confirming the fix (recorded in the ledger)
        #[arg(long)]
        confirmed_by: String,
    },
    // CAC-REVIEW: human-confirmation entry — `cac confirm` is the only
    // command that turns staged PROVISIONAL_LOCK decisions into writes; the
    // confirmer identity is recorded in .cac/chp/decisions.jsonl.
    /// Show CHP decision-ledger records with integrity status
    Decisions,
    /// Show signed audit trail
    Audit,
    /// Verifiable agent-run packet: scan report, decision register, audit tail
    Packet,
    /// Start PR webhook server (GitHub + Codeberg/Gitea)
    Serve {
        /// Bind address (overrides CAC_BIND_ADDR)
        #[arg(long, env = "CAC_BIND_ADDR", default_value = "0.0.0.0:8080")]
        bind: String,
        /// Webhook HMAC secret (overrides CAC_WEBHOOK_SECRET)
        #[arg(long, env = "CAC_WEBHOOK_SECRET")]
        webhook_secret: Option<String>,
        /// Enable auto-fix PR creation on violations
        #[arg(long, env = "CAC_AUTO_FIX_PR")]
        auto_fix_pr: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ledger = build_ledger(&cli.globals)?;

    match cli.command {
        Commands::Scan => {
            let report = scan(&cli.globals)?;
            ledger.record(
                AuditPhase::Detect,
                "detector-agent",
                "scan_complete",
                None,
                None,
                None,
                serde_json::json!({
                    "violations": report.violation_count(),
                    "files_scanned": report.files_scanned,
                }),
            )?;
            emit_scan(&cli.globals.format, &report)?;
            if report.has_critical() {
                std::process::exit(1);
            }
        }
        Commands::Fix {
            dry_run,
            confirmed_by,
        } => {
            let report = scan(&cli.globals)?;
            let fixer = Fixer::new(&cli.globals.root, dry_run);
            let proposals = fixer.propose(&report.violations);
            if dry_run {
                let matched = fixer.apply(&proposals)?;
                ledger.record(
                    AuditPhase::Fix,
                    "fixer-agent",
                    "dry_run",
                    None,
                    None,
                    None,
                    serde_json::json!({
                        "proposed": proposals.len(),
                        "matched": matched,
                        "dry_run": true,
                    }),
                )?;
                if cli.globals.format == "json" {
                    println!("{}", serde_json::to_string_pretty(&proposals)?);
                } else {
                    println!(
                        "Proposed {} fix(es), {} would match (dry run — no writes)",
                        proposals.len(),
                        matched
                    );
                    for p in &proposals {
                        println!(
                            "  [{}] {} — {}",
                            p.file_path, p.description, p.fixed_snippet
                        );
                    }
                }
            } else {
                let gate = ChpGate::new(&cli.globals.root, &cli.globals.policies);
                let lock_policy = LockPolicy::from_env();
                let gated =
                    fixer.apply_gated(&proposals, &gate, lock_policy, confirmed_by.as_deref())?;
                ledger.record(
                    AuditPhase::Fix,
                    "fixer-agent",
                    "chp_gated_fix",
                    None,
                    None,
                    None,
                    serde_json::json!({
                        "proposed": proposals.len(),
                        "applied": gated.applied,
                        "refused": gated.refused,
                        "pending_human_lock": gated.pending,
                        "lock_policy": lock_policy_name(lock_policy),
                    }),
                )?;
                if cli.globals.format == "json" {
                    println!("{}", serde_json::to_string_pretty(&gated)?);
                } else {
                    println!(
                        "Proposed {} fix(es): {} applied, {} refused, {} pending human lock",
                        proposals.len(),
                        gated.applied,
                        gated.refused,
                        gated.pending
                    );
                    for o in &gated.outcomes {
                        println!("  [{}] {}: {}", o.decision_id, o.result, o.detail);
                    }
                }
            }
        }
        Commands::Validate { fixes_applied } => {
            let original = scan(&cli.globals)?;
            let validator = Validator::new(&cli.globals.root, &cli.globals.policies);
            let report = validator.validate_after_fix(&original, fixes_applied)?;
            ledger.record(
                AuditPhase::Validate,
                "validator-agent",
                if report.passed { "passed" } else { "failed" },
                None,
                None,
                None,
                serde_json::json!({
                    "original": report.original_violations,
                    "remaining": report.remaining_violations,
                    "fixes_applied": report.fixes_applied,
                    "adversarial_notes": report.adversarial_notes,
                }),
            )?;
            if cli.globals.format == "json" {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Validation {} — {}/{} violations remain after {} fix(es)",
                    if report.passed { "PASSED" } else { "FAILED" },
                    report.remaining_violations,
                    report.original_violations,
                    report.fixes_applied
                );
                for note in &report.adversarial_notes {
                    println!("  • {note}");
                }
            }
            if !report.passed {
                std::process::exit(1);
            }
        }
        Commands::Run {
            dry_run,
            confirmed_by,
        } => {
            let original = scan(&cli.globals)?;
            ledger.record(
                AuditPhase::Detect,
                "detector-agent",
                "scan_complete",
                None,
                None,
                None,
                serde_json::json!({ "violations": original.violation_count() }),
            )?;

            let fixer = Fixer::new(&cli.globals.root, dry_run);
            let proposals = fixer.propose(&original.violations);
            let applied = if dry_run {
                fixer.apply(&proposals)?
            } else {
                let gate = ChpGate::new(&cli.globals.root, &cli.globals.policies);
                let lock_policy = LockPolicy::from_env();
                let gated =
                    fixer.apply_gated(&proposals, &gate, lock_policy, confirmed_by.as_deref())?;
                ledger.record(
                    AuditPhase::Fix,
                    "fixer-agent",
                    "chp_gated_fix",
                    None,
                    None,
                    None,
                    serde_json::json!({
                        "proposed": proposals.len(),
                        "applied": gated.applied,
                        "refused": gated.refused,
                        "pending_human_lock": gated.pending,
                        "lock_policy": lock_policy_name(lock_policy),
                    }),
                )?;
                if gated.pending > 0 {
                    println!(
                        "Fix stage: {} fix(es) pending human lock — nothing written.\n\
                         Complete them with: cac confirm --decision-id <id> --confirmed-by <who>\n\
                         (see `cac decisions`); skipping validation of unapplied fixes.",
                        gated.pending
                    );
                }
                gated.applied
            };
            if dry_run {
                ledger.record(
                    AuditPhase::Fix,
                    "fixer-agent",
                    "dry_run",
                    None,
                    None,
                    None,
                    serde_json::json!({ "proposed": proposals.len(), "applied": applied }),
                )?;
            }

            let validator = Validator::new(&cli.globals.root, &cli.globals.policies);
            let validation = validator.validate_after_fix(&original, applied)?;
            ledger.record(
                AuditPhase::Validate,
                "validator-agent",
                if validation.passed {
                    "passed"
                } else {
                    "failed"
                },
                None,
                None,
                None,
                serde_json::json!({
                    "remaining": validation.remaining_violations,
                    "passed": validation.passed,
                }),
            )?;

            if cli.globals.format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "scan": original,
                        "fixes_applied": applied,
                        "validation": validation,
                    }))?
                );
            } else {
                println!("=== Compliance-as-Code Pipeline ===");
                println!(
                    "Detect: {} violation(s) in {} file(s)",
                    original.violation_count(),
                    original.files_scanned
                );
                println!(
                    "Fix:    {} proposal(s), {} applied",
                    proposals.len(),
                    applied
                );
                println!(
                    "Validate: {} — {} remaining",
                    if validation.passed {
                        "PASSED"
                    } else {
                        "FAILED"
                    },
                    validation.remaining_violations
                );
            }
            if !validation.passed {
                std::process::exit(1);
            }
        }
        Commands::Audit => {
            let events = ledger.read_all()?;
            if cli.globals.format == "json" {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                println!("Audit trail ({} events):", events.len());
                for e in events {
                    println!(
                        "  [{}] {:?} {} — {} ({})",
                        e.timestamp, e.phase, e.agent, e.action, e.id
                    );
                }
            }
        }
        Commands::Packet => {
            // Agent-run evidence packet: the deterministic scan, the CHP
            // decision register with integrity status, and the signed audit
            // tail, assembled from the sources the agents themselves write —
            // a reviewer can reperform the run instead of trusting a
            // self-report. The gate read fails closed when the bridge is
            // unavailable; the packet still carries scan + audit evidence.
            let report = scan(&cli.globals)?;
            let gate = ChpGate::new(&cli.globals.root, &cli.globals.policies);
            let decisions = gate.read_decisions(None).map(Some).unwrap_or_else(|e| {
                eprintln!("packet: decision register unavailable: {e}");
                None
            });
            let events = ledger.read_all()?;
            let packet = serde_json::json!({
                "packet_version": 1,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "root": cli.globals.root.display().to_string(),
                "scan": {
                    "scanned_at": report.scanned_at,
                    "files_scanned": report.files_scanned,
                    "violation_count": report.violation_count(),
                    "violations": report.violations,
                },
                "decision_register": decisions.map(|d| {
                    let records = d["records"].as_array().cloned().unwrap_or_default();
                    serde_json::json!({
                        "record_count": records.len(),
                        "all_integrity_valid": d["all_integrity_valid"],
                        "records": records,
                    })
                }),
                "audit_events": events,
            });
            if cli.globals.format == "json" {
                println!("{}", serde_json::to_string_pretty(&packet)?);
            } else {
                let violations = packet["scan"]["violation_count"].as_u64().unwrap_or(0);
                let records = packet["decision_register"]["record_count"]
                    .as_u64()
                    .unwrap_or(0);
                println!(
                    "Agent-run packet for {} — violations: {violations}, decisions: {records}, audit events: {}",
                    packet["root"].as_str().unwrap_or("."),
                    events.len()
                );
            }
        }
        Commands::Confirm {
            decision_id,
            confirmed_by,
        } => {
            let proposals = load_staged_proposals(&cli.globals.root, &decision_id)?;
            let fixer = Fixer::new(&cli.globals.root, false);
            let gate = ChpGate::new(&cli.globals.root, &cli.globals.policies);
            let gated = fixer.apply_gated(
                &proposals,
                &gate,
                LockPolicy::RequireHuman,
                Some(&confirmed_by),
            )?;
            ledger.record(
                AuditPhase::Fix,
                "human-operator",
                "confirm_fixes",
                None,
                None,
                None,
                serde_json::json!({
                    "decision_id": decision_id,
                    "confirmed_by": confirmed_by,
                    "applied": gated.applied,
                    "refused": gated.refused,
                }),
            )?;
            if cli.globals.format == "json" {
                println!("{}", serde_json::to_string_pretty(&gated)?);
            } else {
                println!(
                    "Decision {decision_id}: {} applied, {} refused",
                    gated.applied, gated.refused
                );
                for o in &gated.outcomes {
                    println!("  [{}] {}: {}", o.decision_id, o.result, o.detail);
                }
            }
            if gated.refused > 0 {
                std::process::exit(1);
            }
        }
        Commands::Decisions => {
            let gate = ChpGate::new(&cli.globals.root, &cli.globals.policies);
            let out = gate.read_decisions(None)?;
            if cli.globals.format == "json" {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                let records = out["records"].as_array().cloned().unwrap_or_default();
                println!(
                    "CHP decision ledger ({} record(s), integrity_ok={})",
                    records.len(),
                    out["all_integrity_valid"].as_bool().unwrap_or(false)
                );
                for r in &records {
                    // The body is a canonical JSON string; parse it for the
                    // body-level fields (r0_verdict lives inside).
                    let body: serde_json::Value =
                        serde_json::from_str(r["body"].as_str().unwrap_or("{}"))
                            .unwrap_or(serde_json::Value::Null);
                    println!(
                        "  [{}] {} outcome={} rule={} file={} integrity_valid={} r0={}",
                        r["created_at"].as_str().unwrap_or(""),
                        r["decision_id"].as_str().unwrap_or(""),
                        r["outcome"].as_str().unwrap_or(""),
                        r["rule_id"].as_str().unwrap_or(""),
                        r["file_path"].as_str().unwrap_or(""),
                        r["integrity_valid"].as_bool().unwrap_or(false),
                        body["r0_verdict"].as_str().unwrap_or("n/a"),
                    );
                }
            }
        }
        Commands::Serve {
            bind,
            webhook_secret,
            auto_fix_pr,
        } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();

            let mut config = WebhookConfig::from_env(cli.globals.policies.clone());
            config.bind_addr = bind;
            config.policies_dir = cli.globals.policies;
            config.signing_key = cli.globals.signing_key;
            if let Some(secret) = webhook_secret {
                config.webhook_secret = secret;
            }
            if auto_fix_pr {
                config.auto_fix_pr = true;
            }

            println!("CAC webhook server starting on {}", config.bind_addr);
            println!("  POST /webhook         — auto-detect GitHub or Gitea");
            println!("  POST /webhook/github  — GitHub pull_request events");
            println!("  POST /webhook/gitea   — Codeberg/Gitea pull_request events");
            println!("  GET  /health          — liveness probe");

            tokio::runtime::Runtime::new()?
                .block_on(run_server(config))
                .map_err(|err| anyhow::anyhow!("webhook server failed: {err}"))?;
        }
    }

    Ok(())
}

fn build_ledger(opts: &GlobalOpts) -> Result<AuditLedger> {
    Ok(AuditLedger::new(LedgerConfig {
        signing_key: opts.signing_key.clone(),
        ledger_path: default_ledger_path(&opts.root),
    }))
}

fn lock_policy_name(policy: LockPolicy) -> &'static str {
    match policy {
        LockPolicy::RequireHuman => "require_human_lock",
        LockPolicy::AutoConfirm => "auto_confirm",
        LockPolicy::ProposeBranch => "propose_branch",
    }
}

/// Load the proposals stored in a staged decision session (written by
/// `fix` under PROVISIONAL_LOCK) so `confirm` can apply exactly what was
/// staged.
fn load_staged_proposals(root: &std::path::Path, decision_id: &str) -> Result<Vec<FixProposal>> {
    let path = root
        .join(".cac/chp/sessions")
        .join(format!("{decision_id}.json"));
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("no staged decision session at {}", path.display()))?;
    let session: serde_json::Value = serde_json::from_str(&raw)?;
    // Session files store the CHP protocol status (upper-case).
    let status = session["status"].as_str().unwrap_or_default();
    if !status.eq_ignore_ascii_case("provisional_lock") {
        bail!("decision {decision_id} is not awaiting confirmation (status: {status})");
    }
    let proposals: Vec<FixProposal> = serde_json::from_value(session["proposals"].clone())
        .context("staged session has unusable proposals")?;
    Ok(proposals)
}

fn scan(opts: &GlobalOpts) -> Result<ScanReport> {
    let scanner = Scanner::from_config(ScanConfig::new(&opts.root, &opts.policies))
        .context("failed to initialize scanner")?;
    scanner.scan().context("scan failed")
}

fn emit_scan(format: &str, report: &ScanReport) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if report.violations.is_empty() {
        println!(
            "No violations found ({} files scanned)",
            report.files_scanned
        );
    } else {
        println!(
            "Found {} violation(s) across {} files scanned:\n",
            report.violations.len(),
            report.files_scanned
        );
        for v in &report.violations {
            println!(
                "[{:?}] {}:{} — {} ({})",
                v.severity, v.file_path, v.line, v.message, v.rule_id
            );
            println!("    {}", v.snippet);
        }
    }
    Ok(())
}
