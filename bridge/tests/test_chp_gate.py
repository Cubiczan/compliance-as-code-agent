"""Bridge protocol tests: run chp_gate.py as a subprocess, exactly as the
Rust agent does. Requires consensus-hardening-protocol==0.1.1 importable by
the interpreter in CAC_TEST_PYTHON (default: python3)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

BRIDGE = Path(__file__).resolve().parent.parent / "chp_gate.py"


def run_gate(root: Path, command: str, payload: dict) -> tuple[int, dict]:
    proc = subprocess.run(
        [os.environ.get("CAC_TEST_PYTHON", sys.executable), str(BRIDGE), command],
        input=json.dumps({"root": str(root), **payload}),
        capture_output=True,
        text=True,
    )
    try:
        out = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        out = {"_raw": proc.stdout, "_stderr": proc.stderr}
    return proc.returncode, out


def r0_payload(**overrides) -> dict:
    base = {"solvable": True, "scoped": True, "valid": True, "worth_it": True}
    base.update(overrides)
    return base


def assess_payload(**parity) -> dict:
    parity.setdefault("ran", True)
    parity.setdefault("resolved", True)
    parity.setdefault("files_scanned", 2)
    return {
        "guardrail_checks": {
            "path_within_root": True,
            "snippet_anchored": True,
            "single_file_write": True,
        },
        "parity": parity,
    }


def open_payload(root: Path, decision_id: str = "fix-test0001") -> dict:
    return {
        "decision_id": decision_id,
        "title": "Fix secret-api-key in src/main.rs",
        "domain": "general",
        "owner": "cac-fixer-agent",
        "dossier": {
            "core_problem": "Resolve the flagged no-hardcoded-secrets violation",
            "current_state": ["violation flagged at src/main.rs:7"],
            "constraints": ["single-file write", "snippet-anchored replacement"],
            "scope": ["src/main.rs"],
        },
        "proposals": [
            {
                "violation_id": "src/main.rs:7",
                "file_path": "src/main.rs",
                "original_snippet": 'let api_key_val = "hardcoded";',
                "fixed_snippet": 'let api_key_val = std::env::var("API_KEY_VAL");',
                "description": "Replace hardcoded credential with env lookup",
            }
        ],
        "r0": {"verdict": "PASS", "results": {"Solvable": "PASS"}},
        "assessment": {"score": 100, "findings": ["ok"], "parity": {"resolved": True}},
        "parity": {"ran": True, "resolved": True, "files_scanned": 2},
    }


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path


# ------------------------------------------------------------------- R0
def test_r0_pass_has_capitalized_keys_and_exit_ok(root: Path):
    code, out = run_gate(root, "r0", r0_payload())
    assert code == 0
    assert out["verdict"] == "PASS"
    assert set(out["results"]) == {"Solvable", "Scoped", "Valid", "Worth_it"}
    assert all(v == "PASS" for v in out["results"].values())


def test_r0_failure_is_fatal_halt(root: Path):
    code, out = run_gate(root, "r0", r0_payload(solvable=False))
    assert code == 3  # refusal
    assert out["verdict"] == "HALT"
    assert out["results"]["Solvable"] == "FATAL"


@pytest.mark.parametrize("missing", ["solvable", "scoped", "valid", "worth_it"])
def test_each_r0_dimension_refuses_when_false(root: Path, missing: str):
    code, out = run_gate(root, "r0", r0_payload(**{missing: False}))
    assert code == 3
    assert out["results"][missing.capitalize() if missing != "worth_it" else "Worth_it"] == "FATAL"


# -------------------------------------------------------------- adversary
def test_assess_full_evidence_scores_100(root: Path):
    code, out = run_gate(root, "assess", assess_payload())
    assert code == 0
    assert out["score"] == 100
    assert out["floor"] == 70
    assert out["verdict"] == "PASS"
    assert out["fatal"] is False


def test_assess_parity_failure_is_fatal_even_at_floor(root: Path):
    code, out = run_gate(root, "assess", assess_payload(resolved=False))
    assert code == 3
    assert out["fatal"] is True
    # guardrails 40 + bounded 30 meet the 70 floor, but parity failure is fatal
    assert out["score"] == 70


def test_assess_missing_scan_is_fatal(root: Path):
    code, out = run_gate(root, "assess", assess_payload(ran=False, files_scanned=0))
    assert code == 3
    assert out["fatal"] is True


def test_assess_guardrail_failure_is_fatal(root: Path):
    payload = assess_payload()
    payload["guardrail_checks"]["path_within_root"] = False
    code, out = run_gate(root, "assess", payload)
    assert code == 3
    assert out["fatal"] is True
    assert out["score"] < 100


# -------------------------------------------------------------- lock flow
def test_open_sets_provisional_lock(root: Path):
    code, out = run_gate(root, "open", open_payload(root))
    assert code == 0, out
    assert out["status"] == "PROVISIONAL_LOCK"
    assert out["r0_verdict"] == "PASS"
    assert (root / ".cac" / "chp" / "sessions" / "fix-test0001.json").exists()


def test_confirm_locks_with_confirmed_by(root: Path):
    run_gate(root, "open", open_payload(root))
    code, out = run_gate(root, "confirm", {
        "decision_id": "fix-test0001", "confirmed_by": "sam@cubiczan.com",
    })
    assert code == 0, out
    assert out["status"] == "LOCKED"
    # the confirmed proposals round-trip back for the write stage
    assert out["proposals"][0]["file_path"] == "src/main.rs"


def test_confirm_without_open_fails(root: Path):
    code, out = run_gate(root, "confirm", {
        "decision_id": "fix-missing", "confirmed_by": "sam@cubiczan.com",
    })
    assert code == 3  # fail-closed refusal


def test_confirm_requires_confirmed_by(root: Path):
    run_gate(root, "open", open_payload(root))
    code, out = run_gate(root, "confirm", {
        "decision_id": "fix-test0001", "confirmed_by": "  ",
    })
    assert code == 2  # protocol error, fail-closed


def test_double_confirm_fails(root: Path):
    run_gate(root, "open", open_payload(root))
    ok = run_gate(root, "confirm", {
        "decision_id": "fix-test0001", "confirmed_by": "sam@cubiczan.com",
    })
    assert ok[0] == 0
    code, out = run_gate(root, "confirm", {
        "decision_id": "fix-test0001", "confirmed_by": "sam@cubiczan.com",
    })
    assert code == 2
    assert "PROVISIONAL_LOCK" in out["error"]


def test_reject_returns_to_exploring(root: Path):
    run_gate(root, "open", open_payload(root))
    code, out = run_gate(root, "reject", {
        "decision_id": "fix-test0001", "confirmed_by": "sam@cubiczan.com",
    })
    assert code == 0
    assert out["status"] == "EXPLORING"


# ------------------------------------------------------------------ ledger
def record_payload(root: Path, outcome: str = "applied") -> dict:
    return {
        "decision_id": "fix-test0001",
        "outcome": outcome,
        "title": "Fix secret-api-key in src/main.rs",
        "rule_id": "secret-api-key",
        "policy_id": "no-hardcoded-secrets",
        "file_path": "src/main.rs",
        "session_status": "LOCKED" if outcome == "applied" else None,
        "r0_verdict": "PASS",
        "foundation_verdict": "PASS",
        "foundation_score": 100,
        "confirmed_by": "sam@cubiczan.com" if outcome == "applied" else None,
        "landed_via": "cli_confirm",
    }


def test_record_then_read_round_trip(root: Path):
    code, out = run_gate(root, "record", record_payload(root))
    assert code == 0, out
    code, out = run_gate(root, "read", {})
    assert code == 0
    assert out["all_integrity_valid"] is True
    assert len(out["records"]) == 1
    rec = out["records"][0]
    assert rec["outcome"] == "applied"
    assert rec["envelope_valid"] is True
    assert rec["integrity_valid"] is True
    assert rec["body_sha256"] == hashlib.sha256(rec["body"].encode()).hexdigest()


def test_read_empty_ledger_is_valid(root: Path):
    code, out = run_gate(root, "read", {})
    assert code == 0
    assert out == {"records": [], "all_integrity_valid": True}


def test_body_tamper_detected_on_read(root: Path):
    run_gate(root, "record", record_payload(root))
    ledger = root / ".cac" / "chp" / "decisions.jsonl"
    entries = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
    entries[0]["body"] = entries[0]["body"].replace('"applied"', '"refused"')
    ledger.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    code, out = run_gate(root, "read", {})
    assert out["all_integrity_valid"] is False
    assert out["records"][0]["integrity_valid"] is False


def test_envelope_tamper_detected_on_read(root: Path):
    run_gate(root, "record", record_payload(root))
    ledger = root / ".cac" / "chp" / "decisions.jsonl"
    entries = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
    entries[0]["envelope"] = entries[0]["envelope"].replace("BEGIN_PAYLOAD", "BEGIN_PAYLOAD_X")
    ledger.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    code, out = run_gate(root, "read", {})
    assert out["records"][0]["envelope_valid"] is False
    assert out["all_integrity_valid"] is False


def test_refusal_record_round_trips(root: Path):
    code, out = run_gate(root, "record", record_payload(root, outcome="refused"))
    assert code == 0
    code, out = run_gate(root, "read", {})
    assert out["records"][0]["outcome"] == "refused"
    assert out["records"][0]["session_status"] is None
    assert out["all_integrity_valid"] is True


# ------------------------------------------------------------- fail-closed
def test_unknown_command_errors(root: Path):
    proc = subprocess.run(
        [os.environ.get("CAC_TEST_PYTHON", sys.executable), str(BRIDGE), "nope"],
        input="{}", capture_output=True, text=True,
    )
    assert proc.returncode == 2
    assert "error" in json.loads(proc.stdout)


def test_missing_chp_package_fails_closed(root: Path):
    """Without site-packages (no chp import) the bridge must exit 2, never succeed."""
    proc = subprocess.run(
        [os.environ.get("CAC_TEST_PYTHON", sys.executable), "-S", str(BRIDGE), "r0"],
        input=json.dumps({"root": str(root), **r0_payload()}),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    out = json.loads(proc.stdout)
    assert out["error"] == "consensus_hardening_protocol_unavailable"
