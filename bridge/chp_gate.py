#!/usr/bin/env python3
"""CHP gate for auto-fix writes (consensus-hardening-protocol 0.1.1).

Subprocess bridge called by the Rust agent (crates/cac-chp). The scan side of
the agent stays ungated; every auto-fix WRITE passes through here first:

  R0 gate -> deterministic adversary (guardrails 40 + bounded scan 30
  + parity 30, general floor 70) -> human lock (PROVISIONAL_LOCK ->
  third-party validation -> LOCKED) -> decision record in an append-only
  JSONL ledger with body_sha256 integrity, re-validated on read.

Parity is judged by the caller, which re-scans a fixed copy of the flagged
file against the real policy definitions; this script scores the evidence
and enforces the fatal rules (R0 HALT and parity failure are fatal even
with a named confirmer).

Protocol: one JSON document on stdin, one JSON document on stdout.
Exit 0 = command succeeded, 3 = gate refusal (fatal), 2 = protocol/infra
error (fail-closed: the caller must treat this as a refusal too).

Commands: r0, assess, open, confirm, reject, record, read.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Protocol exit codes (defined before the chp import so the fail-closed
# path below can use them before anything else in this module loads).
EXIT_OK = 0
EXIT_ERROR = 2
EXIT_REFUSED = 3


def _chp_unavailable() -> None:
    print(json.dumps({
        "error": "consensus_hardening_protocol_unavailable",
        "detail": "the consensus-hardening-protocol package is not importable",
        "hint": "pip install consensus-hardening-protocol==0.1.1",
    }))
    sys.exit(EXIT_ERROR)


try:
    from chp import (
        CHPOrchestrator,
        DecisionCase,
        Dossier,
        FoundationAttack,
        FoundationDisclosure,
        SessionStatus,
        ThirdPartyValidation,
        ValidationResult,
        Verdict,
        apply_third_party_validation,
        build_payload_envelope,
        validate_payload_envelope,
    )
    from chp.foundation import foundation_floor, foundation_verdict
    from chp.gates import evaluate_r0_gate
except ImportError:
    # fail-closed: no CHP, no fixes
    _chp_unavailable()
    sys.exit(EXIT_ERROR)  # pragma: no cover

# Deterministic adversary scoring (out of 100), mirroring the erp-control-plane
# promotion gate: evidence inputs come from executed checks, not self-report.
_GUARDRAIL_POINTS = 40
_BOUNDED_SCAN_POINTS = 30
_PARITY_POINTS = 30
_FULL_SCORE = _GUARDRAIL_POINTS + _BOUNDED_SCAN_POINTS + _PARITY_POINTS

GENERAL_FLOOR = foundation_floor("general")  # 70

ENVELOPE_ROUTE = "CAC-FIX"


class Refusal(Exception):
    """A fatal gate verdict: the fix must not land."""

    def __init__(self, reason: str, payload: dict[str, Any]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.payload = payload


def _fail(message: str) -> None:  # pragma: no cover - used before imports land
    print(json.dumps({"error": message}))
    sys.exit(EXIT_ERROR)


def _utcnow() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def state_dir(root: str) -> Path:
    return Path(root) / ".cac" / "chp"


def session_path(root: str, decision_id: str) -> Path:
    return state_dir(root) / "sessions" / f"{decision_id}.json"


def ledger_path(root: str) -> Path:
    return state_dir(root) / "decisions.jsonl"


# --------------------------------------------------------------------- R0
def cmd_r0(req: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Evaluate the pre-write R0 gate. Result keys are capitalized; any
    FATAL is a HALT refusal."""
    evaluation = evaluate_r0_gate(
        solvable=bool(req.get("solvable")),
        scoped=bool(req.get("scoped")),
        valid=bool(req.get("valid")),
        worth_it=bool(req.get("worth_it")),
    )
    out = {
        "results": dict(evaluation.results),
        "verdict": evaluation.verdict.value,
    }
    if evaluation.verdict.value != "PASS":
        return out, EXIT_REFUSED
    return out, EXIT_OK


# --------------------------------------------------------------- adversary
def cmd_assess(req: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Score the fix's foundation from executed-check evidence.

    Inputs (all produced by the caller's real checks):
      guardrail_checks: {path_within_root, snippet_anchored, single_file_write}
      parity: {ran, resolved, files_scanned, ...evidence}
    A parity failure is fatal regardless of score or confirmer.
    """
    guard = req.get("guardrail_checks") or {}
    parity = req.get("parity") or {}
    findings: list[str] = []
    score = 0

    guard_ok = all(bool(guard.get(k)) for k in (
        "path_within_root", "snippet_anchored", "single_file_write"))
    if guard_ok:
        score += _GUARDRAIL_POINTS
        findings.append(
            "guardrails passed: write bounded to the flagged file, "
            "snippet-anchored replacement, single-file mutation"
        )
    else:
        failed = [k for k in ("path_within_root", "snippet_anchored",
                              "single_file_write") if not guard.get(k)]
        findings.append(f"guardrail check failed: {', '.join(sorted(failed))}")

    scan_ran = bool(parity.get("ran"))
    files_scanned = int(parity.get("files_scanned") or 0)
    if scan_ran and files_scanned >= 1:
        score += _BOUNDED_SCAN_POINTS
        findings.append(
            f"bounded scan: parity re-scan executed over {files_scanned} file(s) "
            "against the policy definitions"
        )
    else:
        findings.append("no bounded scan evidence — parity re-scan did not run")

    resolved = bool(parity.get("resolved"))
    evidence = {k: v for k, v in parity.items() if k not in ("ran",)}
    if scan_ran and resolved:
        score += _PARITY_POINTS
        findings.append("parity: the fixed content no longer matches the flagged rule")
    elif scan_ran and not resolved:
        findings.append(
            "parity FAILURE: the fix does not resolve the flagged violation "
            "against the policy definition"
        )
    else:
        findings.append("parity unavailable: re-scan failed — treating as fatal")

    fatal = not (scan_ran and resolved) or not guard_ok
    verdict = foundation_verdict(
        FoundationAttack(foundation_score=score, attack_summary="; ".join(findings),
                         assumption_attacks=["x", "y", "z"]),
        domain=req.get("domain") or "general",
    )
    out = {
        "score": min(score, _FULL_SCORE),
        "domain": req.get("domain") or "general",
        "floor": GENERAL_FLOOR,
        "verdict": verdict.value,
        "fatal": fatal,
        "findings": findings,
        "parity": evidence,
    }
    if fatal:
        return out, EXIT_REFUSED
    if verdict != Verdict.PASS:
        return out, EXIT_REFUSED
    return out, EXIT_OK


# ------------------------------------------------------------- human lock
def _build_case(req: dict[str, Any]) -> DecisionCase:
    dossier = Dossier(
        core_problem=req["dossier"]["core_problem"],
        goal_state=req["dossier"].get("goal_state", []),
        current_state=req["dossier"].get("current_state", []),
        constraints=req["dossier"].get("constraints", []),
        scope=req["dossier"].get("scope", []),
    )
    disclosure = FoundationDisclosure(
        weakest_assumptions=[
            "the proposal's fixed_snippet resolves the flagged rule",
            "the flagged file state matches the violation snapshot",
            "the parity re-scan reflects the real policy definitions",
        ],
        invalidation_conditions=[
            "parity re-scan still flags the violation after the fix",
            "the file state no longer matches the violation snapshot",
        ],
        key_vulnerability="single-file parity: only the flagged rule is re-verified",
    )
    attack = FoundationAttack(
        attack_summary="; ".join(req["assessment"]["findings"]),
        foundation_score=req["assessment"]["score"],
        vulnerability_strike=(
            "without parity the fix rests only on structural guardrails, "
            "not on the policy definition"
        ),
        assumption_attacks=[
            "parity re-scan against the policy definition",
            "pre-write state match against the flagged file",
            "write bounded to exactly the flagged file",
        ],
    )
    case = DecisionCase(
        decision_id=req["decision_id"],
        title=req["title"],
        domain=req.get("domain") or "general",
        created_at=_utcnow(),
        owner=req.get("owner") or "cac-fixer-agent",
        high_stakes=True,
        dossier=dossier,
        foundation_score=req["assessment"]["score"],
    )
    report = CHPOrchestrator().run_initial_session(
        case=case, foundation_disclosure=disclosure, foundation_attack=attack
    )
    # Collapsed flow (as in the reference gate): the decision may only proceed
    # through the human lock, never self-certify.
    case.status = SessionStatus.PROVISIONAL_LOCK
    session = {
        "decision_id": case.decision_id,
        "status": case.status.value,
        "created_at": case.created_at,
        "root": req["root"],
        "r0": req["r0"],
        "assessment": req["assessment"],
        "parity": req["parity"],
        "proposals": req["proposals"],
        "confirmed_by": None,
        "case": {
            "decision_id": case.decision_id,
            "title": case.title,
            "domain": case.domain,
            "created_at": case.created_at,
            "owner": case.owner,
            "foundation_score": case.foundation_score,
            "r0_verdict": report.r0_verdict.value,
            "foundation_verdict": report.foundation_verdict.value,
            "locked_decisions": list(case.locked_decisions),
        },
    }
    return case, session, report


def cmd_open(req: dict[str, Any]) -> tuple[dict[str, Any], int]:
    case, session, report = _build_case(req)
    path = session_path(req["root"], case.decision_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(session, ensure_ascii=False, indent=2))
    out = {
        "decision_id": case.decision_id,
        "status": case.status.value,
        "r0_verdict": report.r0_verdict.value,
        "foundation_verdict": report.foundation_verdict.value,
        "foundation_score": case.foundation_score,
        "session_path": str(path),
    }
    return out, EXIT_OK


def _load_case(session: dict[str, Any]) -> DecisionCase:
    stored = session["case"]
    status = SessionStatus(session["status"])
    return DecisionCase(
        decision_id=stored["decision_id"],
        title=stored["title"],
        domain=stored["domain"],
        created_at=stored["created_at"],
        owner=stored["owner"],
        status=status,
        high_stakes=True,
        foundation_score=stored.get("foundation_score"),
        locked_decisions=list(stored.get("locked_decisions", [])),
    )


def cmd_confirm(req: dict[str, Any]) -> tuple[dict[str, Any], int]:
    session = _load_session(req)
    if session["status"] != SessionStatus.PROVISIONAL_LOCK.value:
        return {
            "error": "third-party validation requires PROVISIONAL_LOCK status",
            "status": session["status"],
        }, EXIT_ERROR
    case = _load_case(session)
    confirmed_by = req.get("confirmed_by") or ""
    if not confirmed_by.strip():
        return {"error": "confirmed_by is required to lock a decision"}, EXIT_ERROR
    status = apply_third_party_validation(
        case,
        ThirdPartyValidation(
            validator=confirmed_by,
            item=case.decision_id,
            challenge=req.get("challenge")
            or "Confirm the auto-fix resolves the flagged violation and is safe to land",
            result=ValidationResult.CONFIRM,
            rationale=req.get("rationale")
            or f"Named confirmer approved the fix via {Path(sys.argv[0]).name}",
        ),
    )
    session["status"] = status.value
    session["confirmed_by"] = confirmed_by
    session["case"]["locked_decisions"] = list(case.locked_decisions)
    _save_session(req, session)
    return {"decision_id": case.decision_id, "status": status.value,
            "proposals": session["proposals"]}, EXIT_OK


def cmd_reject(req: dict[str, Any]) -> tuple[dict[str, Any], int]:
    session = _load_session(req)
    if session["status"] != SessionStatus.PROVISIONAL_LOCK.value:
        return {
            "error": "third-party validation requires PROVISIONAL_LOCK status",
            "status": session["status"],
        }, EXIT_ERROR
    case = _load_case(session)
    status = apply_third_party_validation(
        case,
        ThirdPartyValidation(
            validator=req.get("confirmed_by") or "unknown",
            item=case.decision_id,
            challenge="Human review of the pending auto-fix",
            result=ValidationResult.REJECT,
            rationale=req.get("rationale") or "Fix rejected by human reviewer",
        ),
    )
    session["status"] = status.value
    session["confirmed_by"] = req.get("confirmed_by")
    _save_session(req, session)
    return {"decision_id": case.decision_id, "status": status.value}, EXIT_OK


def _load_session(req: dict[str, Any]) -> dict[str, Any]:
    path = session_path(req["root"], req["decision_id"])
    if not path.exists():
        raise Refusal(f"unknown decision session {req['decision_id']}", {})
    return json.loads(path.read_text())


def _save_session(req: dict[str, Any], session: dict[str, Any]) -> None:
    path = session_path(req["root"], req["decision_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(session, ensure_ascii=False, indent=2))


# ------------------------------------------------------------------ ledger
def cmd_record(req: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Seal a decision (applied or refused) into the append-only ledger."""
    body = json.dumps(
        {
            "decision_id": req.get("decision_id"),
            "title": req.get("title"),
            "domain": req.get("domain") or "general",
            "outcome": req["outcome"],
            "rule_id": req.get("rule_id"),
            "policy_id": req.get("policy_id"),
            "file_path": req.get("file_path"),
            "violation_line": req.get("violation_line"),
            "fix_description": req.get("fix_description"),
            "session_status": req.get("session_status"),
            "r0_verdict": req.get("r0_verdict"),
            "r0_results": req.get("r0_results"),
            "foundation_verdict": req.get("foundation_verdict"),
            "foundation_score": req.get("foundation_score"),
            "parity": req.get("parity"),
            "refusal_reason": req.get("refusal_reason"),
            "landed_via": req.get("landed_via"),
            "locked_decisions": req.get("locked_decisions", []),
            "artifacts": req.get("artifacts", {}),
            "recorded_at": _utcnow(),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    envelope = build_payload_envelope(body, route=ENVELOPE_ROUTE)
    entry = {
        "decision_id": req.get("decision_id"),
        "created_at": req.get("created_at") or _utcnow(),
        "title": req.get("title"),
        "domain": req.get("domain") or "general",
        "outcome": req["outcome"],
        "rule_id": req.get("rule_id"),
        "policy_id": req.get("policy_id"),
        "file_path": req.get("file_path"),
        "session_status": req.get("session_status"),
        "r0_verdict": req.get("r0_verdict"),
        "foundation_verdict": req.get("foundation_verdict"),
        "foundation_score": req.get("foundation_score"),
        "confirmed_by": req.get("confirmed_by"),
        "landed_via": req.get("landed_via"),
        "artifacts": req.get("artifacts", {}),
        "body": body,
        "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "envelope": envelope.render(),
    }
    path = ledger_path(req["root"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return {"decision_id": entry["decision_id"], "body_sha256": entry["body_sha256"],
            "ledger": str(path)}, EXIT_OK


def cmd_read(req: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Newest-first records, envelope and body integrity re-validated on read."""
    path = ledger_path(req["root"])
    if not path.exists():
        return {"records": [], "all_integrity_valid": True}, EXIT_OK
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            digest = hashlib.sha256(entry.get("body", "").encode("utf-8")).hexdigest()
            records.append({
                **entry,
                "envelope_valid": validate_payload_envelope(entry.get("envelope", "")),
                "integrity_valid": digest == entry.get("body_sha256"),
            })
    limit = int(req.get("limit") or len(records))
    records = list(reversed(records))[:limit]
    return {
        "records": records,
        "all_integrity_valid": all(r["integrity_valid"] and r["envelope_valid"]
                                   for r in records),
    }, EXIT_OK


COMMANDS = {
    "r0": cmd_r0,
    "assess": cmd_assess,
    "open": cmd_open,
    "confirm": cmd_confirm,
    "reject": cmd_reject,
    "record": cmd_record,
    "read": cmd_read,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(json.dumps({"error": f"usage: {Path(sys.argv[0]).name} "
                                  f"{'|'.join(sorted(COMMANDS))} < JSON"}))
        return EXIT_ERROR
    req = json.loads(sys.stdin.read() or "{}")
    try:
        out, code = COMMANDS[sys.argv[1]](req)
    except Refusal as exc:
        print(json.dumps({"error": exc.reason, **exc.payload}))
        return EXIT_REFUSED
    except ValueError as exc:
        print(json.dumps({"error": "protocol_error", "detail": str(exc)}))
        return EXIT_ERROR
    print(json.dumps(out, ensure_ascii=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
