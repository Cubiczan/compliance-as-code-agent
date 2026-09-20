"""Row 15 differential harness: Python bridge R0 verdicts vs the native chp-gate binary.

The Python subprocess bridge (`bridge/chp_gate.py`, backed by
consensus-hardening-protocol==0.1.1) and the canonical native substrate
(`chp-core-rs` `chp-gate` JSON-over-stdio binary, methods evaluate_r0_gate et
al.) independently implement the CHP R0 gate. This harness runs the full
four-boolean corpus (`bridge/differential/r0_fixtures.json`) through both and
fails loudly on divergence, appending any accepted divergence to
`bridge/differential/divergences.jsonl` for the decision record.

Binary resolution order (documented fallback, mirroring swarmfi's adoption of
the native core): `CHP_GATE_BIN`, then `chp-gate` on PATH, then the
repo-adjacent dev build `../chp-core-rs/target/{release,debug}/chp-gate`. When
no binary resolves, the native differential is skipped with an explicit
reason — the corpus truth table still runs against the Python bridge.

When the two implementations diverge, `chp-core-rs` v0.1.0 semantics are
authoritative: the native substrate is the canonical implementation, and a
divergence is a defect in the ported copy (the Python bridge) to be fixed
there, not a local preference. Divergences found before that fix are
appended to `bridge/differential/divergences.jsonl` for the decision record.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from test_chp_gate import run_gate

DIFF_DIR = Path(__file__).resolve().parent.parent / "differential"
FIXTURES = json.loads((DIFF_DIR / "r0_fixtures.json").read_text())["fixtures"]
LEDGER = DIFF_DIR / "divergences.jsonl"


def resolve_native_binary() -> str | None:
    candidates = [
        os.environ.get("CHP_GATE_BIN") or None,
        shutil.which("chp-gate"),
    ]
    crate_root = DIFF_DIR.parents[1].parent / "chp-core-rs"
    for profile in ("release", "debug"):
        dev_bin = crate_root / "target" / profile / "chp-gate"
        if dev_bin.is_file():
            candidates.append(str(dev_bin))
    return next((c for c in candidates if c), None)


def native_r0(binary: str, fixture: dict) -> dict:
    request = json.dumps({
        "method": "evaluate_r0_gate",
        "params": {k: fixture[k] for k in ("solvable", "scoped", "valid", "worth_it")},
    })
    proc = subprocess.run(
        [binary], input=request + "\n", capture_output=True, text=True, check=True
    )
    response = json.loads(proc.stdout.strip().splitlines()[-1])
    assert "error" not in response, response
    return response


def _record_divergence(fixture: dict, python_out: dict, native_out: dict) -> None:
    entry = {
        "recorded_at": dt.datetime.now(dt.UTC).isoformat(),
        "fixture": fixture["id"],
        "inputs": {k: fixture[k] for k in ("solvable", "scoped", "valid", "worth_it")},
        "python": {"verdict": python_out.get("verdict"), "results": python_out.get("results")},
        "native": {"verdict": native_out.get("verdict"), "results": native_out.get("results")},
        "disposition": "UNEXPECTED — harness failed; resolve before shipping either side",
    }
    with LEDGER.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def test_fixture_corpus_truth_table() -> None:
    """The Python bridge must follow the reference R0 semantics: all-PASS -> PASS."""
    for fixture in FIXTURES:
        code, out = run_gate(Path("."), "r0", {
            k: fixture[k] for k in ("solvable", "scoped", "valid", "worth_it")
        })
        all_pass = all(fixture[k] for k in ("solvable", "scoped", "valid", "worth_it"))
        expected = "PASS" if all_pass else "HALT"
        assert out.get("verdict") == expected, (fixture["id"], out)
        assert (code == 0) is all_pass, (fixture["id"], code)


def test_python_and_native_r0_agree() -> None:
    binary = resolve_native_binary()
    if binary is None:
        pytest.skip("chp-gate binary unavailable; native differential not run (fallback documented)")
    diverged = []
    for fixture in FIXTURES:
        _, py_out = run_gate(Path("."), "r0", {
            k: fixture[k] for k in ("solvable", "scoped", "valid", "worth_it")
        })
        native = native_r0(binary, fixture)
        if py_out.get("verdict") != native.get("verdict"):
            diverged.append((fixture, py_out, native))
            _record_divergence(fixture, py_out, native)
    assert not diverged, f"R0 verdict divergence on {len(diverged)} fixture(s): {diverged}"
