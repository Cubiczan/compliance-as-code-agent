#!/usr/bin/env python3
"""MCP server for the compliance-as-code-agent scanner.

Exposes the deterministic Rust core (`cac` CLI: scan, decisions) as Model
Context Protocol tools. Thin wrapper — no scanning or gate logic lives here;
every call shells out to the compiled `cac` binary and fails closed when it
cannot resolve. The auto-fix WRITE path stays inside the CHP gate and is
deliberately NOT exposed over MCP: gate-refused fixes are a human-lock
surface, not an agent tool.

Follows the same publishing path proven by invoice-audit-engine /
codesentinel: stdio transport, `io.github.*` namespace convention.

Run it (repo root, after `cargo build`):

    uv run --with 'mcp<2' python bridge/mcp_server.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "compliance-as-code-agent",
    instructions=(
        "Deterministic policy scanning for codebases. Supply a root; the "
        "tools run the Rust `cac` scanner (YAML policy packs: hardcoded "
        "secrets, GDPR tagging, SOC2 audit trails) and read the CHP decision "
        "register with revalidated integrity. Scanning is read-only; auto-fix "
        "writes are CHP-gated and not exposed here."
    ),
)


def resolve_cli() -> str:
    """Resolve the compiled `cac` binary: CAC_CLI_BIN, repo target dirs, PATH."""
    candidates = [os.environ.get("CAC_CLI_BIN") or None]
    repo_root = Path(__file__).resolve().parents[1]
    candidates.extend(str(repo_root / "target" / profile / "cac") for profile in ("release", "debug"))
    candidates.append(shutil.which("cac"))
    # Filesystem paths are only candidates when they actually exist — a
    # stale profile build (e.g. release not built) must fall through to the
    # next candidate instead of failing at spawn time.
    binary = next((c for c in candidates if c and Path(c).is_file()), None)
    if binary is None:
        raise RuntimeError(
            "cac binary not found — set CAC_CLI_BIN or run `cargo build -p cac-cli`"
        )
    return binary


def run_cli(args: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        [resolve_cli(), *args], capture_output=True, text=True, check=False
    )
    # `cac scan` exits 1 when it finds critical violations — after printing
    # the JSON report. Parse stdout whenever it carries a report; a nonzero
    # exit with no parseable output is the real failure.
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        if proc.returncode != 0:
            raise RuntimeError(
                f"cac {' '.join(args)} failed (exit {proc.returncode}): {proc.stderr.strip()}"
            ) from None
        raise


@mcp.tool()
def scan_repository(root: str, policies: str = "") -> dict[str, Any]:
    """Scan a repository against the YAML policy packs (read-only, deterministic).

    Returns files scanned and every violation with rule id, policy, severity,
    location, snippet, and whether an auto-fix exists.

    Args:
        root: Filesystem path to scan.
        policies: Optional policy-pack directory. Defaults to the repo's
            policies when omitted.
    """
    args = ["scan", "--root", root, "--format", "json"]
    if policies:
        args.extend(["--policies", policies])
    return run_cli(args)


@mcp.tool()
def decision_register(root: str = ".") -> dict[str, Any]:
    """Read the CHP decision register (append-only ledger, integrity revalidated on read).

    Returns the recorded apply/refuse decisions with per-record
    integrity_valid and the aggregate all_integrity_valid flag. Requires the
    Python CHP bridge to be importable — the read path fail-closes otherwise.

    Args:
        root: Scan root whose `.cac/` state directory holds the ledger.
    """
    return run_cli(["--root", root, "decisions", "--format", "json"])


def main() -> None:
    """Console entry point: run the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
