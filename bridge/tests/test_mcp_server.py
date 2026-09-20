"""The MCP server registers the deterministic `cac` core as callable tools.

Pins tool registration and a real scan of `examples/violations` through the
MCP path. Skipped cleanly when the optional ``mcp`` package is not installed;
the scan test additionally skips with an explicit reason when no compiled
`cac` binary resolves.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server import mcp, resolve_cli, scan_repository  # noqa: E402


def _tool_names() -> set[str]:
    tools = asyncio.run(mcp.list_tools())
    return {t.name for t in tools}


def test_expected_tools_registered() -> None:
    assert _tool_names() >= {"scan_repository", "decision_register"}


def test_scan_via_mcp_path_finds_gdpr_violations() -> None:
    try:
        resolve_cli()
    except RuntimeError as exc:
        pytest.skip(f"cac binary unavailable: {exc}")
    report = scan_repository(
        str(Path(__file__).resolve().parents[2] / "examples" / "violations")
    )
    rule_ids = {v["rule_id"] for v in report["violations"]}
    assert "gdpr-email-field" in rule_ids
    assert report["files_scanned"] >= 1
