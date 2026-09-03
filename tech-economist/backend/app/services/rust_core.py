from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parents[4]
_RUST_DIR = _ROOT / "crates" / "te-core"
_BINARY = _ROOT / "target" / "release" / "te-core"


def _run(command: list[str], payload: Any) -> Any | None:
    proc = subprocess.run(
        command,
        input=json.dumps(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        return None
    output = proc.stdout.decode("utf-8").strip()
    return json.loads(output) if output else None


def run_rust_core(command: str, payload: Any) -> Any | None:
    if _BINARY.exists():
        result = _run([str(_BINARY), command], payload)
        if result is not None:
            return result

    if shutil.which("cargo"):
        return _run(
            ["cargo", "run", "--quiet", "--manifest-path", str(_RUST_DIR / "Cargo.toml"), "--", command],
            payload,
        )

    return None
