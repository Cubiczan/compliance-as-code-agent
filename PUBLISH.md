# Publish to crates.io — compliance-as-code-agent

CLI binary crate: **`cac-cli`** → installs binary **`cac`**.  
Core library: **`cac-core`**.

## Name availability (checked 2026-08-21)

All free on crates.io: `cac-cli`, `cac-core`, `cac-scanner`, `cac-fixer`, `cac-validator`, `cac-webhook`, `compliance-as-code`, `cubiczan-cac`.

**Chosen names:** keep `cac-*` crate names (already wired). Discoverability alias later: publish a thin `compliance-as-code` binary crate that re-exports / depends on `cac-cli` if desired.

## Publish order (core first)

Git deps are **not** allowed on crates.io. `cac-webhook` previously depended on `resilient-call` via git; that is now an in-crate `retry` module.

```bash
cd ~/Desktop/icohangar-repos/compliance-as-code-agent

# OTP / token once
cargo login   # paste crates.io API token

# 1) leaf library
cargo publish -p cac-core

# 2) direct dependents of core
cargo publish -p cac-scanner
cargo publish -p cac-fixer

# 3) depends on scanner
cargo publish -p cac-validator

# 4) webhook (depends on core/scanner/fixer/validator)
cargo publish -p cac-webhook

# 5) CLI binary last
cargo publish -p cac-cli

# verify
cargo search cac-cli
cargo install cac-cli --locked
cac --help
```

If a step fails because crates.io index lag, wait ~1–2 minutes and retry.

## Local verify before publish

```bash
cargo test
cargo build --release -p cac-cli
./target/release/cac scan --root examples/violations
```

## MCP wrapper (shipped from source)

The thin stdio MCP server is **built and ships from source**: `bridge/mcp_server.py` exposes `scan_repository` and `decision_register` as read-only tools that shell out to the compiled `cac` binary — no scanning or gate logic is duplicated, resolution fails closed when no binary exists, and the CHP-gated auto-fix write path is deliberately not exposed. Run it from a repo checkout with `uv run --with 'mcp<2' python bridge/mcp_server.py`.

The crates.io publish sequence is **complete** (verified 2026-09-20: `cac-core`, `cac-scanner`, `cac-fixer`, `cac-validator`, `cac-webhook`, `cac-cli`, all at 0.1.0 with this repository's URL), so `cargo install cac-cli --locked` now provides the `cac` binary the MCP wrapper delegates to. The wrapper itself is Python and currently ships from source, not inside the crate package; packaging it with the crate is deferred until the crates.io install path needs it.

## Blockers / notes

- Workspace `authors` / `repository` updated for GitHub `icohangar-ops/compliance-as-code-agent`.
- Ensure GitHub remote matches `repository` URL before publish (crates.io links it).
- Do **not** `cargo publish` until you run the OTP/`cargo login` step yourself.
