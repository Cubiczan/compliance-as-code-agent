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

## Optional MCP wrapper (later)

A thin stdio MCP over `cac scan` / `cac run` (similar to `@cubiczan/chp-mcp`) is **not** built yet. Sketch: Node or Rust MCP server exposing `cac_scan`, `cac_validate`, `cac_audit` tools that shell out to the `cac` binary. Track in README; ship after crates.io is live.

## Blockers / notes

- Workspace `authors` / `repository` updated for GitHub `icohangar-ops/compliance-as-code-agent`.
- Ensure GitHub remote matches `repository` URL before publish (crates.io links it).
- Do **not** `cargo publish` until you run the OTP/`cargo login` step yourself.
