## Context

`cac-cli` already orchestrates Detector (`cac-scanner`), Fixer (`cac-fixer`), Validator (`cac-validator`), and the HMAC-signed JSONL ledger in `cac-core`. `cac serve` is an HTTP webhook — the wrong transport for Cursor / Claude Code. Sibling packages `@cubiczan/chp-mcp` and `@cubiczan/codesentinel-mcp` are TypeScript stdio servers using `@modelcontextprotocol/sdk`.

This repo’s engine is Rust. MCP is only the pipe.

## Goals / Non-Goals

**Goals:**
- Stdio MCP tools that return real engine JSON for scan / fix / validate / run / audit.
- npm package `@cubiczan/compliance-as-code-mcp` ready to publish later (no publish in this change).
- Resolve the `cac` binary via `CAC_BIN`, `PATH`, or a local `target/{debug,release}/cac`.
- Treat CLI exit `1` with valid JSON (critical findings) as a successful tool result.
- Cursor + Claude Code install docs, brand Cubiczan.

**Non-Goals:**
- Reimplementing YAML policy packs or regex rules in TypeScript.
- LLM-assisted detection or `explain_finding`-style generation.
- Shipping a webhook alternative or changing `cac serve`.
- `npm publish` or crates.io publish.
- Rebuilding the CHP / policy engine.

## Decisions

1. **TypeScript MCP + spawn `cac --format json`**
   - Matches `@cubiczan/chp-mcp` (stdio, `npx`, `claude mcp add`).
   - Guarantees one policy implementation (the Rust crates).
   - Alternative rejected: port the scanner to JS. Alternative accepted as fallback later: a native `cac mcp` subcommand can exec the same handlers; not required for v0 if the npm server can find a built `cac`.

2. **Binary resolution order**
   - `CAC_BIN` → `cac` on `PATH` → walk from cwd / package root for `target/release/cac` then `target/debug/cac`.
   - Clear error if missing: tell the operator to `cargo build -p cac-cli`.

3. **Tool names**
   - `scan`, `fix`, `validate`, `run`, `audit` (plus `cac_version` for diagnostics).
   - Shared args: `root`, `policies`, `signing_key`; `dry_run` on fix/run; `fixes_applied` on validate.

4. **Packaging**
   - Package lives in `mcp/` with its own `package.json`, `tsconfig.json`, `server.json`.
   - `bin` name `compliance-as-code-mcp` (and `cac-mcp` alias if easy).
   - Cargo workspace unchanged except docs; the engine crate remains `cac-cli`.

5. **Tests**
   - Build `cac`, start the MCP server over stdio, `tools/list`, then `scan` on `examples/violations` with repo `policies/`.
   - Assert violation count > 0 and at least one known `rule_id` (e.g. `secret-api-key`).

## Risks / Trade-offs

- **`npx` without a built `cac`**: documented; tests and CI always build the CLI first.
- **CLI exit codes**: scan/validate/run exit 1 on fail — wrapper must not surface that as MCP `isError` when JSON parsed.
- **Two languages in one repo**: isolated under `mcp/`; Rust crates stay the source of truth.
