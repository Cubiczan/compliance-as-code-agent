## 1. npm MCP package

- [x] 1.1 Add `mcp/` package `@cubiczan/compliance-as-code-mcp` with TypeScript, `@modelcontextprotocol/sdk`, bin, `server.json`, and publishConfig (do not publish)
- [x] 1.2 Resolve `cac` via `CAC_BIN` / PATH / local cargo target and invoke `--format json`
- [x] 1.3 Register tools `scan`, `fix`, `validate`, `run`, `audit` (and `cac_version`); map args to CLI flags
- [x] 1.4 Treat CLI exit 1 + valid JSON as a successful findings payload

## 2. Tests

- [x] 2.1 `tools/list` test asserting the five pipeline tools
- [x] 2.2 `scan` against `examples/violations` + `policies/` asserting real `rule_id` hits

## 3. Docs and CI

- [x] 3.1 README: Cubiczan Cursor `mcp.json` snippet and `claude mcp add` one-liner
- [x] 3.2 CI job: `cargo build -p cac-cli` then `mcp` tests
