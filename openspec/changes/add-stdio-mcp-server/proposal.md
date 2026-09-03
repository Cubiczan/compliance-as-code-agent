## Why

Cursor and Claude Code can only reach this agent through a custom PR webhook (`cac serve`) or by running the CLI by hand. Sibling Cubiczan products already expose their engines as stdio MCP tools (`@cubiczan/chp-mcp`, `@cubiczan/codesentinel-mcp`). Compliance-as-Code needs the same pipe so an IDE agent can scan, fix, validate, and read the signed `.cac/audit.jsonl` ledger without standing up HTTP.

Detection already runs offline against YAML policy packs. The MCP layer must not add an LLM to that path and must not reimplement the Rust policy engine.

## What Changes

- Add a stdio MCP server that wraps the real Detector / Fixer / Validator pipeline and the signed audit ledger.
- Expose callable tools for `scan`, `fix`, `validate`, `run`, and `audit`.
- Package as `@cubiczan/compliance-as-code-mcp` (npm, unpublished) and keep the Rust `cac` binary as the engine.
- Document Cursor `mcp.json` and `claude mcp add` install, spelled Cubiczan.
- Add tests: `tools/list` plus `scan` against `examples/violations` returning real policy hits.

## Capabilities

### New Capabilities
- `stdio-mcp`: stdio Model Context Protocol server that invokes `cac` (scan, fix, validate, run, audit) and returns engine JSON to MCP clients.

### Modified Capabilities
- (none — brownfield; no existing OpenSpec capability specs)

## Impact

- New `mcp/` npm package (TypeScript, `@modelcontextprotocol/sdk`) that spawns `cac --format json`.
- Optional `cac mcp` convenience path documented for a locally built binary.
- Root README install section; CI job to build `cac` and run MCP tests.
- No change to YAML policy packs, scanner/fixer/validator crates, or webhook server.
