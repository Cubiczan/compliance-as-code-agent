## Purpose

Give Cursor, Claude Code, and other MCP clients a stdio pipe to the existing Compliance-as-Code Detector, Fixer, Validator, and signed audit ledger without reimplementing policy or requiring an LLM.

## ADDED Requirements

### Requirement: Stdio MCP server starts from a documented command
The project SHALL provide a documented command that starts a stdio MCP server for Cubiczan Compliance-as-Code. The server SHALL speak JSON-RPC MCP over stdin/stdout and SHALL NOT require a webhook, HTTP bind address, or LLM for detection.

#### Scenario: Documented start command
- **WHEN** an operator runs the documented start command (`npx` package bin, `node mcp/dist/index.js`, or `cac mcp` after a local build)
- **THEN** the process accepts MCP `initialize` and remains on stdio until the client disconnects

### Requirement: Tools wrap the real cac pipeline
The server SHALL expose tools named `scan`, `fix`, `validate`, `run`, and `audit` that invoke the real `cac` CLI or the same Rust library crates. Tools SHALL NOT reimplement YAML policy packs or the Detector / Fixer / Validator logic in TypeScript.

#### Scenario: tools/list advertises pipeline tools
- **WHEN** a client sends MCP `tools/list`
- **THEN** the response includes tools `scan`, `fix`, `validate`, `run`, and `audit`

#### Scenario: scan returns real policy findings
- **WHEN** a client calls `scan` with `root` set to `examples/violations` and `policies` set to the repo `policies/` directory
- **THEN** the tool result is JSON from the engine and contains at least one violation with a real `rule_id` from the shipped policy packs

#### Scenario: critical CLI exit is not a transport failure
- **WHEN** `cac scan` exits `1` because critical violations were found and stdout is valid JSON
- **THEN** the MCP tool result is a successful content payload with those findings, not an MCP error

### Requirement: Offline detection
Detection SHALL run entirely in the existing offline policy engine. The MCP server SHALL NOT call an LLM to decide whether a file violates a policy.

#### Scenario: scan without network or model
- **WHEN** `scan` is invoked with no LLM API keys set
- **THEN** findings are still produced from YAML policy evaluation

### Requirement: Shared tool arguments
`scan`, `fix`, `validate`, `run`, and `audit` SHALL accept optional `root`, `policies` (where applicable), and `signing_key` arguments that map to the existing `cac` flags / `CAC_LEDGER_SIGNING_KEY`. `fix` and `run` SHALL accept `dry_run`. `validate` SHALL accept `fixes_applied`.

#### Scenario: dry-run fix does not require a webhook
- **WHEN** a client calls `fix` with `dry_run` true
- **THEN** the engine is invoked with `--dry-run --format json` and no webhook server is started

### Requirement: Cursor and Claude Code install
The README SHALL show Cubiczan-branded install for Cursor (`mcp.json` snippet) and Claude Code (`claude mcp add` one-liner) using package `@cubiczan/compliance-as-code-mcp`. The brand SHALL be spelled Cubiczan.

#### Scenario: README documents both clients
- **WHEN** a reader opens the project README
- **THEN** they can copy a Cursor `mcpServers` snippet and a `claude mcp add` command that start this stdio server
