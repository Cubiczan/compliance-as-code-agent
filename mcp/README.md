# `@cubiczan/compliance-as-code-mcp`

Stdio MCP pipe for **Cubiczan** Compliance-as-Code. Cursor, Claude Code, or any MCP client can call the real `cac` Detector / Fixer / Validator pipeline and the signed `.cac/audit.jsonl` ledger — no custom webhook, no LLM for detection.

CHP is the lock; MCP is the pipe. Same shape as [`@cubiczan/chp-mcp`](https://www.npmjs.com/package/@cubiczan/chp-mcp) and [`@cubiczan/codesentinel-mcp`](https://www.npmjs.com/package/@cubiczan/codesentinel-mcp).

## How the pieces fit

```text
MCP client (Cursor / Claude / …)
        │  tools/call
        ▼
┌───────────────────────────────┐
│  MCP server (transport)       │  ← you are here
│  scan / fix / validate / run  │     @cubiczan/compliance-as-code-mcp
│  audit                        │
└───────────────┬───────────────┘
                │ spawns `cac --format json`
                ▼
┌───────────────────────────────┐
│  cac-cli (Rust engine)        │
│  cac-scanner / fixer /        │
│  validator / signed ledger    │
└───────────────────────────────┘
```

## Prerequisites

The MCP server invokes the real `cac` binary. It does **not** reimplement YAML policy packs.

```bash
cargo build --release -p cac-cli
export CAC_BIN="$(pwd)/target/release/cac"   # or put cac on PATH
```

## Install

```bash
# from this repo (until the package is published)
npm install --prefix mcp
npm run build --prefix mcp

# later, after npm publish:
# npm install -g @cubiczan/compliance-as-code-mcp
# npx -y @cubiczan/compliance-as-code-mcp
```

Start stdio MCP (foreground; Cursor / Claude spawn this for you):

```bash
node mcp/dist/index.js
# or: npx -y @cubiczan/compliance-as-code-mcp
```

### Cursor / Claude Desktop

Add to `mcp.json` (Cursor: `.cursor/mcp.json` or global MCP settings):

```json
{
  "mcpServers": {
    "compliance-as-code": {
      "command": "npx",
      "args": ["-y", "@cubiczan/compliance-as-code-mcp"],
      "env": {
        "CAC_BIN": "/absolute/path/to/cac"
      }
    }
  }
}
```

From a clone of this repo, before publish:

```json
{
  "mcpServers": {
    "compliance-as-code": {
      "command": "node",
      "args": ["/absolute/path/to/compliance-as-code-agent/mcp/dist/index.js"],
      "env": {
        "CAC_BIN": "/absolute/path/to/compliance-as-code-agent/target/release/cac"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add compliance-as-code -- npx -y @cubiczan/compliance-as-code-mcp
```

From source:

```bash
claude mcp add compliance-as-code -- node /absolute/path/to/compliance-as-code-agent/mcp/dist/index.js
```

Set `CAC_BIN` in the host environment (or in the MCP `env` block) so the pipe can find the engine.

## Tools

| Tool | Maps to | Purpose |
|------|---------|---------|
| `scan` | `cac scan --format json` | Detector — YAML policy hits, signed ledger event |
| `fix` | `cac fix --format json` | Fixer — propose / apply rule-based auto-fixes |
| `validate` | `cac validate --format json` | Validator — re-scan + CHP-style adversarial notes |
| `run` | `cac run --format json` | Full detect → fix → validate pipeline |
| `audit` | `cac audit --format json` | Read signed `.cac/audit.jsonl` |
| `cac_version` | — | MCP package + resolved `cac` path |

Shared arguments: `root`, `policies`, `signing_key`. `fix` / `run` accept `dry_run`. `validate` accepts `fixes_applied`.

### Example — scan the bundled violations fixture

```jsonc
// tools/call scan
{
  "root": "examples/violations",
  "policies": "policies"
}
```

Returns real findings (`secret-api-key`, GDPR annotations, SOC2 `audit_log` gaps). Detection is offline.

## Tests

```bash
cargo build -p cac-cli
npm test --prefix mcp
```

Exercises `tools/list` and `scan` against `examples/violations`.

## Publish later

Package metadata is ready (`publishConfig.access: public`). **Do not `npm publish` from this change** — no tokens in CI.

## Licence

MIT. Cubiczan.
