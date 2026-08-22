# Compliance-as-Code Agent

> **Cubiczan stack** — [Profile](https://github.com/Cubiczan) · [CHP](https://github.com/Cubiczan/consensus-hardening-protocol) · **You are here:** `compliance-as-code-agent`

Rust agent that scans codebases against organizational compliance policies and auto-fixes violations.

Built by [Cubiczan](https://github.com/Cubiczan) — composes patterns from [Consensus Hardening Protocol](https://github.com/Cubiczan/consensus-hardening-protocol) and [autonomous-business-os](https://github.com/Cubiczan/autonomous-business-os).

## What it does

| Agent | Role |
|-------|------|
| **Detector** | Walks the repo and evaluates YAML policy packs |
| **Fixer** | Proposes and applies rule-based auto-fixes |
| **Validator** | Re-scans + CHP-style adversarial review |

Every check and fix is logged to a signed append-only audit ledger (`.cac/audit.jsonl`).

## Policy packs (included)

- **no-hardcoded-secrets** — API keys, passwords, tokens, `.env` commits (SOC2)
- **gdpr-data-tagging** — `@gdpr` annotations on PII fields
- **soc2-audit-trails** — `audit_log` calls on auth, delete, and payment handlers

## Quick start

```bash
cargo build --release
cargo run -p cac-cli -- scan --root examples/violations
cargo run -p cac-cli -- run --root examples/violations --dry-run
```

After crates.io publish:

```bash
cargo install cac-cli
cac scan --root .
```

See [PUBLISH.md](PUBLISH.md) for crates.io publish order (`cac-core` → … → `cac-cli`).

## MCP (optional, later)

A thin MCP stdio wrapper around `cac scan` / `cac run` / `cac audit` is planned (same pattern as `@cubiczan/chp-mcp`) but not shipped yet. Use the CLI binary directly until then.
## CLI

```bash
cac scan              # Detector agent
cac fix [--dry-run]   # Fixer agent
cac validate          # Validator agent
cac run [--dry-run]   # Full detect → fix → validate pipeline
cac audit             # Show signed audit trail
cac serve             # PR webhook server (GitHub + Codeberg)
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--root` | `.` | Repository root to scan |
| `--policies` | `policies` | Policy YAML directory |
| `--format` | `text` | `text` or `json` |
| `--signing-key` | env `CAC_LEDGER_SIGNING_KEY` | HMAC key for audit signatures |

## Architecture

```
policies/*.yaml
      │
      ▼
┌─────────────┐    ┌─────────────┐    ┌────────────────┐
│ cac-scanner │───▶│  cac-fixer  │───▶│ cac-validator  │
│  (detect)   │    │   (fix)     │    │  (validate)    │
└──────┬──────┘    └──────┬──────┘    └───────┬────────┘
       │                  │                    │
       └──────────────────┴────────────────────┘
                          │
                    cac-core (policy + audit ledger)
                          │
                    .cac/audit.jsonl
```

## PR webhook integration

Run the webhook server to scan pull requests automatically:

```bash
cp .env.example .env   # set CAC_WEBHOOK_SECRET, tokens
cac serve --policies policies
```

On each `pull_request` event (opened, synchronized, reopened):

1. **Detector** clones the PR head and scans against policies
2. Posts **commit status** (`compliance-as-code/scan`) — pass or fail
3. Posts a **PR comment** with violation details
4. Optionally opens an **auto-fix PR** when `CAC_AUTO_FIX_PR=true`

See [docs/WEBHOOK_SETUP.md](docs/WEBHOOK_SETUP.md) for GitHub and Codeberg webhook configuration.

## CI integration

```yaml
- run: cargo build --release -p cac-cli
- run: ./target/release/cac scan --format json
  env:
    CAC_LEDGER_SIGNING_KEY: ${{ secrets.CAC_LEDGER_SIGNING_KEY }}
```

Exit code `1` when critical violations remain after validation.

## Air-gap / regulated deployments

- Static policy engine runs fully offline — no LLM required for detection
- Single binary (`cac`) suitable for on-prem CI and air-gapped environments
- Signed audit ledger provides SOC2 evidence chain

---

## Cubiczan stack

| Governance | [consensus-hardening-protocol](https://github.com/Cubiczan/consensus-hardening-protocol) · [agent-conductor](https://github.com/Cubiczan/agent-conductor) · **compliance-as-code-agent** · [cleanmandate](https://github.com/Cubiczan/cleanmandate) |
| Finance | [Strata](https://github.com/Cubiczan/Strata) · [meshcfo](https://github.com/Cubiczan/meshcfo) · [Metabocommand](https://github.com/Cubiczan/Metabocommand) |

YAML policy packs here gate [cleanmandate](https://github.com/Cubiczan/cleanmandate) spend rules and PR webhooks for [software-factory](https://github.com/Cubiczan/software-factory) output.

## License

MIT — see [LICENSE](LICENSE).
