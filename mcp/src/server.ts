/**
 * Cubiczan Compliance-as-Code MCP server — thin transport over the cac CLI.
 *
 * CHP is the lock; MCP is the pipe. Detection stays in the offline Rust
 * policy engine. This process does not call an LLM to decide violations.
 */

import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { commonFlags, parseEngineJson, resolveCacBin, runCac } from "./cac.js";

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json") as { version: string };

function jsonContent(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function errorContent(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
    isError: true,
  };
}

const rootArg = z
  .string()
  .optional()
  .describe("Repository root to scan (cac --root). Default: current working directory.");
const policiesArg = z
  .string()
  .optional()
  .describe("Directory of YAML policy packs (cac --policies). Default: policies.");
const signingKeyArg = z
  .string()
  .optional()
  .describe("HMAC key for .cac/audit.jsonl (or set CAC_LEDGER_SIGNING_KEY).");

export function createServer(): McpServer {
  const server = new McpServer({
    name: "compliance-as-code-mcp",
    version: PKG_VERSION,
  });

  server.tool(
    "scan",
    "Detector agent: walk the repo and evaluate Cubiczan YAML policy packs " +
      "(secrets, GDPR tagging, SOC2 audit trails). Offline — no LLM. " +
      "Returns the cac scan JSON report and records a signed ledger event.",
    {
      root: rootArg,
      policies: policiesArg,
      signing_key: signingKeyArg,
    },
    async ({ root, policies, signing_key }) => {
      try {
        const invocation = await runCac(["scan", ...commonFlags({ root, policies, signing_key })]);
        return jsonContent(parseEngineJson(invocation));
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "fix",
    "Fixer agent: propose (and optionally apply) rule-based auto-fixes for " +
      "scan findings. Invokes the real cac fixer — does not regenerate policy.",
    {
      root: rootArg,
      policies: policiesArg,
      signing_key: signingKeyArg,
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview fixes without writing files (cac --dry-run). Default false."),
    },
    async ({ root, policies, signing_key, dry_run }) => {
      try {
        const extra = dry_run ? ["--dry-run"] : [];
        const invocation = await runCac([
          "fix",
          ...extra,
          ...commonFlags({ root, policies, signing_key }),
        ]);
        return jsonContent(parseEngineJson(invocation));
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "validate",
    "Validator agent: re-scan after fixes and run CHP-style adversarial review. " +
      "Returns the cac validate JSON report.",
    {
      root: rootArg,
      policies: policiesArg,
      signing_key: signingKeyArg,
      fixes_applied: z
        .number()
        .int()
        .optional()
        .describe("Number of fixes applied in the prior step (cac --fixes-applied)."),
    },
    async ({ root, policies, signing_key, fixes_applied }) => {
      try {
        const extra =
          typeof fixes_applied === "number" ? ["--fixes-applied", String(fixes_applied)] : [];
        const invocation = await runCac([
          "validate",
          ...extra,
          ...commonFlags({ root, policies, signing_key }),
        ]);
        return jsonContent(parseEngineJson(invocation));
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "run",
    "Full Compliance-as-Code pipeline: detect → fix → validate. " +
      "Same as `cac run`. Offline policy engine; no LLM.",
    {
      root: rootArg,
      policies: policiesArg,
      signing_key: signingKeyArg,
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the fix stage without writing files."),
    },
    async ({ root, policies, signing_key, dry_run }) => {
      try {
        const extra = dry_run ? ["--dry-run"] : [];
        const invocation = await runCac([
          "run",
          ...extra,
          ...commonFlags({ root, policies, signing_key }),
        ]);
        return jsonContent(parseEngineJson(invocation));
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "audit",
    "Read the signed append-only ledger at <root>/.cac/audit.jsonl " +
      "(cac audit --format json).",
    {
      root: rootArg,
      signing_key: signingKeyArg,
    },
    async ({ root, signing_key }) => {
      try {
        const invocation = await runCac(["audit", ...commonFlags({ root, signing_key })]);
        return jsonContent(parseEngineJson(invocation));
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "cac_version",
    "Report MCP package version and the resolved cac engine path.",
    {},
    async () =>
      jsonContent({
        mcp: `@cubiczan/compliance-as-code-mcp@${PKG_VERSION}`,
        brand: "Cubiczan",
        engine: "cac-cli",
        cac_bin: resolveCacBin(),
        detection: "offline YAML policy packs — no LLM",
      }),
  );

  return server;
}
