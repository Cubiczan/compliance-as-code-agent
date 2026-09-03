import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const mcpDir = path.resolve(testDir, "..");
const repoRoot = path.resolve(mcpDir, "..");
const serverEntry = path.join(mcpDir, "dist", "index.js");
const policiesDir = path.join(repoRoot, "policies");
const violationsRoot = path.join(repoRoot, "examples", "violations");

const PIPELINE_TOOLS = ["scan", "fix", "validate", "run", "audit"] as const;

function resolveBuiltCac(): string {
  if (process.env.CAC_BIN && existsSync(process.env.CAC_BIN)) {
    return process.env.CAC_BIN;
  }
  for (const rel of ["target/debug/cac", "target/release/cac"]) {
    const candidate = path.join(repoRoot, rel);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  const build = spawnSync("cargo", ["build", "-p", "cac-cli"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (build.status !== 0) {
    throw new Error(`cargo build -p cac-cli failed:\n${build.stderr}`);
  }
  const built = path.join(repoRoot, "target/debug/cac");
  if (!existsSync(built)) {
    throw new Error("cac binary missing after cargo build");
  }
  return built;
}

function parseToolJson(result: { content: Array<{ type: string; text?: string }> }): unknown {
  const text = result.content.find((c) => c.type === "text")?.text;
  assert.ok(text, "tool result missing text content");
  return JSON.parse(text);
}

async function withClient<T>(fn: (client: Client) => Promise<T>): Promise<T> {
  const cacBin = resolveBuiltCac();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    env: {
      ...process.env,
      CAC_BIN: cacBin,
    },
    cwd: repoRoot,
  });
  const client = new Client({ name: "cac-mcp-test", version: "0.0.0" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

test("tools/list exposes scan, fix, validate, run, and audit", async () => {
  await withClient(async (client) => {
    const listed = await client.listTools();
    const names = listed.tools.map((t) => t.name);
    for (const name of PIPELINE_TOOLS) {
      assert.ok(names.includes(name), `missing tool ${name}; have ${names.join(", ")}`);
    }
  });
});

test("scan against examples/violations returns real policy hits", async () => {
  await withClient(async (client) => {
    const raw = await client.callTool({
      name: "scan",
      arguments: {
        root: violationsRoot,
        policies: policiesDir,
        signing_key: "mcp-test-signing-key",
      },
    });
    assert.equal(raw.isError, undefined);
    const report = parseToolJson(raw) as {
      violations?: Array<{ rule_id?: string; policy_id?: string }>;
    };
    assert.ok(Array.isArray(report.violations), "scan JSON missing violations[]");
    assert.ok(
      report.violations.length > 0,
      "expected real policy hits on examples/violations",
    );
    const ruleIds = report.violations.map((v) => v.rule_id);
    const expected = ["secret-api-key", "gdpr-email-field", "soc2-auth-handler"];
    const found = expected.filter((id) => ruleIds.includes(id));
    assert.ok(
      found.length > 0,
      `expected at least one of ${expected.join(", ")}; got ${ruleIds.join(", ")}`,
    );
  });
});
