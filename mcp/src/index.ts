#!/usr/bin/env node
/**
 * @cubiczan/compliance-as-code-mcp — stdio MCP entrypoint.
 *
 * One-command install for Cursor / Claude Code:
 *   npx -y @cubiczan/compliance-as-code-mcp
 *
 * Requires a built `cac` on PATH or CAC_BIN (cargo build -p cac-cli).
 * CHP is the lock; MCP is the pipe.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

const server = createServer();
const transport = new StdioServerTransport();

function shutdown(): void {
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.stdin.on("end", shutdown);

await server.connect(transport);
