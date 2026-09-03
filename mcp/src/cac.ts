import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_DIR = dirname(fileURLToPath(new URL(".", import.meta.url)));

export class CacNotFoundError extends Error {
  constructor() {
    super(
      "cac binary not found. Build the engine with `cargo build -p cac-cli` " +
        "or set CAC_BIN to the cac executable.",
    );
    this.name = "CacNotFoundError";
  }
}

export function resolveCacBin(): string {
  const fromEnv = process.env.CAC_BIN?.trim();
  if (fromEnv && existsSync(fromEnv)) {
    return resolve(fromEnv);
  }

  const candidates: string[] = [];
  const walkRoots = [process.cwd(), PACKAGE_DIR, join(PACKAGE_DIR, "..")];
  for (const root of walkRoots) {
    let dir = resolve(root);
    for (let i = 0; i < 8; i += 1) {
      candidates.push(join(dir, "target", "release", "cac"));
      candidates.push(join(dir, "target", "debug", "cac"));
      const parent = dirname(dir);
      if (parent === dir) {
        break;
      }
      dir = parent;
    }
  }

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return "cac";
}

export interface CacInvocation {
  stdout: string;
  stderr: string;
  code: number | null;
}

export function runCac(args: string[], env?: NodeJS.ProcessEnv): Promise<CacInvocation> {
  const bin = resolveCacBin();
  return new Promise((resolvePromise, reject) => {
    const child = spawn(bin, args, {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(new CacNotFoundError());
        return;
      }
      reject(err);
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("close", (code) => {
      resolvePromise({ stdout, stderr, code });
    });
  });
}

export interface CacCommonArgs {
  root?: string;
  policies?: string;
  signing_key?: string;
}

export function commonFlags(args: CacCommonArgs): string[] {
  const flags = ["--format", "json"];
  if (args.root) {
    flags.push("--root", args.root);
  }
  if (args.policies) {
    flags.push("--policies", args.policies);
  }
  if (args.signing_key) {
    flags.push("--signing-key", args.signing_key);
  }
  return flags;
}

/**
 * cac scan/validate/run exit 1 when critical violations remain.
 * That is a findings payload, not an MCP transport failure.
 */
export function parseEngineJson(invocation: CacInvocation): unknown {
  const text = invocation.stdout.trim();
  if (!text) {
    throw new Error(
      invocation.stderr.trim() ||
        `cac produced no stdout (exit ${invocation.code ?? "unknown"})`,
    );
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(
      `cac returned non-JSON stdout (exit ${invocation.code ?? "unknown"}): ${text.slice(0, 400)}`,
    );
  }
}
