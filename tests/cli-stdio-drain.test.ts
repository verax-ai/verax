/**
 * process.exit after a large stdout write cuts a pipe on Linux and macOS
 * (~146 KB). The CLI entry must drain stdout/stderr before ending.
 * On Windows the same pipe delivers the full write before the change too.
 */
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createProxy, FileLedger, loadPolicy } from "@verax-ai/proxy";

import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { persistPolicySnapshot } from "../packages/body/src/policy-store.ts";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

const TOOL_COUNT = 120;
const NAME_LEN = 2000;
const FROM = "2026-03-01";
const TO = "2026-03-31";

async function largeReportLedger(): Promise<string> {
  const rules = Array.from({ length: TOOL_COUNT }, (_, i) => {
    const tool = `t${i}-` + "a".repeat(NAME_LEN);
    return { id: `r${i}`, tool, requires: ["verax:memory"], mode: "allow" as const, text: "x" };
  });
  const policyDoc = { version: 1 as const, default: "deny" as const, rules };
  const dir = mkdtempSync(join(tmpdir(), "verax-stdio-drain-"));
  const signers = loadOrCreateSigners(dir);
  const policy = loadPolicy(policyDoc);
  persistPolicySnapshot(dir, policy.hash, policyDoc);
  let clock = Date.UTC(2026, 2, 10);
  let n = 0;
  const proxy = createProxy({
    policy,
    recordSigner: signers.recordSigner,
    effectSigner: signers.effectSigner,
    ledger: new FileLedger(dir),
    now: () => clock++,
    nonce: () => `n${n++}`,
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  const principal = { brain: "b", scopes: new Set(["verax:memory"]) };
  for (const rule of rules) {
    await proxy.call({ name: rule.tool, arguments: {} }, principal);
  }
  return dir;
}

function spawnCli(args: string[]): Promise<{ status: number | null; stdout: Buffer; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const chunks: Buffer[] = [];
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => chunks.push(c));
    child.stderr.on("data", (c: Buffer | string) => {
      stderr += typeof c === "string" ? c : c.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (status) => {
      resolve({ status, stdout: Buffer.concat(chunks), stderr });
    });
  });
}

describe("CLI stdio drain before exit", () => {
  it("n2. report --json over 200 KB through a pipe is complete parseable JSON", async () => {
    const dir = await largeReportLedger();
    try {
      const ran = await spawnCli(["report", dir, "--from", FROM, "--to", TO, "--json"]);
      assert.equal(ran.status, 0, ran.stderr);
      assert.ok(
        ran.stdout.byteLength > 200_000,
        `expected >200 KB of stdout, got ${ran.stdout.byteLength}`,
      );
      const parsed = JSON.parse(ran.stdout.toString("utf8")) as {
        verification?: { ok?: boolean };
        decisions?: { byTool?: Record<string, unknown> };
      };
      assert.equal(parsed.verification?.ok, true);
      assert.equal(Object.keys(parsed.decisions?.byTool ?? {}).length, TOOL_COUNT);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
