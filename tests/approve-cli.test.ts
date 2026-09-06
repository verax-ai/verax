import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createProxy, FileLedger, loadPolicy } from "@verax-ai/proxy";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";

const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src", "cli.ts");

const POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "memory-put-approve",
      tool: "memory.put",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Writes need operator approval.",
    },
  ],
};

describe("verax approve CLI", () => {
  it("writes a chained allow for a pending defer", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-approve-cli-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy(POLICY),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "d-cli",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "memory.put",
        arguments: { id: "n1", body: "x", source: { kind: "t" }, validUntilMs: 9_999 },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    ledger.close();
    const child = spawn(process.execPath, ["--experimental-strip-types", cli, "approve", dir, "d-cli"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (buf: Buffer) => {
      stdout += String(buf);
    });
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    const code = await new Promise<number>((resolve) => {
      child.on("close", (exit) => resolve(exit ?? 1));
    });
    assert.equal(code, 0, stderr);
    assert.match(stdout, /^approved:/);
    const again = new FileLedger(dir);
    const recs = await again.decisions();
    assert.equal(recs.length, 2);
    assert.equal(recs[0]!.claims.decision, "defer");
    assert.equal(recs[1]!.claims.decision, "allow");
    assert.equal(recs[1]!.claims.reasonCode, "approved-by-operator");
    again.close();
  });
});
