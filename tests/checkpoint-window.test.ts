import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { explain } from "@verax-ai/proxy";

import { createBodyServices } from "../packages/body/src/wiring.ts";
import { requestWitnessCheckpoint } from "../packages/body/src/witness.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/**
 * Waits for the witness to announce its socket. The bound is generous because
 * this measures a process start, not a deadline: under a full test run the
 * witness strips types on a busy CPU and took over 5 s twice. A witness that
 * exits fails immediately, so a real failure is still caught at once.
 */
async function waitFile(path: string, child?: { exitCode: number | null }, ms = 30_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (existsSync(path)) return;
    if (child && child.exitCode !== null) throw new Error(`witness-exited:${child.exitCode}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`listen-timeout:${path}`);
}

function spawnWitness(dir: string) {
  return spawn(process.execPath, ["--experimental-strip-types", cli, "witness", dir], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
}

async function putNote(dir: string, ref: string) {
  const body = testKeys();
  const services = createBodyServices({
    stateDir: dir,
    policyFile,
    recordSigner: body,
    effectSigner: body,
    now: () => 5_000,
    nonce: () => ref,
  });
  const allowed = await services.proxy.call(
    {
      name: "memory.put",
      arguments: {
        id: `note-${ref}`,
        body: { t: 1 },
        source: { uri: "file://t", retrievedAtMs: 1 },
        validUntilMs: 9_999,
      },
    },
    { brain: "brain-1", scopes: new Set(["verax:memory"]) },
  );
  assert.equal(allowed.isError, false);
  return services;
}

describe("durable checkpoint", () => {
  it("without a checkpoint explain still lists window-coverage as notApplicable", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-cp-none-"));
    const services = await putNote(dir, "bare-1");
    try {
      const result = await explain(services.ledger, "bare-1");
      assert.deepEqual(result.finding.notApplicable, ["window-coverage"]);
    } finally {
      services.ledger.close();
    }
  });

  it("a witness-signed covering checkpoint makes window-coverage applicable", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-cp-ok-"));
    const child = spawnWitness(dir);
    try {
      await waitFile(join(dir, "witness.listen.json"), child);
      const services = await putNote(dir, "cover-1");
      try {
        const decisions = await services.ledger.decisions();
        const times = decisions.map((d) => d.claims.timestampMs);
        const startMs = Math.min(...times);
        const endMs = Math.max(...times) + 1;
        const signed = await requestWitnessCheckpoint(dir, { epoch: 0, startMs, endMs });
        assert.ok(signed, "witness did not sign a checkpoint");
        assert.equal(existsSync(join(dir, "checkpoints.jsonl")), true);
        const covered = await explain(services.ledger, "cover-1");
        assert.equal(
          covered.finding.notApplicable?.includes("window-coverage") ?? false,
          false,
          `notApplicable stayed ${JSON.stringify(covered.finding.notApplicable)}`,
        );
        const bare = JSON.parse(readFileSync(join(dir, "checkpoints.jsonl"), "utf8").trim().split("\n")[0] ?? "{}") as {
          claims?: { startMs?: number; endMs?: number };
        };
        assert.equal(bare.claims?.startMs, startMs);
        assert.equal(bare.claims?.endMs, endMs);
      } finally {
        services.ledger.close();
      }
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGTERM");
        await new Promise((resolve) => child.once("close", resolve));
      }
    }
  });
});
