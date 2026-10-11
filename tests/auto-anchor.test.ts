import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger } from "@verax-ai/proxy";

import { runDoctor } from "../packages/body/src/doctor.ts";
import { readWitnessPulse } from "../packages/body/src/health-extras.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";
import { readWitnessListen, requestWitnessCheckpoint } from "../packages/body/src/witness.ts";
import { refusedAsElevated, skipIfElevated } from "./elevated-refusal.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");
const ledger = join(root, "test-vectors", "v1", "valid-full", "ledger");
const pins = join(root, "test-vectors", "v1", "valid-full", "pins");
const fixture = join(root, "tests", "fixtures", "anchor-capsule");
const serviceKey = readFileSync(join(fixture, "service-key.pem"), "utf8");
// valid-full's only checkpoint window ends here.
const FIXTURE_END_MS = 1790974492255;

function copyLedger(withAnchors: boolean): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-autoanchor-"));
  for (const name of readdirSync(ledger)) copyFileSync(join(ledger, name), join(dir, name));
  if (withAnchors) copyFileSync(join(fixture, "checkpoint-anchors.jsonl"), join(dir, "checkpoint-anchors.jsonl"));
  return dir;
}

const pinned = () => ({
  publicKeyPem: readFileSync(join(pins, "record-key.pem"), "utf8"),
  witnessPublicKeyPem: readFileSync(join(pins, "witness-key.pem"), "utf8"),
  checkpointPublicKeyPem: readFileSync(join(pins, "witness-key.pem"), "utf8"),
});

/**
 * A receipt kept in the same directory as the checkpoint can be deleted with
 * nothing to show for it. `requireAnchored` turns that into a named problem
 * once the checkpoint is older than the grace.
 */
describe("verify --require-anchored", () => {
  it("a deleted receipt is named once the checkpoint is past the grace", async () => {
    const dir = copyLedger(false);
    try {
      const result = await verifyLedger(dir, {
        ...pinned(),
        anchorPublicKeyPem: serviceKey,
        requireAnchored: true,
        nowMs: FIXTURE_END_MS + 60 * 60 * 1000,
      });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.startsWith("checkpoint-not-anchored ")), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a checkpoint inside the grace is not yet held to it", async () => {
    const dir = copyLedger(false);
    try {
      const result = await verifyLedger(dir, {
        ...pinned(),
        anchorPublicKeyPem: serviceKey,
        requireAnchored: true,
        nowMs: FIXTURE_END_MS + 1000,
      });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a receipt that verifies under the service key satisfies it", async () => {
    const dir = copyLedger(true);
    try {
      const result = await verifyLedger(dir, {
        ...pinned(),
        anchorPublicKeyPem: serviceKey,
        requireAnchored: true,
        nowMs: FIXTURE_END_MS + 60 * 60 * 1000,
      });
      assert.equal(result.ok, true, JSON.stringify(result.problems));
      assert.equal(result.anchors.verified, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a receipt under another key does not satisfy it", async () => {
    const dir = copyLedger(true);
    const other = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    try {
      const result = await verifyLedger(dir, {
        ...pinned(),
        anchorPublicKeyPem: other,
        requireAnchored: true,
        nowMs: FIXTURE_END_MS + 60 * 60 * 1000,
      });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.startsWith("checkpoint-not-anchored ")), JSON.stringify(result.problems));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("without the service key it does not pass", async () => {
    const dir = copyLedger(true);
    try {
      const result = await verifyLedger(dir, { ...pinned(), requireAnchored: true });
      assert.equal(result.ok, false);
      assert.ok(result.problems.some((p) => p.startsWith("require-anchored needs the service key")));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the command refuses --require-anchored without --anchor-key, and a bad grace", async () => {
    const dir = copyLedger(true);
    const out: string[] = [];
    try {
      // verify exits 1 for every run that does not verify, a usage error included.
      assert.equal(await runVerify([dir, "--require-anchored"], (s) => out.push(s)), 1);
      assert.match(out.join("\n"), /--require-anchored needs --anchor-key/);
      const keyFile = join(dir, "service.pem");
      writeFileSync(keyFile, serviceKey, "utf8");
      out.length = 0;
      assert.equal(
        await runVerify([dir, "--anchor-key", keyFile, "--require-anchored", "--anchor-grace-ms", "-5"], (s) => out.push(s)),
        1,
      );
      assert.equal(
        await runVerify([dir, "--anchor-key", keyFile, "--require-anchored", "--anchor-grace-ms", "soon"], (s) => out.push(s)),
        1,
      );
      assert.equal(out.filter((l) => /--anchor-grace-ms needs a whole number/.test(l)).length, 2, out.join("\n"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

async function waitFor(check: () => boolean, child?: { exitCode: number | null }, ms = 30_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return;
    if (child && child.exitCode !== null) throw new Error(`witness-exited:${child.exitCode}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("wait-timeout");
}

type Mode = "answer" | "fail" | "hang";

/** A loopback Transparency Service. `answer` returns the fixture receipt for the entry it is asked for. */
async function fakeService(mode: Mode): Promise<{ url: string; server: Server; seen: string[] }> {
  const fixtureRow = JSON.parse(readFileSync(join(fixture, "checkpoint-anchors.jsonl"), "utf8").trim()) as {
    receiptB64: string;
    leafIndex: number;
    treeSize: number;
  };
  const seen: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push(body);
      if (mode === "hang") return;
      if (mode === "fail") {
        res.writeHead(500).end();
        return;
      }
      const { capsule_id } = JSON.parse(body) as { capsule_id: string };
      const entry = createHash("sha256").update(Buffer.from(capsule_id, "hex")).digest("hex");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          receipt_b64: fixtureRow.receiptB64,
          entry_hash: entry,
          leaf_index: fixtureRow.leafIndex,
          tree_size: fixtureRow.treeSize,
        }),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("bind");
  return { url: `http://127.0.0.1:${addr.port}`, server, seen };
}

function spawnWitness(dir: string, env: Record<string, string>) {
  return spawn(process.execPath, ["--experimental-strip-types", cli, "witness", dir], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    env: { ...process.env, ...env },
  });
}

async function withWitness(
  t: { skip: (m?: string) => void },
  mode: Mode,
  run: (dir: string, seen: string[]) => Promise<void>,
): Promise<void> {
  if (skipIfElevated(t)) return;
  const service = await fakeService(mode);
  const dir = mkdtempSync(join(tmpdir(), "verax-autoanchor-w-"));
  const child = spawnWitness(dir, { VERAX_ANCHOR_SERVICE: service.url });
  let stderr = "";
  child.stderr?.on("data", (buf: Buffer) => {
    stderr += String(buf);
  });
  try {
    try {
      await waitFor(() => existsSync(join(dir, "witness.listen.json")), child);
    } catch (err) {
      if (child.exitCode !== null && refusedAsElevated(child.exitCode, stderr)) return;
      throw err;
    }
    await run(dir, service.seen);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await new Promise((resolve) => child.once("close", resolve));
    }
    service.server.closeAllConnections();
    service.server.close();
  }
}

async function signOne(dir: string, ref: string) {
  const body = (() => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    return {
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
  })();
  const services = createBodyServices({
    stateDir: dir,
    policyFile,
    recordSigner: body,
    effectSigner: body,
    now: () => 5_000,
    nonce: () => ref,
  });
  try {
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
    const started = Date.now();
    const signed = await requestWitnessCheckpoint(dir, { epoch: 0, startMs: 4_000, endMs: 6_000 });
    return { signed, tookMs: Date.now() - started };
  } finally {
    services.ledger.close();
  }
}

function statusRows(dir: string): { result?: string; reason?: string; checkpointHash?: string }[] {
  const path = join(dir, "witness-status.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l) as { result?: string });
}

/**
 * With `VERAX_ANCHOR_SERVICE` set the witness registers each checkpoint it
 * signs, after it has answered the body, and a failure is a status row.
 */
describe("verax witness with VERAX_ANCHOR_SERVICE", () => {
  it("registers the checkpoint it signs and keeps the receipt", async (t) => {
    await withWitness(t, "answer", async (dir, seen) => {
      assert.ok(readWitnessListen(dir)?.anchorService?.startsWith("http://127.0.0.1:"));
      const { signed } = await signOne(dir, "auto-1");
      assert.ok(signed, "witness did not sign a checkpoint");
      await waitFor(() => existsSync(join(dir, "checkpoint-anchors.jsonl")));
      assert.equal(seen.length, 1);
      const rows = readFileSync(join(dir, "checkpoint-anchors.jsonl"), "utf8").trim().split("\n");
      assert.equal(rows.length, 1);
      const kept = JSON.parse(rows[0]!) as { checkpointHash: string };
      assert.deepEqual(JSON.parse(seen[0]!), { capsule_id: kept.checkpointHash });
      await waitFor(() => statusRows(dir).some((r) => r.result === "anchored"));
      const doctor = runDoctor({ VERAX_STATE_DIR: dir }, []).find((c) => c.id === "anchor");
      assert.equal(doctor?.level, "ok", JSON.stringify(doctor));
      assert.match(doctor?.detail ?? "", /anchors each checkpoint at http:\/\/127\.0\.0\.1:/);
    });
  });

  it("a service that fails leaves an anchor-failed row and the checkpoint stands", async (t) => {
    await withWitness(t, "fail", async (dir) => {
      const { signed } = await signOne(dir, "auto-2");
      assert.ok(signed, "a failing service stopped the checkpoint");
      await waitFor(() => statusRows(dir).some((r) => r.result === "anchor-failed"));
      assert.equal(existsSync(join(dir, "checkpoint-anchors.jsonl")), false);
      const doctor = runDoctor({ VERAX_STATE_DIR: dir }, []).find((c) => c.id === "anchor");
      assert.equal(doctor?.level, "warn", JSON.stringify(doctor));
      assert.match(doctor?.detail ?? "", /1 checkpoint\(s\) not yet anchored .*last attempt failed: unreachable/);
    });
  });

  it("a service that never answers does not hold up the checkpoint", async (t) => {
    await withWitness(t, "hang", async (dir, seen) => {
      const { signed, tookMs } = await signOne(dir, "auto-3");
      assert.ok(signed, "a hanging service stopped the checkpoint");
      assert.ok(tookMs < 800, `checkpoint took ${tookMs} ms`);
      await waitFor(() => seen.length === 1);
    });
  });

  it("refuses to start when the service is not https and not loopback", async (t) => {
    if (skipIfElevated(t)) return;
    const dir = mkdtempSync(join(tmpdir(), "verax-autoanchor-bad-"));
    const child = spawnWitness(dir, { VERAX_ANCHOR_SERVICE: "http://witness.example" });
    let stderr = "";
    child.stderr?.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    // A witness that ignores the setting keeps running; that is the failure, not a hang.
    const code = await new Promise<number | null>((resolve) => {
      const timer = setTimeout(() => {
        child.kill("SIGTERM");
        resolve(null);
      }, 30_000);
      child.once("close", (c) => {
        clearTimeout(timer);
        resolve(c);
      });
    });
    if (code !== null && refusedAsElevated(code, stderr)) return;
    assert.equal(code, 64, stderr);
    assert.match(stderr, /witness-anchor-config/);
    assert.equal(existsSync(join(dir, "witness.listen.json")), false);
  });
});

/** A checkpoint or anchor row after the last signature does not hide the witness class. */
describe("witness pulse with anchor rows", () => {
  it("reads the class from the last signed or fallback row", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-autoanchor-pulse-"));
    try {
      writeFileSync(
        join(dir, "witness-status.jsonl"),
        [
          { atMs: 1, ref: "r1", result: "signed", pid: 1 },
          { atMs: 2, result: "checkpoint", checkpointHash: "ab".repeat(32) },
          { atMs: 3, result: "anchored", service: "https://s", checkpointHash: "ab".repeat(32) },
          { atMs: 4, result: "anchor-failed", service: "https://s", reason: "unreachable" },
        ]
          .map((r) => JSON.stringify(r))
          .join("\n") + "\n",
        "utf8",
      );
      assert.deepEqual(readWitnessPulse(dir), { class: "same-org", atMs: 1 });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
