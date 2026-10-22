import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { tenantKey, verifyLedger } from "@verax-ai/proxy";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import { runDoctor } from "../packages/body/src/doctor.ts";
import { resumeBody } from "../packages/body/src/halt.ts";
import { loadOrCreateSigners, resolveHeadDir } from "../packages/body/src/keys.ts";
import { runMemoryRehead } from "../packages/body/src/memory-rehead-cli.ts";
import { MEMORY_COMMITS_FILE, memoryHeadPath, memoryStateDirHash } from "../packages/body/src/memory-store.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";

const policyFile = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "proxy", "policy", "default.json");
const UNTIL = Date.now() + 30 * 86_400_000;
const writer = { brain: "agent-a", scopes: new Set(["verax:memory", "verax:read"]) };

const APPROVE_POLICY = {
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

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function parse(result: { isError?: boolean; content: { text: string }[] }): {
  isError: boolean;
  data: Record<string, unknown>;
} {
  return { isError: result.isError === true, data: JSON.parse(result.content[0]?.text ?? "{}") as Record<string, unknown> };
}

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

function objectWith(state: string, marker: string): string {
  const hits = filesUnder(join(state, "tenants")).filter((f) => readFileSync(f, "utf8").includes(marker));
  assert.equal(hits.length, 1, `expected exactly one object holding ${marker}, found ${hits.length}`);
  return hits[0]!;
}

async function putFact(
  services: ReturnType<typeof createBodyServices>,
  id: string,
  fact: string,
): Promise<ReturnType<typeof parse>> {
  return parse(
    await services.proxy.call(
      {
        name: "memory.put",
        arguments: { id, body: { fact }, source: { uri: `file://${id}`, retrievedAtMs: 1 }, validUntilMs: UNTIL },
      },
      writer,
    ),
  );
}

async function getFact(services: ReturnType<typeof createBodyServices>, id: string): Promise<ReturnType<typeof parse>> {
  return parse(await services.proxy.call({ name: "memory.get", arguments: { id } }, writer));
}

function withPin<T>(pin: string, fn: () => T): T {
  const prev = process.env.VERAX_RECORD_PUBKEY_PIN;
  process.env.VERAX_RECORD_PUBKEY_PIN = pin;
  const restore = () => {
    if (prev === undefined) delete process.env.VERAX_RECORD_PUBKEY_PIN;
    else process.env.VERAX_RECORD_PUBKEY_PIN = prev;
  };
  try {
    const result = fn();
    if (result instanceof Promise) {
      return result.finally(restore) as T;
    }
    restore();
    return result;
  } catch (err) {
    restore();
    throw err;
  }
}

describe("memory integrity hardening (H1-H22)", () => {
  it("H1: a second open is refused and the first body keeps serving; a restart serves all", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h1-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const first = createBodyServices(opts);
    try {
      const seeded = await putFact(first, "n1", "fact-h1");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      assert.throws(() => createBodyServices(opts), /ledger-locked/);
      const live = await getFact(first, "n1");
      assert.equal(live.isError, false, JSON.stringify(live.data));
      assert.equal((live.data.body as { fact?: string } | undefined)?.fact, "fact-h1");
      first.ledger.close();
      const restarted = createBodyServices(opts);
      try {
        const again = await getFact(restarted, "n1");
        assert.equal(again.isError, false, JSON.stringify(again.data));
        assert.equal((again.data.body as { fact?: string } | undefined)?.fact, "fact-h1");
      } finally {
        restarted.ledger.close();
      }
    } finally {
      if (existsSync(join(stateDir, "ledger.lock"))) first.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H2: keysDir without record.public.pem stops the open", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h2-"));
    const keysDir = mkdtempSync(join(tmpdir(), "verax-h2-keys-"));
    const keys = testKeys();
    try {
      assert.throws(
        () => createBodyServices({ stateDir, policyFile, recordSigner: keys, effectSigner: keys, keysDir }),
        /record-public-key-missing/,
      );
      assert.equal(existsSync(join(stateDir, "ledger.lock")), false);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      rmSync(keysDir, { recursive: true, force: true });
    }
  });

  it("H3: keysDir public key that is not the record private key stops the open", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h3-"));
    const keysDir = mkdtempSync(join(tmpdir(), "verax-h3-keys-"));
    const keys = testKeys();
    const other = testKeys();
    writeFileSync(join(keysDir, "record.public.pem"), other.publicKeyPem);
    try {
      assert.throws(
        () => createBodyServices({ stateDir, policyFile, recordSigner: keys, effectSigner: keys, keysDir }),
        /record-public-key-mismatch/,
      );
      assert.equal(existsSync(join(stateDir, "ledger.lock")), false);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      rmSync(keysDir, { recursive: true, force: true });
    }
  });

  it("H4: a wrong VERAX_RECORD_PUBKEY_PIN stops the open; the matching pin opens and C1 holds", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h4-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    try {
      assert.throws(() => withPin(testKeys().publicKeyPem, () => createBodyServices(opts)), /record-pubkey-pin-mismatch/);
      assert.equal(existsSync(join(stateDir, "ledger.lock")), false);
      const first = withPin(keys.publicKeyPem, () => createBodyServices(opts));
      const seeded = await putFact(first, "n1", "fact-h4");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      first.ledger.close();
      const restarted = withPin(keys.publicKeyPem, () => createBodyServices(opts));
      try {
        const got = await getFact(restarted, "n1");
        assert.equal(got.isError, false, JSON.stringify(got.data));
        assert.equal((got.data.body as { fact?: string } | undefined)?.fact, "fact-h4");
      } finally {
        restarted.ledger.close();
      }
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H5: a raw 1e400 body is mismatch and does not crash the process", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h5-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const first = createBodyServices(opts);
    try {
      const seeded = await putFact(first, "n1", "fact-h5");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      first.ledger.close();
      const path = objectWith(stateDir, "fact-h5");
      const obj = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
      const { body: _body, ...rest } = obj;
      writeFileSync(path, `{"body":1e400,${JSON.stringify(rest).slice(1)}`);
      const restarted = createBodyServices(opts);
      try {
        const got = await getFact(restarted, "n1");
        assert.equal(got.isError, true, JSON.stringify(got.data));
        assert.equal(got.data.error, "memory-integrity-mismatch");
        assert.equal(JSON.stringify(got.data).includes("Infinity"), false);
      } finally {
        restarted.ledger.close();
      }
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H6: id note..2026 put, get, and get after restart", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h6-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const id = "note..2026";
    const first = createBodyServices(opts);
    try {
      const seeded = await putFact(first, id, "fact-dotdot");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      const live = await getFact(first, id);
      assert.equal(live.isError, false, JSON.stringify(live.data));
      assert.equal((live.data.body as { fact?: string } | undefined)?.fact, "fact-dotdot");
      first.ledger.close();
      const restarted = createBodyServices(opts);
      try {
        const again = await getFact(restarted, id);
        assert.equal(again.isError, false, JSON.stringify(again.data));
        assert.equal((again.data.body as { fact?: string } | undefined)?.fact, "fact-dotdot");
      } finally {
        restarted.ledger.close();
      }
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H7: approve with a separate keysDir signs the ledger under that key", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h7-"));
    const keysDir = mkdtempSync(join(tmpdir(), "verax-h7-keys-"));
    const localPolicy = join(stateDir, "policy.json");
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(localPolicy, `${JSON.stringify(APPROVE_POLICY)}\n`);
    const signers = loadOrCreateSigners(stateDir, keysDir);
    const services = createBodyServices({
      stateDir,
      policyFile: localPolicy,
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      keysDir,
      nonce: () => "h7-ref",
    });
    try {
      const held = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id: "n1",
            body: { fact: "h7" },
            source: { uri: "file://h7", retrievedAtMs: 1 },
            validUntilMs: UNTIL,
          },
        },
        writer,
      );
      assert.match(held.content[0]?.text ?? "", /deferred:approval-required/);
      services.ledger.close();
      let err = "";
      const code = await runApprove(
        ["approve", "--from-script", stateDir, "h7-ref"],
        (s) => {
          err += s;
        },
        () => undefined,
        undefined,
        { elevated: () => false, env: { ...process.env, VERAX_KEYS_DIR: keysDir } },
      );
      assert.equal(code, 0, err);
      const verified = await verifyLedger(stateDir, { publicKeyPem: signers.recordSigner.publicKeyPem });
      assert.equal(verified.signaturesInvalid, 0, verified.problems.join("\n"));
      assert.ok(verified.signaturesValid >= 2, `expected signed rows, got ${verified.signaturesValid}`);
      assert.equal(verified.trust.source, "pinned");
    } finally {
      try {
        services.ledger.close();
      } catch {
        // already closed
      }
      rmSync(stateDir, { recursive: true, force: true });
      rmSync(keysDir, { recursive: true, force: true });
    }
  });

  it("H8: a later put after an _inputs pin is served by memory.get, not the pinned v1", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h8-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const services = createBodyServices(opts);
    try {
      const v1 = await putFact(services, "n1", "fact-h8-v1");
      assert.equal(v1.isError, false, JSON.stringify(v1.data));
      const versionHash = String(v1.data.versionHash ?? "");
      assert.match(versionHash, /^[0-9a-f]{64}$/);

      let remembered = 0;
      const orig = services.memoryStore.rememberDecisionSnapshot.bind(services.memoryStore);
      services.memoryStore.rememberDecisionSnapshot = (tenant, object) => {
        remembered += 1;
        orig(tenant, object);
      };

      await services.proxy.call(
        { name: "message.read", arguments: { _inputs: [{ id: "n1", versionHash }] } },
        writer,
      );
      assert.equal(remembered, 1, "readMemoryMeta must run for the _inputs pin");

      const v2 = await putFact(services, "n1", "fact-h8-v2");
      assert.equal(v2.isError, false, JSON.stringify(v2.data));
      const got = await getFact(services, "n1");
      assert.equal(got.isError, false, JSON.stringify(got.data));
      assert.equal((got.data.body as { fact?: string } | undefined)?.fact, "fact-h8-v2");
    } finally {
      services.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H9: a pin does not skip verification after restart or a same-process file change", async () => {
    const keys = testKeys();

    const liveDir = mkdtempSync(join(tmpdir(), "verax-h9-live-"));
    const live = createBodyServices({ stateDir: liveDir, policyFile, recordSigner: keys, effectSigner: keys });
    try {
      const seeded = await putFact(live, "n1", "fact-h9-live");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      const versionHash = String(seeded.data.versionHash ?? "");
      assert.match(versionHash, /^[0-9a-f]{64}$/);

      let remembered = 0;
      const orig = live.memoryStore.rememberDecisionSnapshot.bind(live.memoryStore);
      live.memoryStore.rememberDecisionSnapshot = (tenant, object) => {
        remembered += 1;
        orig(tenant, object);
      };
      await live.proxy.call(
        { name: "message.read", arguments: { _inputs: [{ id: "n1", versionHash }] } },
        writer,
      );
      assert.equal(remembered, 1, "readMemoryMeta must run for the _inputs pin");

      const path = objectWith(liveDir, "fact-h9-live");
      writeFileSync(path, readFileSync(path, "utf8").replaceAll("fact-h9-live", "attacker-live"));
      const got = await getFact(live, "n1");
      assert.equal(got.isError, true, JSON.stringify(got.data));
      assert.match(String(got.data.error ?? ""), /^memory-integrity-/);
      assert.equal(JSON.stringify(got.data).includes("attacker-live"), false);
      assert.equal(JSON.stringify(got.data).includes("fact-h9-live"), false);
    } finally {
      live.ledger.close();
      rmSync(liveDir, { recursive: true, force: true });
    }

    const restartDir = mkdtempSync(join(tmpdir(), "verax-h9-restart-"));
    const restartOpts = { stateDir: restartDir, policyFile, recordSigner: keys, effectSigner: keys };
    const first = createBodyServices(restartOpts);
    try {
      const seeded = await putFact(first, "n1", "fact-h9-restart");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      const versionHash = String(seeded.data.versionHash ?? "");
      assert.match(versionHash, /^[0-9a-f]{64}$/);

      let remembered = 0;
      const orig = first.memoryStore.rememberDecisionSnapshot.bind(first.memoryStore);
      first.memoryStore.rememberDecisionSnapshot = (tenant, object) => {
        remembered += 1;
        orig(tenant, object);
      };
      await first.proxy.call(
        { name: "message.read", arguments: { _inputs: [{ id: "n1", versionHash }] } },
        writer,
      );
      assert.equal(remembered, 1, "readMemoryMeta must run for the _inputs pin");
      first.ledger.close();

      const path = objectWith(restartDir, "fact-h9-restart");
      writeFileSync(path, readFileSync(path, "utf8").replaceAll("fact-h9-restart", "attacker-restart"));
      const restarted = createBodyServices(restartOpts);
      try {
        const got = await getFact(restarted, "n1");
        assert.equal(got.isError, true, JSON.stringify(got.data));
        assert.match(String(got.data.error ?? ""), /^memory-integrity-/);
        assert.equal(JSON.stringify(got.data).includes("attacker-restart"), false);
        assert.equal(JSON.stringify(got.data).includes("fact-h9-restart"), false);
      } finally {
        restarted.ledger.close();
      }
    } finally {
      if (existsSync(join(restartDir, "ledger.lock"))) first.ledger.close();
      rmSync(restartDir, { recursive: true, force: true });
    }
  });

  it("H10: memory.get _inputs v1, v2 written after the decision and before the tool, answers memory-changed", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h10-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const services = createBodyServices(opts);
    try {
      const v1 = await putFact(services, "n1", "fact-h10-v1");
      assert.equal(v1.isError, false, JSON.stringify(v1.data));
      const versionHash = String(v1.data.versionHash ?? "");
      assert.match(versionHash, /^[0-9a-f]{64}$/);

      const orig = services.ledger.appendDecisionChained.bind(services.ledger);
      let injected = false;
      (services.ledger as { appendDecisionChained: typeof orig }).appendDecisionChained = async (build) => {
        let subject = "";
        let decision = "";
        await orig((prev) => {
          const rec = build(prev);
          subject = rec.claims.subject;
          decision = rec.claims.decision;
          return rec;
        });
        if (!injected && subject === "memory.get" && decision === "allow") {
          injected = true;
          const written = await services.memoryStore.put({
            tenantKey: tenantKey(writer),
            id: "n1",
            body: { fact: "fact-h10-v2" },
            source: { uri: "file://n1", retrievedAtMs: 1 },
            validFromMs: 0,
            validUntilMs: UNTIL,
            putRef: "h10-race",
            quotaBytes: 1_000_000,
          });
          assert.equal(written.ok, true, JSON.stringify(written));
        }
      };

      const got = parse(
        await services.proxy.call(
          { name: "memory.get", arguments: { id: "n1", _inputs: [{ id: "n1", versionHash }] } },
          writer,
        ),
      );
      assert.equal(injected, true, "v2 must be written after the allow and before memory.get");
      assert.equal(got.isError, true, JSON.stringify(got.data));
      assert.equal(got.data.error, "memory-changed");
      assert.equal(got.data.id, "n1");
    } finally {
      services.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H12: without keysDir, a public key that is not the record private key stops the open", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h12-"));
    const keys = testKeys();
    const other = testKeys();
    try {
      assert.throws(
        () =>
          createBodyServices({
            stateDir,
            policyFile,
            recordSigner: { publicKeyPem: keys.publicKeyPem, privateKeyPem: other.privateKeyPem },
            effectSigner: keys,
          }),
        /record-public-key-mismatch/,
      );
      assert.equal(existsSync(join(stateDir, "ledger.lock")), false);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H13: a directory at the commit path opens the body; get is history-unavailable", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h13-"));
    const keys = testKeys();
    mkdirSync(join(stateDir, "memory-commits.jsonl"));
    const services = createBodyServices({ stateDir, policyFile, recordSigner: keys, effectSigner: keys });
    try {
      const got = await getFact(services, "n1");
      assert.equal(got.isError, true, JSON.stringify(got.data));
      assert.equal(got.data.error, "memory-integrity-history-unavailable");
    } finally {
      services.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H14: a broken head signature makes get history-unavailable after open", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h14-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const first = createBodyServices(opts);
    try {
      const seeded = await putFact(first, "n1", "fact-h14");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      first.ledger.close();
      const headPath = memoryHeadPath(stateDir, resolveHeadDir(stateDir));
      const row = JSON.parse(readFileSync(headPath, "utf8")) as { sig: string };
      writeFileSync(headPath, `${JSON.stringify({ ...row, sig: `x${row.sig.slice(1)}` })}\n`);
      const restarted = createBodyServices(opts);
      try {
        const got = await getFact(restarted, "n1");
        assert.equal(got.isError, true, JSON.stringify(got.data));
        assert.equal(got.data.error, "memory-integrity-history-unavailable");
      } finally {
        restarted.ledger.close();
      }
    } finally {
      if (existsSync(join(stateDir, "ledger.lock"))) first.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H15: crash after commit, before head update, opens and the head catches up", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h15-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const first = createBodyServices(opts);
    try {
      const a = await putFact(first, "n1", "fact-h15-a");
      assert.equal(a.isError, false, JSON.stringify(a.data));
      const headPath = memoryHeadPath(stateDir, resolveHeadDir(stateDir));
      const previous = readFileSync(headPath);
      const b = await putFact(first, "n2", "fact-h15-b");
      assert.equal(b.isError, false, JSON.stringify(b.data));
      writeFileSync(headPath, previous);
      first.ledger.close();
      const restarted = createBodyServices(opts);
      try {
        const got1 = await getFact(restarted, "n1");
        const got2 = await getFact(restarted, "n2");
        assert.equal(got1.isError, false, JSON.stringify(got1.data));
        assert.equal(got2.isError, false, JSON.stringify(got2.data));
        assert.equal((got1.data.body as { fact?: string } | undefined)?.fact, "fact-h15-a");
        assert.equal((got2.data.body as { fact?: string } | undefined)?.fact, "fact-h15-b");
        const head = JSON.parse(readFileSync(headPath, "utf8")) as { payload: { seq: number; lastHash: string } };
        const lines = readFileSync(join(stateDir, MEMORY_COMMITS_FILE), "utf8")
          .split("\n")
          .filter((line) => line.trim() !== "");
        const last = JSON.parse(lines[lines.length - 1]!) as { payload: { seq: number } };
        assert.equal(head.payload.seq, last.payload.seq);
        assert.equal(head.payload.seq, 2);
      } finally {
        restarted.ledger.close();
      }
    } finally {
      if (existsSync(join(stateDir, "ledger.lock"))) first.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H16: verax doctor warns when the key dir is inside state, and not when it is outside", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h16-"));
    const keysDir = mkdtempSync(join(tmpdir(), "verax-h16-keys-"));
    try {
      const inside = runDoctor({ VERAX_STATE_DIR: stateDir }, ["node", "cli.ts", "doctor"]);
      const warning = inside.find((c) => c.id === "record-key-location");
      assert.equal(warning?.level, "warn", JSON.stringify(inside));
      assert.match(
        warning?.detail ?? "",
        /record key is inside the state directory; a state-directory writer also holds the key/,
      );
      assert.match(warning?.detail ?? "", /VERAX_KEYS_DIR/);
      const outside = runDoctor(
        { VERAX_STATE_DIR: stateDir, VERAX_KEYS_DIR: keysDir },
        ["node", "cli.ts", "doctor"],
      );
      assert.equal(
        outside.find((c) => c.id === "record-key-location"),
        undefined,
        JSON.stringify(outside),
      );
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
      rmSync(keysDir, { recursive: true, force: true });
    }
  });

  it("H17: a directory at the head path fail-closes; get never serves the old version", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h17-"));
    const keys = testKeys();
    const opts = { stateDir, policyFile, recordSigner: keys, effectSigner: keys };
    const first = createBodyServices(opts);
    try {
      const v1 = await putFact(first, "n1", "fact-h17-v1");
      assert.equal(v1.isError, false, JSON.stringify(v1.data));
      const headPath = memoryHeadPath(stateDir, resolveHeadDir(stateDir));
      rmSync(headPath);
      mkdirSync(headPath);
      try {
        await putFact(first, "n1", "fact-h17-v2");
      } catch {
        // put may throw or return; get must still fail-close.
      }
      const got = await getFact(first, "n1");
      assert.equal(got.isError, true, JSON.stringify(got.data));
      assert.equal(got.data.error, "memory-integrity-history-unavailable");
      assert.notEqual((got.data.body as { fact?: string } | undefined)?.fact, "fact-h17-v1");
      assert.notEqual((got.data.body as { fact?: string } | undefined)?.fact, "fact-h17-v2");
    } finally {
      if (existsSync(join(stateDir, "ledger.lock"))) first.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it(
    "H18: win32 case variants of the same state dir share doctor warning and head file name",
    { skip: process.platform !== "win32" && "win32 folds case; a different case is a different path elsewhere" },
    () => {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-h18-"));
      const lower = stateDir.toLowerCase();
      const upper = stateDir.toUpperCase();
      try {
        assert.notEqual(lower, upper);
        const argv = ["node", "cli.ts", "doctor"];
        const original = runDoctor({ VERAX_STATE_DIR: lower }, argv);
        const cased = runDoctor({ VERAX_STATE_DIR: upper }, argv);
        const warningA = original.find((c) => c.id === "record-key-location");
        const warningB = cased.find((c) => c.id === "record-key-location");
        assert.equal(warningA?.level, "warn", JSON.stringify(original));
        assert.equal(warningB?.level, "warn", JSON.stringify(cased));
        assert.equal(warningA?.detail, warningB?.detail);
        assert.equal(memoryStateDirHash(lower), memoryStateDirHash(upper));
        assert.equal(
          basename(memoryHeadPath(lower, resolveHeadDir(lower))),
          basename(memoryHeadPath(upper, resolveHeadDir(upper))),
        );
      } finally {
        rmSync(stateDir, { recursive: true, force: true });
      }
    },
  );

  it("H19: missing head on a non-empty chain stays closed until rehead", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h19-"));
    const signers = loadOrCreateSigners(stateDir);
    const opts = {
      stateDir,
      policyFile,
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
    };
    const first = createBodyServices(opts);
    try {
      const a = await putFact(first, "n1", "fact-h19-a");
      const b = await putFact(first, "n2", "fact-h19-b");
      assert.equal(a.isError, false, JSON.stringify(a.data));
      assert.equal(b.isError, false, JSON.stringify(b.data));
      first.ledger.close();
      const headPath = memoryHeadPath(stateDir, resolveHeadDir(stateDir));
      rmSync(headPath);
      const closed = createBodyServices(opts);
      try {
        const got = await getFact(closed, "n1");
        assert.equal(got.isError, true, JSON.stringify(got.data));
        assert.equal(got.data.error, "memory-integrity-history-unavailable");
        const refused = await closed.proxy.call(
          {
            name: "memory.put",
            arguments: {
              id: "n3",
              body: { fact: "fact-h19-c" },
              source: { uri: "file://n3", retrievedAtMs: 1 },
              validUntilMs: UNTIL,
            },
          },
          writer,
        );
        assert.equal(refused.isError, true, refused.content[0]?.text);
        const refusedText = refused.content[0]?.text ?? "";
        assert.ok(
          refusedText.includes("memory-integrity-history-unavailable") || /denied:halted/.test(refusedText),
          refusedText,
        );
        assert.equal(existsSync(headPath), false);
      } finally {
        closed.ledger.close();
      }
      let out = "";
      let err = "";
      const code = await runMemoryRehead(
        ["rehead", stateDir],
        { write(s) { out += s; return true; } },
        { write(s) { err += s; return true; } },
      );
      assert.equal(code, 0, err);
      assert.match(out, /^2 [0-9a-f]{16}\n$/);
      assert.equal(existsSync(headPath), true);
      const opened = createBodyServices(opts);
      try {
        const halted1 = await opened.proxy.call({ name: "memory.get", arguments: { id: "n1" } }, writer);
        const halted2 = await opened.proxy.call({ name: "memory.get", arguments: { id: "n2" } }, writer);
        assert.equal(halted1.isError, true, halted1.content[0]?.text);
        assert.equal(halted2.isError, true, halted2.content[0]?.text);
        assert.match(halted1.content[0]?.text ?? "", /denied:halted/);
        assert.match(halted2.content[0]?.text ?? "", /denied:halted/);
        resumeBody(stateDir, "test-operator", "cli");
        const got1 = await getFact(opened, "n1");
        const got2 = await getFact(opened, "n2");
        assert.equal(got1.isError, false, JSON.stringify(got1.data));
        assert.equal(got2.isError, false, JSON.stringify(got2.data));
        assert.equal((got1.data.body as { fact?: string } | undefined)?.fact, "fact-h19-a");
        assert.equal((got2.data.body as { fact?: string } | undefined)?.fact, "fact-h19-b");
      } finally {
        opened.ledger.close();
      }
    } finally {
      if (existsSync(join(stateDir, "ledger.lock"))) first.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H20: rehead is refused while the body holds the ledger lock", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h20-"));
    const signers = loadOrCreateSigners(stateDir);
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
    });
    try {
      let err = "";
      const code = await runMemoryRehead(
        ["rehead", stateDir],
        { write() { return true; } },
        { write(s) { err += s; return true; } },
      );
      assert.equal(code, 1, err);
      assert.match(err, /^memory-rehead-body-running\n$/);
    } finally {
      services.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H21: concurrent put and get of a new id never returns memory-integrity-*", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h21-"));
    const keys = testKeys();
    const services = createBodyServices({ stateDir, policyFile, recordSigner: keys, effectSigner: keys });
    try {
      for (let i = 0; i < 50; i++) {
        const id = `n-h21-${i}`;
        const fact = `fact-h21-${i}`;
        const [written, got] = await Promise.all([putFact(services, id, fact), getFact(services, id)]);
        assert.equal(written.isError, false, JSON.stringify(written.data));
        const getError = typeof got.data.error === "string" ? got.data.error : "";
        assert.equal(getError.startsWith("memory-integrity-"), false, JSON.stringify(got.data));
        if (got.isError) {
          assert.equal(got.data.error, "not-found", JSON.stringify(got.data));
        } else {
          assert.equal((got.data.body as { fact?: string } | undefined)?.fact, fact);
        }
      }
      for (let i = 0; i < 50; i++) {
        const id = `n-h21-${i}`;
        const got = await getFact(services, id);
        assert.equal(got.isError, false, JSON.stringify(got.data));
        assert.equal((got.data.body as { fact?: string } | undefined)?.fact, `fact-h21-${i}`);
      }
    } finally {
      services.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("H22: a wrong VERAX_RECORD_PUBKEY_PIN refuses rehead and writes no head; the matching pin works", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-h22-"));
    const signers = loadOrCreateSigners(stateDir);
    const opts = {
      stateDir,
      policyFile,
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
    };
    const first = createBodyServices(opts);
    try {
      const seeded = await putFact(first, "n1", "fact-h22");
      assert.equal(seeded.isError, false, JSON.stringify(seeded.data));
      first.ledger.close();
      const headPath = memoryHeadPath(stateDir, resolveHeadDir(stateDir));
      rmSync(headPath);
      assert.equal(existsSync(headPath), false);

      let err = "";
      const refused = await withPin(testKeys().publicKeyPem, () =>
        runMemoryRehead(
          ["rehead", stateDir],
          { write() { return true; } },
          { write(s) { err += s; return true; } },
        ),
      );
      assert.equal(refused, 1, err);
      assert.match(err, /^memory-rehead-failed:record-pubkey-pin-mismatch\n$/);
      assert.equal(existsSync(headPath), false);

      let out = "";
      err = "";
      const code = await withPin(signers.recordSigner.publicKeyPem, () =>
        runMemoryRehead(
          ["rehead", stateDir],
          { write(s) { out += s; return true; } },
          { write(s) { err += s; return true; } },
        ),
      );
      assert.equal(code, 0, err);
      assert.match(out, /^1 [0-9a-f]{16}\n$/);
      assert.equal(existsSync(headPath), true);

      const opened = createBodyServices(opts);
      try {
        const got = await getFact(opened, "n1");
        assert.equal(got.isError, false, JSON.stringify(got.data));
        assert.equal((got.data.body as { fact?: string } | undefined)?.fact, "fact-h22");
      } finally {
        opened.ledger.close();
      }
    } finally {
      if (existsSync(join(stateDir, "ledger.lock"))) first.ledger.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });
});
