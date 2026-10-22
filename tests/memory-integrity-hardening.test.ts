import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger } from "@verax-ai/proxy";

import { runApprove } from "../packages/body/src/approve-cli.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
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
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.VERAX_RECORD_PUBKEY_PIN;
    else process.env.VERAX_RECORD_PUBKEY_PIN = prev;
  }
}

describe("memory integrity hardening (H1-H9)", () => {
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
});
