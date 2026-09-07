import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createBodyServices } from "../src/wiring.ts";
import { runDoctor } from "../src/doctor.ts";

const policyFile = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "proxy", "policy", "default.json");

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function envFor(dir: string): NodeJS.ProcessEnv {
  return {
    VERAX_ISSUER: "http://127.0.0.1:8790",
    VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
    VERAX_AUDIENCE: "http://127.0.0.1:8787",
    VERAX_STATE_DIR: dir,
    VERAX_POLICY_FILE: policyFile,
    VERAX_HEARTBEAT_MAX_MS: "60000",
  };
}

async function putOnce(dir: string, ref: string) {
  const keys = testKeys();
  const services = createBodyServices({
    stateDir: dir,
    policyFile,
    recordSigner: keys,
    effectSigner: keys,
    now: () => 9_000,
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
  services.ledger.close();
}

describe("evidence copy and heartbeat", () => {
  it("mirrors the decision line and doctor sees a live heartbeat", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-copy-ok-"));
    await putOnce(dir, "copy-1");
    assert.equal(existsSync(join(dir, "evidence-copy", "decisions.jsonl")), true);
    const src = readFileSync(join(dir, "decisions.jsonl"), "utf8");
    const copy = readFileSync(join(dir, "evidence-copy", "decisions.jsonl"), "utf8");
    assert.equal(copy, src);
    const hb = JSON.parse(readFileSync(join(dir, "heartbeat.json"), "utf8")) as {
      lastDecisionN?: number;
    };
    assert.equal(hb.lastDecisionN, 1);
    const checks = runDoctor(envFor(dir), ["node", "cli.ts", "doctor"]);
    const pulse = checks.find((c) => c.id === "heartbeat");
    assert.equal(pulse?.level, "ok");
    const mirror = checks.find((c) => c.id === "evidence-copy");
    assert.equal(mirror?.level, "ok");
  });

  it("a stale heartbeat is spoken as silent by verax doctor", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-copy-silent-"));
    await putOnce(dir, "copy-2");
    writeFileSync(
      join(dir, "heartbeat.json"),
      `${JSON.stringify({ atMs: 1, pid: 1, lastDecisionN: 1, lastEffectN: 1 })}\n`,
      { encoding: "utf8" },
    );
    const checks = runDoctor({ ...envFor(dir), VERAX_HEARTBEAT_MAX_MS: "50" }, ["node", "cli.ts", "doctor"]);
    const pulse = checks.find((c) => c.id === "heartbeat");
    assert.equal(pulse?.level, "fail");
    assert.match(pulse?.detail ?? "", /silent/);
  });

  it("a short or corrupt copy is visible", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-copy-lag-"));
    await putOnce(dir, "copy-3");
    writeFileSync(join(dir, "evidence-copy", "decisions.jsonl"), "", { encoding: "utf8" });
    const lag = runDoctor(envFor(dir), ["node", "cli.ts", "doctor"]).find((c) => c.id === "evidence-copy");
    assert.equal(lag?.level, "fail");
    assert.match(lag?.detail ?? "", /stale|behind|short/);
    writeFileSync(join(dir, "evidence-copy", "decisions.jsonl"), "{not-json\n", { encoding: "utf8" });
    const bad = runDoctor(envFor(dir), ["node", "cli.ts", "doctor"]).find((c) => c.id === "evidence-copy");
    assert.equal(bad?.level, "fail");
    assert.match(bad?.detail ?? "", /corrupt/);
  });

  it("an effects copy that falls behind is visible too, not only decisions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-copy-effects-"));
    await putOnce(dir, "copy-4");
    // Half the evidence is the effect rows; a mirror that drops them silently is
    // the same silence this section exists to break.
    writeFileSync(join(dir, "evidence-copy", "effects.jsonl"), "", { encoding: "utf8" });
    const lag = runDoctor(envFor(dir), ["node", "cli.ts", "doctor"]).find((c) => c.id === "evidence-copy");
    assert.equal(lag?.level, "fail", JSON.stringify(lag));
    assert.match(lag?.detail ?? "", /effect/);

    writeFileSync(join(dir, "evidence-copy", "effects.jsonl"), "{not-json\n", { encoding: "utf8" });
    const bad2 = runDoctor(envFor(dir), ["node", "cli.ts", "doctor"]).find((c) => c.id === "evidence-copy");
    assert.equal(bad2?.level, "fail");
    assert.match(bad2?.detail ?? "", /corrupt/);
  });
});
