import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { coseFromHex, verifyCoseSign1 } from "@cedulon/cose";

import { createBodyServices } from "../packages/body/src/wiring.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const keysSrc = join(root, "packages", "body", "src", "keys.ts");
const policyFile = join(root, "packages", "proxy", "policy", "default.json");

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function lastStatus(dir: string): { result?: string; reason?: string } {
  const path = join(dir, "witness-status.jsonl");
  if (!existsSync(path)) return {};
  const lines = readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter((l) => l !== "");
  return JSON.parse(lines[lines.length - 1] ?? "{}") as { result?: string; reason?: string };
}

async function waitFile(path: string, ms = 5000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (existsSync(path)) return;
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

describe("independent witness process", () => {
  it("an effect signed by verax witness fails the body key and verifies with the witness key", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-witness-ok-"));
    const body = testKeys();
    const child = spawnWitness(dir);
    const listenPath = join(dir, "witness.listen.json");
    try {
      await waitFile(listenPath);
      const listen = JSON.parse(readFileSync(listenPath, "utf8")) as { publicKeyPem?: string; pid?: number };
      assert.equal(typeof listen.publicKeyPem, "string");
      assert.notEqual(listen.publicKeyPem, body.publicKeyPem);
      assert.equal(existsSync(join(dir, "keys", "witness.private.pem")), true);
      const services = createBodyServices({
        stateDir: dir,
        policyFile,
        recordSigner: body,
        effectSigner: body,
        now: () => 1_700,
        nonce: () => "wit-1",
      });
      try {
        const allowed = await services.proxy.call(
          {
            name: "memory.put",
            arguments: {
              id: "note-1",
              body: { t: 1 },
              source: { uri: "file://t", retrievedAtMs: 1 },
              validUntilMs: 9_999,
            },
          },
          { brain: "brain-1", scopes: new Set(["verax:memory"]) },
        );
        assert.equal(allowed.isError, false);
        const effects = await services.ledger.effects();
        const effect = effects.find((e) => e.row.ref === "wit-1");
        assert.ok(effect, "missing effect");
        assert.equal(effect.witnessClass, "same-org");
        const cose = coseFromHex(effect.attestation?.coseHex ?? "");
        assert.equal(verifyCoseSign1(cose, listen.publicKeyPem!, "application/json"), true, "witness key must verify");
        assert.equal(verifyCoseSign1(cose, body.publicKeyPem, "application/json"), false, "body key must not verify");
        assert.equal(lastStatus(dir).result, "signed");
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

  it("without a witness process the effect stays self and the fallback is recorded", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-witness-none-"));
    const body = testKeys();
    const services = createBodyServices({
      stateDir: dir,
      policyFile,
      recordSigner: body,
      effectSigner: body,
      now: () => 1_800,
      nonce: () => "self-1",
    });
    try {
      const allowed = await services.proxy.call(
        {
          name: "memory.put",
          arguments: {
            id: "note-2",
            body: { t: 2 },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: 9_999,
          },
        },
        { brain: "brain-1", scopes: new Set(["verax:memory"]) },
      );
      assert.equal(allowed.isError, false);
      const effects = await services.ledger.effects();
      const effect = effects.find((e) => e.row.ref === "self-1");
      assert.ok(effect, "missing effect");
      assert.equal(effect.witnessClass, "self");
      const cose = coseFromHex(effect.attestation?.coseHex ?? "");
      assert.equal(verifyCoseSign1(cose, body.publicKeyPem, "application/json"), true);
      const status = lastStatus(dir);
      assert.equal(status.result, "self-fallback");
      assert.equal(status.reason, "unreachable");
    } finally {
      services.ledger.close();
    }
  });

  it("the body key loader never names the witness private file", () => {
    const src = readFileSync(keysSrc, "utf8");
    assert.equal(src.includes("witness.private.pem"), false);
    assert.equal(src.includes("effect.private.pem"), true);
  });
});
