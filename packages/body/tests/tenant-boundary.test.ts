import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { explain, tenantKey } from "@verax-ai/proxy";

import { runDoctor } from "../src/doctor.ts";
import { createBodyServices } from "../src/wiring.ts";

const policyFile = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "proxy",
  "policy",
  "default.json",
);

function testKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function parse(result: { content: { text: string }[] }): Record<string, unknown> {
  return JSON.parse(result.content[0]?.text ?? "{}") as Record<string, unknown>;
}

const writerA = {
  brain: "alice",
  scopes: new Set(["verax:memory", "verax:read"]),
  iss: "https://issuer-a.example",
};
const writerB = {
  brain: "bob",
  scopes: new Set(["verax:memory", "verax:read"]),
  iss: "https://issuer-b.example",
};
const readerB = {
  brain: "bob",
  scopes: new Set(["verax:read"]),
  iss: "https://issuer-b.example",
};

const putArgs = {
  id: "note-1",
  body: { secret: "alice-only" },
  source: { uri: "file://t", retrievedAtMs: 1 },
  validUntilMs: 9_999_999,
};

describe("S4 tenant boundary", () => {
  it("same aud, different iss and sub: B cannot read A's put (tenant-mismatch, signed, no body)", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-tenant-accept-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      const put = await services.proxy.call(
        { name: "memory.put", arguments: putArgs },
        writerA,
      );
      assert.equal(put.isError, false, parse(put).error as string);

      const got = await services.proxy.call(
        { name: "memory.get", arguments: { id: "note-1" } },
        readerB,
      );
      assert.equal(got.isError, true);
      assert.match(got.content[0]?.text ?? "", /denied:tenant-mismatch:/);
      assert.equal(JSON.stringify(got).includes("alice-only"), false);

      const recs = await services.ledger.decisions();
      const mismatch = recs.filter((d) => d.claims.reasonCode === "tenant-mismatch");
      assert.equal(mismatch.length, 1);
      assert.equal(mismatch[0]!.claims.decision, "deny");
      assert.equal(typeof mismatch[0]!.coseHex, "string");
      assert.equal(mismatch[0]!.claims.effectHash, null);

      const aDir = join(stateDir, "tenants", tenantKey(writerA), "memory");
      const bDir = join(stateDir, "tenants", tenantKey(writerB), "memory");
      assert.equal(existsSync(join(aDir, "note-1.json")), true);
      assert.equal(existsSync(join(stateDir, "memory", "note-1.json")), false);
      assert.equal(existsSync(join(bDir, "note-1.json")), false);
    } finally {
      services.ledger.close();
    }
  });

  it("does not silently merge a legacy flat memory/ directory", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-tenant-legacy-"));
    mkdirSync(join(stateDir, "memory"), { recursive: true });
    writeFileSync(
      join(stateDir, "memory", "note-1.json"),
      `${JSON.stringify({
        id: "note-1",
        body: { secret: "legacy" },
        source: { kind: "t" },
        validFromMs: 0,
        validUntilMs: 9_999_999,
        versionHash: "00".repeat(32),
      })}\n`,
      "utf8",
    );
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      const got = await services.proxy.call(
        { name: "memory.get", arguments: { id: "note-1" } },
        readerB,
      );
      const text = got.content[0]?.text ?? "";
      assert.equal(JSON.stringify(got).includes("legacy"), false);
      assert.equal(text.includes("legacy"), false);
      const parsed = (() => {
        try {
          return JSON.parse(text) as Record<string, unknown>;
        } catch {
          return {};
        }
      })();
      assert.notEqual(parsed.body !== undefined && parsed.id === "note-1", true);
    } finally {
      services.ledger.close();
    }
  });

  it("verax doctor warns when legacy memory/ is present", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-tenant-doctor-"));
    mkdirSync(join(stateDir, "memory"), { recursive: true });
    const checks = runDoctor(
      {
        VERAX_ISSUER: "http://127.0.0.1:8790",
        VERAX_JWKS_URL: "http://127.0.0.1:8790/.well-known/jwks.json",
        VERAX_AUDIENCE: "http://127.0.0.1:8787",
        VERAX_STATE_DIR: stateDir,
        VERAX_POLICY_FILE: "x",
      },
      ["node", "cli.ts", "doctor"],
    );
    const legacy = checks.find((c) => c.id === "legacy-memory");
    assert.equal(legacy?.level, "warn");
    assert.match(legacy?.detail ?? "", /tenants\//);
  });
});

describe("S4 _ref namespace", () => {
  it("one tenant cannot close another's _ref", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-tenant-ref-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      const first = await services.proxy.call(
        { name: "memory.put", arguments: { ...putArgs, body: { who: "a" }, _ref: "shared" } },
        writerA,
      );
      assert.equal(first.isError, false);
      const second = await services.proxy.call(
        {
          name: "memory.put",
          arguments: { ...putArgs, body: { who: "b" }, source: { kind: "t" }, _ref: "shared" },
        },
        writerB,
      );
      assert.equal(second.isError, false, second.content[0]?.text);
      const recs = await services.ledger.decisions();
      assert.equal(recs.some((d) => d.claims.reasonCode === "ref-reuse"), false);
      assert.equal(recs.filter((d) => d.claims.decision === "allow").length, 2);
      const aFile = JSON.parse(
        readFileSync(join(stateDir, "tenants", tenantKey(writerA), "memory", "note-1.json"), "utf8"),
      ) as { body: { who?: string } };
      const bFile = JSON.parse(
        readFileSync(join(stateDir, "tenants", tenantKey(writerB), "memory", "note-1.json"), "utf8"),
      ) as { body: { who?: string } };
      assert.equal(aFile.body.who, "a");
      assert.equal(bFile.body.who, "b");
    } finally {
      services.ledger.close();
    }
  });
});

function brainPrefix(text: string): string {
  return text.replace(/:[^:]*$/, "");
}

describe("S5 A1 audit.explain tenant close", () => {
  it("another tenant's ref is deny tenant-mismatch, signed, no record body", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-s5-explain-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      const put = await services.proxy.call(
        { name: "memory.put", arguments: { ...putArgs, _ref: "invoice-1" } },
        writerA,
      );
      assert.equal(put.isError, false, parse(put).error as string);
      const aliceRef = `${tenantKey(writerA)}:invoice-1`;

      const got = await services.proxy.call(
        { name: "audit.explain", arguments: { ref: aliceRef } },
        readerB,
      );
      assert.equal(got.isError, true);
      assert.match(got.content[0]?.text ?? "", /denied:tenant-mismatch:/);
      assert.equal(JSON.stringify(got).includes("\"record\""), false);
      assert.equal(JSON.stringify(got).includes("effectHash"), false);

      const recs = await services.ledger.decisions();
      const mismatch = recs.filter((d) => d.claims.reasonCode === "tenant-mismatch");
      assert.ok(mismatch.length >= 1);
      const explainDeny = mismatch.find((d) => d.claims.subject === "audit.explain");
      assert.ok(explainDeny);
      assert.equal(explainDeny.claims.decision, "deny");
      assert.equal(typeof explainDeny.coseHex, "string");
      assert.equal(explainDeny.claims.effectHash, null);
    } finally {
      services.ledger.close();
    }
  });

  it("nonce refs (no _ref prefix) still close via the inputs principal", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-s5-nonce-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
      nonce: (() => {
        const q = ["nonce-record-1"];
        let n = 0;
        return () => q.shift() ?? `n-${++n}`;
      })(),
    });
    try {
      const put = await services.proxy.call(
        { name: "memory.put", arguments: putArgs },
        writerA,
      );
      assert.equal(put.isError, false);
      const recs = await services.ledger.decisions();
      const aliceRef = recs[0]!.claims.ref;
      assert.equal(aliceRef, "nonce-record-1");
      assert.equal(aliceRef.includes(":"), false);

      const cross = await services.proxy.call(
        { name: "audit.explain", arguments: { ref: aliceRef } },
        readerB,
      );
      assert.equal(cross.isError, true);
      assert.match(cross.content[0]?.text ?? "", /denied:tenant-mismatch:/);

      const own = await services.proxy.call(
        { name: "audit.explain", arguments: { ref: aliceRef } },
        writerA,
      );
      assert.equal(own.isError, false);
      const body = parse(own);
      assert.equal(typeof body.record, "object");
    } finally {
      services.ledger.close();
    }
  });

  it("operator explain() still reads any ref (panel path is not the tool)", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-s5-op-explain-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      await services.proxy.call(
        { name: "memory.put", arguments: { ...putArgs, _ref: "invoice-1" } },
        writerA,
      );
      const aliceRef = `${tenantKey(writerA)}:invoice-1`;
      const result = await explain(services.ledger, aliceRef, await services.explainOpts());
      assert.equal(result.record.claims.ref, aliceRef);
      assert.equal(result.record.claims.decision, "allow");
    } finally {
      services.ledger.close();
    }
  });
});

describe("S5 A2 uniform brain answer", () => {
  it("another tenant's id and a missing id look the same to the brain; the ledger rows differ", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-s5-oracle-"));
    const keys = testKeys();
    const services = createBodyServices({
      stateDir,
      policyFile,
      recordSigner: keys,
      effectSigner: keys,
    });
    try {
      await services.proxy.call({ name: "memory.put", arguments: putArgs }, writerA);

      const other = await services.proxy.call(
        { name: "memory.get", arguments: { id: "note-1" } },
        readerB,
      );
      const missing = await services.proxy.call(
        { name: "memory.get", arguments: { id: "note-404" } },
        readerB,
      );
      const otherText = other.content[0]?.text ?? "";
      const missingText = missing.content[0]?.text ?? "";
      assert.match(otherText, /denied:tenant-mismatch:/);
      assert.equal(brainPrefix(otherText), brainPrefix(missingText));
      assert.equal(JSON.stringify(other).includes("alice-only"), false);

      const recs = await services.ledger.decisions();
      const getRows = recs.filter((d) => d.claims.subject === "memory.get");
      const codes = new Set(getRows.map((d) => d.claims.reasonCode));
      assert.equal(codes.has("tenant-mismatch"), true);
      assert.equal(codes.size >= 2, true, `ledger codes=${[...codes].join(",")}`);
    } finally {
      services.ledger.close();
    }
  });
});
