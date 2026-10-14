import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { canonical } from "@cedulon/core";
import { sha256Canonical } from "@verax-ai/proxy";

import { copyDefinition } from "../packages/body/src/definitions.ts";
import { readStartSummary, recordBodyStart } from "../packages/body/src/heartbeat.ts";

/**
 * The definitions a start ran with are kept where the body keeps its record.
 * The manifest the operator pinned is copied into the state directory before
 * the start row names it, the start row carries its digest under the record
 * key's signature, and reading the starts back checks that each named
 * manifest is there and is the one named.
 */

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function temp(): string {
  const d = mkdtempSync(join(tmpdir(), "verax-pins-record-"));
  dirs.push(d);
  return d;
}

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

const manifest = {
  v: 1,
  prefix: "rea",
  selected: null,
  tools: { a: { name: "a", description: "reads a", inputSchema: { type: "object" } } },
};
const digest = sha256Canonical(manifest);

/** The operator's side: a document folder with the pinned manifest in it. */
function pinnedFolder(): string {
  const dir = temp();
  mkdirSync(join(dir, "definitions"));
  writeFileSync(join(dir, "definitions", `${digest}.json`), canonical(manifest), "utf8");
  return dir;
}

describe("pinned definitions in the record", () => {
  it("are copied into the state directory once, byte for byte", () => {
    const state = temp();
    const docs = pinnedFolder();
    copyDefinition(state, docs, digest);
    copyDefinition(state, docs, digest);
    assert.equal(readFileSync(join(state, "definitions", `${digest}.json`), "utf8"), canonical(manifest));
  });

  it("a different file already under the same name stops the copy", () => {
    const state = temp();
    const docs = pinnedFolder();
    mkdirSync(join(state, "definitions"));
    writeFileSync(join(state, "definitions", `${digest}.json`), "{}", "utf8");
    assert.throws(() => copyDefinition(state, docs, digest), /downstream-manifest-conflict:/);
  });

  it("a source manifest that is not the named digest is not copied", () => {
    const state = temp();
    const docs = pinnedFolder();
    writeFileSync(join(docs, "definitions", `${digest}.json`), canonical({ ...manifest, v: 2 }), "utf8");
    assert.throws(() => copyDefinition(state, docs, digest), /downstream-manifest-invalid:/);
  });

  it("a signed start row names the manifests and still verifies", () => {
    const state = temp();
    const k = keys();
    copyDefinition(state, pinnedFolder(), digest);
    recordBodyStart(state, 1_000, k, { downstream: [{ prefix: "rea", manifest: digest }, { prefix: "tug", manifest: null }] });
    const row = JSON.parse(readFileSync(join(state, "starts.jsonl"), "utf8").trim()) as { downstream?: unknown };
    assert.deepEqual(row.downstream, [{ prefix: "rea", manifest: digest }, { prefix: "tug", manifest: null }]);
    const summary = readStartSummary(state, k.publicKeyPem, "pinned");
    assert.deepEqual(summary.problems, []);
    assert.equal(summary.signedVerified, 1);
  });

  it("a start row with no children carries no field and verifies as before", () => {
    const state = temp();
    const k = keys();
    recordBodyStart(state, 1_000, k);
    const row = JSON.parse(readFileSync(join(state, "starts.jsonl"), "utf8").trim()) as Record<string, unknown>;
    assert.equal(Object.hasOwn(row, "downstream"), false);
    assert.deepEqual(readStartSummary(state, k.publicKeyPem, "pinned").problems, []);
  });

  it("a manifest digest changed in a signed row breaks its signature", () => {
    const state = temp();
    const k = keys();
    copyDefinition(state, pinnedFolder(), digest);
    recordBodyStart(state, 1_000, k, { downstream: [{ prefix: "rea", manifest: digest }] });
    const path = join(state, "starts.jsonl");
    writeFileSync(path, readFileSync(path, "utf8").replace(digest, "f".repeat(64)), "utf8");
    const summary = readStartSummary(state, k.publicKeyPem, "pinned");
    assert.ok(summary.problems.some((p) => p.startsWith("start signature does not verify")), JSON.stringify(summary));
  });

  it("a named manifest missing from the state directory is named", () => {
    const state = temp();
    const k = keys();
    recordBodyStart(state, 1_000, k, { downstream: [{ prefix: "rea", manifest: digest }] });
    const summary = readStartSummary(state, k.publicKeyPem, "pinned");
    assert.ok(summary.problems.some((p) => p.startsWith(`downstream-manifest-missing:rea:${digest}`)), JSON.stringify(summary));
  });

  it("a named manifest edited in the state directory is named", () => {
    const state = temp();
    const k = keys();
    copyDefinition(state, pinnedFolder(), digest);
    recordBodyStart(state, 1_000, k, { downstream: [{ prefix: "rea", manifest: digest }] });
    writeFileSync(join(state, "definitions", `${digest}.json`), canonical({ ...manifest, prefix: "other" }), "utf8");
    const summary = readStartSummary(state, k.publicKeyPem, "pinned");
    assert.ok(summary.problems.some((p) => p.startsWith(`downstream-manifest-invalid:rea:${digest}`)), JSON.stringify(summary));
  });
});
