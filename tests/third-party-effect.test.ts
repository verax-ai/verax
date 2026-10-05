import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { generateEffectExtractKeys, signEffectExtract, type EffectExtractClaims, type SignedEffectExtract } from "@cedulon/effect-extract";
import { openDownstream, parseDownstreamJson } from "../packages/body/src/downstream.ts";
import { createBodyServices } from "../packages/body/src/wiring.ts";
import { listen } from "../packages/body/src/server.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { createProxy } from "../packages/proxy/src/proxy.ts";
import { MemoryLedger, signEffectAttestation } from "../packages/proxy/src/ledger.ts";
import { balancedSummary, explain, guaranteeWithConditions } from "../packages/proxy/src/explain.ts";
import { effectDescriptor, sha256Canonical } from "../packages/proxy/src/hash.ts";
import { loadPolicy } from "../packages/proxy/src/policy.ts";
import { verifyLedger } from "../packages/proxy/src/verify-ledger.ts";
import { thirdPartyReceiptCoversRow, thirdPartyReceiptRejection } from "../packages/proxy/src/third-party.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "../packages/proxy/tests/helpers.ts";
import { runGoldenScenario } from "../packages/proxy/tests/golden-scenario.ts";

const keys = generateEffectExtractKeys();
const other = generateEffectExtractKeys();
const principal = { brain: "test", scopes: new Set(["verax:read"]) };
const call = { name: "shop.lookup", arguments: { q: "hello" } };
const normal = { content: [{ type: "text" as const, text: "ok" }], isError: false };
const policyDoc = { version: 1, default: "deny", rules: [{ id: "lookup", tool: call.name, requires: ["verax:read"], text: "Read lookup." }] };
test("a balanced summary never echoes a failing audit summary", () => {
  // Cedulon's summary may count a finding the wrapper dropped (window-coverage without a checkpoint).
  assert.equal(balancedSummary("conditional", [], "audit: 1 finding(s) → FAIL"), "audit: balanced (conditional)");
  assert.equal(balancedSummary("conditional", [], "audit: conditional"), "audit: balanced (conditional)");
});
test("local conditions narrow even an unconditional upstream audit guarantee", () => {
  for (const upstream of ["conditional", "unconditional"] as const) {
    assert.equal(guaranteeWithConditions(upstream, []), upstream);
    for (const condition of ["self witness", "same-party witness", "third-party witness unpinned", "witness independence unstated", "inputs document missing"]) {
      assert.equal(guaranteeWithConditions(upstream, [condition]), "conditional", condition);
    }
  }
});
function receipt(ref = "tp", signer = keys, change?: (b: EffectExtractClaims) => void) {
  const body: EffectExtractClaims = { deciderId: "verax-proxy", channelId: "shop", windowStartMs: 100, windowEndMs: 101,
    effects: [{ ref, effectHash: sha256Canonical(effectDescriptor(call.name, call.arguments)), effectClass: call.name, timestampMs: 100 }] };
  change?.(body);
  return signEffectExtract(body, signer.privateKeyPem, signer.publicKeyPem);
}
async function memory(ex?: SignedEffectExtract) {
  const ledger = new MemoryLedger();
  const proxy = createProxy({ ledger, policy: loadPolicy(policyDoc), recordSigner: RECORD_SIGNER, effectSigner: EFFECT_SIGNER,
    now: () => 100, nonce: () => "tp", inner: async () => ({ ...normal, ...(ex ? { effectReceipt: ex } : {}) }) });
  const result = await proxy.call(call, principal);
  return { ledger, result };
}

test("receipt does not enter resultHash or the agent result", async () => {
  const plain = await memory();
  const signed = await memory(receipt());
  assert.equal((await signed.ledger.effects())[0]!.resultHash, (await plain.ledger.effects())[0]!.resultHash);
  assert.deepEqual(signed.result, plain.result);
});
test("memory ledger stores the exact external row and receipt without body attestation", async () => {
  const ex = receipt();
  const { ledger } = await memory(ex);
  const stored = (await ledger.effects())[0]!;
  assert.equal(stored.witnessClass, "third-party");
  assert.deepEqual(stored.row, ex.body.effects[0]);
  assert.deepEqual(stored.receipt, ex);
  assert.equal(stored.attestation, undefined);
});
test("a third-party row without an external receipt is never body-signed", async () => {
  const { ledger } = await memory();
  await ledger.appendEffect(receipt("external").body.effects[0]!, "third-party", "a".repeat(64));
  const stored = (await ledger.effects())[1]!;
  assert.equal(stored.receipt, undefined);
  assert.equal(stored.attestation, undefined);
});
test("receipt verification refuses missing data, invalid pins and signed extra rows", () => {
  const ex = receipt();
  assert.equal(thirdPartyReceiptCoversRow(undefined, ex.body.effects[0], keys.publicKeyPem), false);
  assert.equal(thirdPartyReceiptCoversRow(ex, ex.body.effects[0], "invalid"), false);
  assert.equal(thirdPartyReceiptCoversRow(receipt("tp", keys, b => b.effects.push({ ...b.effects[0]! })), ex.body.effects[0], keys.publicKeyPem), false);
  assert.equal(thirdPartyReceiptRejection(ex, keys.publicKeyPem, undefined, call.name, ex.body.effects[0]!.effectHash), "ref");
});
for (const field of ["ref", "effectHash", "effectClass", "count"] as const) {
  test(`proxy rejects receipt dispatch mismatch: ${field}`, async () => {
    const ex = receipt("tp", keys, b => { if (field === "count") b.effects.push({ ...b.effects[0]! }); else b.effects[0]![field] = field === "effectHash" ? "a".repeat(64) : "wrong"; });
    const { ledger, result } = await memory(ex);
    assert.equal((await ledger.effects())[0]!.witnessClass, "self");
    assert.equal((result as { effectReceipt?: unknown }).effectReceipt, undefined);
  });
}
test("same-org explain names same-party witness and stays conditional", async () => {
  const { ledger } = await memory();
  (await ledger.effects())[0]!.witnessClass = "same-org";
  const r = await explain(ledger, "tp", { issuerTrust: { publicKeyPem: RECORD_SIGNER.publicKeyPem } });
  assert.match(r.finding.summary, /same-party witness/);
  assert.equal(r.guarantee, "conditional");
});
test("golden scenario summaries never say unconditional while conditions exist", async () => {
  const ledger = await runGoldenScenario(mkdtempSync(join(tmpdir(), "tp-golden-")));
  try {
    for (const d of await ledger.decisions()) for (const source of [undefined, "own-key"] as const) {
      const r = await explain(ledger, d.claims.ref!, { issuerTrust: { publicKeyPem: RECORD_SIGNER.publicKeyPem, source } });
      if (r.finding.label === "conditional") {
        assert.equal(r.guarantee, "conditional");
        assert.doesNotMatch(r.finding.summary, /unconditional/);
      }
    }
  } finally { ledger.close(); }
});
for (const variant of ["valid", "missing", "independence", "issuer", "wrong-key", "tampered", "empty-party"] as const) {
  test(`explain third-party trust: ${variant}`, async () => {
    const ex = receipt("tp", variant === "issuer" ? RECORD_SIGNER : keys);
    const { ledger } = await memory(ex);
    // Isolate explain from proxy implementation on the initial red run.
    Object.assign((await ledger.effects())[0]!, { row: ex.body.effects[0], receipt: ex, witnessClass: "third-party", attestation: undefined });
    if (variant === "tampered") ex.signature = "bad";
    const r = await explain(ledger, "tp", { issuerTrust: { publicKeyPem: RECORD_SIGNER.publicKeyPem },
      ...(variant === "missing" ? {} : { thirdPartyTrust: { publicKeyPem: variant === "wrong-key" ? other.publicKeyPem : ex.publicKeyPem,
        party: variant === "empty-party" ? "" : "Shop operator", independent: variant !== "independence" } }) });
    if (variant === "valid") {
      assert.doesNotMatch(r.finding.summary, /witness|extract unpinned/);
      assert.ok(!r.warnings.some(w => w.code === "unauthenticated-extract"));
      // A one-row receipt does not state the period or path it covers, so completeness stays conditional,
      // and the summary names why instead of echoing the audit's raw text.
      assert.equal(r.guarantee, "conditional");
      assert.match(r.finding.summary, /^audit: balanced \(conditional: .*audit window unstated.*audit scope unstated/);
      assert.doesNotMatch(r.finding.summary, /FAIL|finding\(s\)/);
    } else {
      assert.equal(r.guarantee, "conditional");
      const reason = variant === "issuer" ? "same-party witness" : variant === "independence" || variant === "empty-party" ? "witness independence unstated" : "third-party witness unpinned";
      assert.match(r.finding.summary, new RegExp(reason));
      assert.doesNotMatch(r.finding.summary, /unconditional/);
    }
  });
}

type Variant = "valid" | "wrong-key" | "wrong-ref" | "wrong-class" | "wrong-hash" | "two-rows" | "wrong-start" | "wrong-end" | "wrong-decider" | "missing" | "malformed";
async function downstream(variant: Variant, fn: (ctx: { services: ReturnType<typeof createBodyServices>; ex: () => SignedEffectExtract | undefined; meta: () => unknown; dir: string }) => Promise<void>) {
  let ex: SignedEffectExtract | undefined;
  let meta: unknown;
  const http = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString();
    const server = new Server({ name: "fake-shop", version: "1" }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "lookup", inputSchema: { type: "object" } }] }));
    server.setRequestHandler(CallToolRequestSchema, async req => {
      meta = req.params._meta?.["io.cedulon/decision"];
      const decision = meta as { ref?: string } | undefined;
      ex = receipt(decision?.ref ?? "tp", variant === "wrong-key" ? other : keys, b => {
        b.effects[0]!.effectHash = sha256Canonical({ tool: `shop.${req.params.name}`, arguments: req.params.arguments });
        if (variant === "wrong-ref") b.effects[0]!.ref = "wrong";
        if (variant === "wrong-class") b.effects[0]!.effectClass = "shop.other";
        if (variant === "wrong-hash") b.effects[0]!.effectHash = "a".repeat(64);
        if (variant === "two-rows") b.effects.push({ ...b.effects[0]! });
        if (variant === "wrong-start") b.windowStartMs = 99;
        if (variant === "wrong-end") b.windowEndMs = 102;
        if (variant === "wrong-decider") b.deciderId = "another-proxy";
      });
      return { ...normal, ...(variant === "missing" ? {} : { _meta: { "io.cedulon/effect-extract": variant === "malformed" ? { body: null } : ex } }) };
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    try { await transport.handleRequest(req, res, body ? JSON.parse(body) : undefined); }
    finally { await transport.close(); await server.close(); }
  });
  await new Promise<void>(r => http.listen(0, "127.0.0.1", r));
  const dir = mkdtempSync(join(tmpdir(), "tp-body-"));
  const policyFile = join(dir, "policy.json");
  writeFileSync(policyFile, JSON.stringify(policyDoc));
  const spec = parseDownstreamJson(JSON.stringify({ prefix: "shop", url: `http://127.0.0.1:${(http.address() as { port: number }).port}/mcp`, effectKeyPem: keys.publicKeyPem }));
  const session = await openDownstream(spec);
  const services = createBodyServices({ stateDir: dir, policyFile, recordSigner: RECORD_SIGNER, effectSigner: EFFECT_SIGNER, extraTools: session.tools, now: () => 100, nonce: () => "tp" });
  try { await fn({ services, ex: () => ex, meta: () => meta, dir }); }
  finally { services.ledger.close(); await session.close(); await new Promise<void>(r => http.close(() => r())); }
}
test("downstream receipt survives body, file ledger and repeatable CLI pins", async () => {
  await downstream("valid", async ({ services, ex, meta, dir }) => {
    services.ledger.remoteWitness = async () => { throw new Error("third-party must bypass the body witness"); };
    const result = await services.proxy.call(call, principal);
    assert.deepEqual(meta(), { ref: "tp", deciderId: "verax-proxy", prefix: "shop" });
    assert.equal(result.isError, false);
    assert.equal((result as { effectReceipt?: unknown }).effectReceipt, undefined);
    const stored = (await services.ledger.effects())[0]!;
    assert.equal(stored.witnessClass, "third-party");
    assert.deepEqual(stored.row, ex()!.body.effects[0]);
    assert.deepEqual(stored.receipt, ex());
    assert.equal(stored.attestation, undefined);
    const opts = { publicKeyPem: RECORD_SIGNER.publicKeyPem, thirdPartyPublicKeyPems: [keys.publicKeyPem] };
    assert.equal((await verifyLedger(dir, opts)).effectsBound, 1);
    const unpinned = await verifyLedger(dir);
    assert.equal(unpinned.effectsBound, 0);
    assert.ok(unpinned.problems.includes("third-party row tp unchecked: no pinned third-party key"));
    assert.equal((await verifyLedger(dir, { thirdPartyPublicKeyPems: [other.publicKeyPem] })).effectsBound, 0);
    writeFileSync(join(dir, "third.pem"), keys.publicKeyPem);
    writeFileSync(join(dir, "other.pem"), other.publicKeyPem);
    let output = "";
    assert.equal(await runVerify([dir, "--third-party-key", join(dir, "other.pem"), "--third-party-key", join(dir, "third.pem"), "--json"], s => { output = s; }), 0);
    assert.equal(JSON.parse(output).effectsBound, 1);
    const disk = join(dir, "effects.jsonl");
    const original = readFileSync(disk, "utf8");
    const resultChanged = JSON.parse(original);
    resultChanged.resultHash = "b".repeat(64);
    writeFileSync(disk, JSON.stringify(resultChanged) + "\n");
    assert.equal((await verifyLedger(dir, opts)).effectsBound, 1, "resultHash is explicitly unattested");
    for (const field of ["timestampMs", "actor", "effectClass", "effectHash", "ref"]) {
      const altered = JSON.parse(original);
      altered.row[field] = field === "timestampMs" ? 999 : "tampered";
      writeFileSync(disk, JSON.stringify(altered) + "\n");
      assert.equal((await verifyLedger(dir, opts)).effectsBound, 0, field);
    }
    writeFileSync(disk, original);
    for (const variant of ["ref", "effectHash", "thrown-hash", "two-rows", "signature", "duplicate"] as const) {
      const altered = JSON.parse(original);
      altered.receipt = receipt("tp", keys, b => {
        if (variant === "ref") b.effects[0]!.ref = "orphan";
        if (variant === "effectHash" || variant === "thrown-hash") b.effects[0]!.effectHash = "a".repeat(64);
        if (variant === "thrown-hash") b.effects[0]!.effectClass += ":threw";
        if (variant === "two-rows") b.effects.push({ ...b.effects[0]! });
        if (variant === "duplicate") {
          b.effects[0]!.effectClass = "duplicate-effect";
          b.effects[0]!.effectHash = sha256Canonical({ refused: "duplicate-effect", ref: "tp" });
        }
      });
      altered.row = altered.receipt.body.effects[0];
      if (variant === "signature") altered.receipt.signature = "invalid";
      writeFileSync(disk, JSON.stringify(altered) + "\n");
      assert.equal((await verifyLedger(dir, opts)).effectsBound, 0, variant);
    }
    for (const [role, signer] of [["record", RECORD_SIGNER], ["effect", EFFECT_SIGNER], ["witness", other]] as const) {
      const altered = JSON.parse(original);
      altered.receipt = receipt("tp", signer);
      writeFileSync(disk, JSON.stringify(altered) + "\n");
      const r = await verifyLedger(dir, { ...opts, effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem, witnessPublicKeyPem: other.publicKeyPem, thirdPartyPublicKeyPems: [signer.publicKeyPem.replace(/\n/g, "\r\n")] });
      assert.equal(r.effectsBound, 0, role);
      assert.ok(r.problems.some(p => p.includes("third-party key") && p.includes(role)), r.problems.join("\n"));
    }
    const duplicate = receipt("tp", EFFECT_SIGNER, b => {
      b.effects[0]!.effectClass = "duplicate-effect";
      b.effects[0]!.effectHash = sha256Canonical({ refused: "duplicate-effect", ref: "tp" });
    });
    const duplicateRow = duplicate.body.effects[0]!;
    writeFileSync(disk, JSON.stringify({ row: duplicateRow, witnessClass: "third-party",
      ...signEffectAttestation(duplicateRow, "third-party", undefined, EFFECT_SIGNER) }) + "\n");
    assert.equal((await verifyLedger(dir, { ...opts, effectPublicKeyPem: EFFECT_SIGNER.publicKeyPem })).effectsBound, 0,
      "a duplicate-refusal path must not authenticate third-party rows under body keys");
  });
});
for (const variant of ["wrong-key", "wrong-ref", "wrong-class", "wrong-hash", "two-rows", "wrong-start", "wrong-end", "wrong-decider", "missing", "malformed"] as const) {
  test(`adapter rejects ${variant} with one stderr line and self fallback`, async () => {
    await downstream(variant, async ({ services }) => {
      const lines: string[] = [];
      const original = process.stderr.write;
      process.stderr.write = ((s: string | Uint8Array) => { lines.push(s.toString()); return true; }) as typeof process.stderr.write;
      try {
        assert.equal((await services.proxy.call(call, principal)).isError, false);
        assert.equal((await services.ledger.effects())[0]!.witnessClass, "self");
      } finally { process.stderr.write = original; }
      assert.equal(lines.length, 1, lines.join(""));
      assert.match(lines[0]!, /^verax-body: third-party receipt rejected: [^\r\n]+\n$/);
    });
  });
}
test("config requires an Ed25519 SPKI public key", () => {
  for (const bad of [12, "", "bad", keys.privateKeyPem, generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ type: "spki", format: "pem" }).toString()]) {
    assert.throws(() => parseDownstreamJson(JSON.stringify({ prefix: "shop", url: "http://localhost/mcp", effectKeyPem: bad })), /downstream-effect-key-invalid/);
  }
  assert.equal(parseDownstreamJson(JSON.stringify({ prefix: "shop", url: "http://localhost/mcp", effectKeyPem: keys.publicKeyPem })).effectKeyPem, keys.publicKeyPem);
});
test("openDownstream validates programmatic key configuration before connecting", async () => {
  await assert.rejects(openDownstream({ prefix: "shop", url: "http://localhost:1/mcp", effectKeyPem: "bad" }), /downstream-effect-key-invalid/);
});
for (const role of ["record", "effect", "witness"] as const) {
  test(`body config rejects its ${role} key as a downstream signer before attaching`, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "tp-config-"));
    const signers = loadOrCreateSigners(stateDir);
    writeFileSync(join(stateDir, "keys", "witness.public.pem"), other.publicKeyPem);
    const publicKeyPem = role === "record" ? signers.recordSigner.publicKeyPem : role === "effect" ? signers.effectSigner.publicKeyPem : other.publicKeyPem;
    const downstreamFile = join(stateDir, "downstream.json");
    writeFileSync(downstreamFile, JSON.stringify({ prefix: "shop", url: "http://localhost:1/mcp", effectKeyPem: publicKeyPem.replace(/\n/g, "\r\n") }));
    await assert.rejects(listen({ stateDir, downstreamFile, policyFile: join(stateDir, "unused.json"),
      issuer: "http://localhost", jwksUrl: "http://localhost/jwks", audience: "test", bindHost: "127.0.0.1", bindPort: 0, tlsTerminated: false }), /downstream-effect-key-not-independent:shop/);
  });
}
