import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { verifyDecisionRecord } from "@cedulon/core";

import { approvePending } from "../src/approvals.ts";
import { sha256Canonical } from "../src/hash.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { diskProbe } from "../src/disk.ts";
import { FileLedger, MemoryLedger } from "../src/ledger.ts";
import type { Principal, ToolCall } from "../src/types.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

// Data classes v1 (docs/design/data-classes.md): per class of data the operator
// chooses allow, mask, local or block. Masked values never reach the tool, and
// the signed decision says what was taken out, by count, never by value.

const TCKN = "10000000146";
const EMAIL = "ayse.yilmaz@example.com";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";

const P: Principal = { brain: "brain-1", scopes: new Set(["verax:memory", "verax:read"]) };

function policyV2(extra: Record<string, unknown> = {}, ruleExtra: Record<string, unknown> = {}) {
  return loadPolicy(
    JSON.stringify({
      version: 2,
      default: "deny",
      dataClasses: { email: "mask", tckn: "block", iban: "mask" },
      ...extra,
      rules: [
        { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope.", ...ruleExtra },
        { id: "memory-get", tool: "memory.get", requires: ["verax:read"], text: "Reading memory needs the read scope." },
      ],
    }),
  );
}

function harness(policy: ReturnType<typeof loadPolicy>, refs: string[]) {
  const received: ToolCall[] = [];
  const ledger = new MemoryLedger();
  const proxy = createProxy({
    policy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: tickingNow(),
    nonce: queuedNonce(refs),
    inner: async (call) => {
      received.push(structuredClone({ name: call.name, arguments: call.arguments }));
      return { content: [{ type: "text", text: "ok" }], isError: false };
    },
  });
  return { proxy, ledger, received };
}

describe("data classes: the policy document", () => {
  it("refuses dataClasses under version 1", () => {
    assert.throws(
      () => loadPolicy(JSON.stringify({ version: 1, default: "deny", dataClasses: { email: "mask" }, rules: [] })),
      /dataClasses/,
    );
  });

  it("loads a version 2 document, and a version 1 document still loads as before", () => {
    assert.doesNotThrow(() => policyV2());
    assert.doesNotThrow(() => loadPolicy(JSON.stringify({ version: 1, default: "deny", rules: [] })));
  });

  it("refuses an unknown class name and an unknown choice", () => {
    assert.throws(() => policyV2({ dataClasses: { "e-mail": "mask" } }), /e-mail/);
    assert.throws(() => policyV2({ dataClasses: { email: "redact" } }), /email/);
  });

  it("refuses local without a list of local tools", () => {
    assert.throws(() => policyV2({ dataClasses: { email: "local" } }), /local/);
  });
});

describe("data classes: the gate", () => {
  it("a block class is a signed deny and the tool is not reached", async () => {
    const { proxy, ledger, received } = harness(policyV2(), ["r-block"]);
    const result = await proxy.call({ name: "memory.put", arguments: { id: "n1", body: `TC ${TCKN}` } }, P);
    assert.equal(received.length, 0);
    assert.equal(result.isError, true);
    assert.equal(result.content[0]?.text, "denied:data-class-block:tckn:r-block");
    const [rec] = await ledger.decisions();
    assert.equal(rec.claims.decision, "deny");
    assert.equal(rec.claims.reasonCode, "data-class-block:tckn");
    assert.equal(verifyDecisionRecord(rec, RECORD_SIGNER.publicKeyPem), true);
    assert.equal((await ledger.effects()).length, 0);
  });

  it("a mask class reaches the tool as a label; the record counts it and matches what was forwarded", async () => {
    const { proxy, ledger, received } = harness(policyV2(), ["r-mask"]);
    const args = { id: "n2", body: `mail ${EMAIL}, IBAN ${IBAN}`, tags: [`cc ${EMAIL}`] };
    const result = await proxy.call({ name: "memory.put", arguments: args }, P);
    assert.equal(result.isError, false);
    assert.equal(received.length, 1);
    const sent = JSON.stringify(received[0]);
    assert.ok(!sent.includes(EMAIL), `the e-mail address reached the tool: ${sent}`);
    assert.ok(!sent.includes("1978 6457"), `the IBAN reached the tool: ${sent}`);
    assert.equal(received[0].arguments.id, "n2");

    const [rec] = await ledger.decisions();
    assert.equal(rec.claims.decision, "allow");
    assert.equal(rec.claims.requestHash, sha256Canonical({ name: "memory.put", arguments: args }));
    const inputs = await proxy.inputsLog.get(rec.claims.ref ?? "");
    const dc = (inputs as { dataClasses?: { masked: Record<string, number>; forwardedHash: string } } | null)?.dataClasses;
    assert.ok(dc, "the decision inputs carry no dataClasses entry");
    assert.deepEqual({ ...dc.masked }, { email: 2, iban: 1 });
    assert.equal(dc.forwardedHash, sha256Canonical(received[0]));
    const logged = JSON.stringify(inputs);
    assert.ok(!logged.includes(EMAIL) && !logged.includes("1978 6457"), `a masked value is in the decision inputs: ${logged}`);
    assert.equal(verifyDecisionRecord(rec, RECORD_SIGNER.publicKeyPem), true);
  });

  it("a rule can allow a class the document masks, for its own tool", async () => {
    const { proxy, received } = harness(policyV2({}, { dataClasses: { email: "allow" } }), ["r-allow"]);
    await proxy.call({ name: "memory.put", arguments: { id: "n3", body: `mail ${EMAIL}, IBAN ${IBAN}` } }, P);
    const sent = JSON.stringify(received[0]);
    assert.ok(sent.includes(EMAIL), `the rule allowed e-mail, yet it was masked: ${sent}`);
    assert.ok(!sent.includes("1978 6457"), `the IBAN reached the tool: ${sent}`);
  });

  it("a local class to a tool not marked local is refused", async () => {
    const policy = policyV2({ dataClasses: { iban: "local" }, localTools: ["memory.get"] });
    const { proxy, ledger, received } = harness(policy, ["r-local"]);
    const result = await proxy.call({ name: "memory.put", arguments: { id: "n4", body: `IBAN ${IBAN}` } }, P);
    assert.equal(received.length, 0);
    assert.equal(result.content[0]?.text, "denied:data-class-local:iban:r-local");
    const [rec] = await ledger.decisions();
    assert.equal(rec.claims.reasonCode, "data-class-local:iban");
  });

  it("a blocked file type is refused", async () => {
    const { proxy, received } = harness(policyV2({ fileTypes: { block: [".pem", ".kdbx"] } }), ["r-file"]);
    const result = await proxy.call({ name: "memory.put", arguments: { id: "n5", body: "C:/keys/Server.PEM" } }, P);
    assert.equal(received.length, 0);
    assert.equal(result.content[0]?.text, "denied:file-type-block:.pem:r-file");
  });

  it("a blocked file type is refused when the policy has no dataClasses", async () => {
    const policy = loadPolicy(
      JSON.stringify({
        version: 2,
        default: "deny",
        fileTypes: { block: [".pem"] },
        rules: [
          { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope." },
        ],
      }),
    );
    const { proxy, received } = harness(policy, ["r-file-nodc"]);
    const result = await proxy.call({ name: "memory.put", arguments: { body: "C:/keys/Server.PEM" } }, P);
    assert.equal(received.length, 0);
    assert.equal(result.content[0]?.text, "denied:file-type-block:.pem:r-file-nodc");
  });

  it("text over the scan cap is replaced whole, and the record says so", async () => {
    const { proxy, received } = harness(
      policyV2({ dataClasses: { email: "mask", iban: "mask" }, scanCharCap: 64 }),
      ["r-cap"],
    );
    await proxy.call({ name: "memory.put", arguments: { id: "n6", body: `${"x".repeat(100)} ${EMAIL}` } }, P);
    const sent = JSON.stringify(received[0]);
    assert.ok(!sent.includes(EMAIL), `the e-mail address reached the tool: ${sent}`);
    assert.ok(!sent.includes("xxxxxxxxxx"), `the over-cap text was forwarded in part: ${sent}`);
  });

  it("a call with nothing to mask is forwarded unchanged and records no masking", async () => {
    const { proxy, ledger, received } = harness(policyV2(), ["r-clean"]);
    const args = { id: "n7", body: "ciro 1.250.000 TL" };
    await proxy.call({ name: "memory.put", arguments: args }, P);
    assert.deepEqual(received[0].arguments, args);
    const [rec] = await ledger.decisions();
    const inputs = await proxy.inputsLog.get(rec.claims.ref ?? "");
    const dc = (inputs as { dataClasses?: { masked: Record<string, number> } } | null)?.dataClasses;
    assert.deepEqual({ ...(dc?.masked ?? {}) }, {});
  });

  it("with a scan cap and no class chosen mask, an allowed class reaches the tool", async () => {
    const policy = policyV2({ dataClasses: { email: "allow", tckn: "block" }, scanCharCap: 10_000 });
    const { proxy, received } = harness(policy, ["r-cap-allow"]);
    await proxy.call({ name: "memory.put", arguments: { id: "n9", body: `mail ${EMAIL}` } }, P);
    const sent = JSON.stringify(received[0]);
    assert.ok(sent.includes(EMAIL), `e-mail is allowed, yet it was masked: ${sent}`);
  });

  it("an approved call is forwarded masked, and the allow names what was forwarded", async () => {
    const policy = policyV2({}, { mode: "approve" });
    const { proxy, ledger, received } = harness(policy, ["unused"]);
    const call = { name: "memory.put", arguments: { id: "n10", body: `mail ${EMAIL}`, _ref: "dc-approve" } };
    await proxy.call(call, P);
    await approvePending({
      ledger,
      recordSigner: RECORD_SIGNER,
      now: tickingNow(1_000),
      nonce: queuedNonce(["dc-allow"]),
      ref: "dc-approve",
      approverId: "op-1",
      via: "cli",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals: proxy.approvals,
      inputsLog: proxy.inputsLog,
    });
    const out = await proxy.call(call, P);
    assert.equal(out.isError, false);
    assert.equal(received.length, 1);
    const sent = JSON.stringify(received[0]);
    assert.ok(!sent.includes(EMAIL), `the e-mail address reached the tool after approval: ${sent}`);
    const allow = (await ledger.decisions()).find((d) => d.claims.decision === "allow");
    const effect = (await ledger.effects())[0];
    assert.ok(allow && effect, "no allow record or no effect row");
    assert.equal(allow.claims.effectHash, effect.row.effectHash, "the allow and the effect row name different calls");
  });

  // Security review of the first pass (28 Oct): four ways round the gate.
  it("a key named _inputs or _ref below the top level is scanned like any other", async () => {
    const { proxy, received } = harness(policyV2(), ["r-nested"]);
    const result = await proxy.call(
      { name: "memory.put", arguments: { id: "n11", body: { _ref: `TC ${TCKN}`, note: { _inputs: [`TC ${TCKN}`] } } } },
      P,
    );
    assert.equal(received.length, 0, `a TCKN under a nested _ref/_inputs reached the tool: ${JSON.stringify(received)}`);
    assert.equal(result.content[0]?.text, "denied:data-class-block:tckn:r-nested");
  });

  it("a block class in text over the scan cap is not let through raw", async () => {
    // No scanCharCap in the policy: Conarium's default cap is 16 384 characters.
    const policy = policyV2({ dataClasses: { tckn: "block" } });
    const { proxy, received } = harness(policy, ["r-cap-block"]);
    await proxy.call({ name: "memory.put", arguments: { id: "n12", body: `${"x".repeat(20_000)} TC ${TCKN}` } }, P);
    const sent = JSON.stringify(received);
    assert.ok(!sent.includes(TCKN), "a blocked TCKN over the default cap reached the tool raw");
  });

  it("a blocked class in an object key, or as a number, is refused", async () => {
    const { proxy, received } = harness(policyV2(), ["r-key", "r-num"]);
    const asKey = await proxy.call({ name: "memory.put", arguments: { id: "n13", body: { [TCKN]: "x" } } }, P);
    const asNumber = await proxy.call({ name: "memory.put", arguments: { id: "n14", body: Number(TCKN) } }, P);
    assert.equal(received.length, 0, `a TCKN as a key or a number reached the tool: ${JSON.stringify(received)}`);
    assert.match(asKey.content[0]?.text ?? "", /^denied:data-class-block:tckn:/);
    assert.match(asNumber.content[0]?.text ?? "", /^denied:data-class-block:tckn:/);
  });

  it("a blocked file type is found behind a query, encoding, trailing dots or an NTFS stream", async () => {
    const names = [
      "https://files.example/keys/server.pem?download=1",
      "https://files.example/keys/server.pem#x",
      "keys/server%2Epem",
      "C:\\keys\\server.pem.",
      "C:\\keys\\server.pem ",
      "C:\\keys\\server.pem::$DATA",
      "C:\\keys\\server.pem:stream",
    ];
    const { proxy, received } = harness(policyV2({ fileTypes: { block: [".pem"] } }), names.map((_, i) => `r-f${i}`));
    for (const [i, body] of names.entries()) {
      const out = await proxy.call({ name: "memory.put", arguments: { id: `f${i}`, body } }, P);
      assert.equal(out.content[0]?.text, `denied:file-type-block:.pem:r-f${i}`, `not refused: ${body}`);
    }
    assert.equal(received.length, 0);
  });

  it("a name that only contains a blocked extension is not refused", async () => {
    const { proxy, received } = harness(policyV2({ fileTypes: { block: [".pem"] } }), ["r-ok1", "r-ok2"]);
    for (const body of ["reports/report.pem.txt", "notes.txt"]) {
      const out = await proxy.call({ name: "memory.put", arguments: { id: body, body } }, P);
      assert.equal(out.isError, false, `refused: ${body}`);
    }
    assert.equal(received.length, 2);
  });

  it("a call approved before the policy masked a class is not forwarded raw after it does", async () => {
    // Security review of round 2: the retry after approval ran no gate, and a snapshot
    // without forwarded arguments dispatched the original ones.
    const ledger = new MemoryLedger();
    const received: ToolCall[] = [];
    const inner = async (call: ToolCall) => {
      received.push(structuredClone({ name: call.name, arguments: call.arguments }));
      return { content: [{ type: "text" as const, text: "ok" }], isError: false };
    };
    const rule = { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], mode: "approve", text: "Writes need approval." };
    const before = createProxy({
      policy: loadPolicy(JSON.stringify({ version: 1, default: "deny", rules: [rule] })),
      recordSigner: RECORD_SIGNER, effectSigner: EFFECT_SIGNER, ledger, now: tickingNow(), nonce: queuedNonce(["x"]), inner,
    });
    const call = { name: "memory.put", arguments: { id: "n15", body: `mail ${EMAIL}`, _ref: "dc-policy-change" } };
    await before.call(call, P);
    await approvePending({
      ledger, recordSigner: RECORD_SIGNER, now: tickingNow(1_000), nonce: queuedNonce(["dc-allow-2"]),
      ref: "dc-policy-change", approverId: "op-1", via: "cli",
      policyHash: (await ledger.decisions())[0]!.claims.policyHash,
      approvals: before.approvals, inputsLog: before.inputsLog,
    });
    const after = createProxy({
      policy: loadPolicy(JSON.stringify({ version: 2, default: "deny", dataClasses: { email: "mask" }, rules: [rule] })),
      recordSigner: RECORD_SIGNER, effectSigner: EFFECT_SIGNER, ledger, now: tickingNow(2_000), nonce: queuedNonce(["y", "z"]), inner,
    });
    await after.call(call, P);
    const sent = JSON.stringify(received);
    assert.ok(!sent.includes(EMAIL), `an approved call reached the tool with an address the policy now masks: ${sent}`);
  });

  // Security review of round 3.
  it("a blocked extension after an NTFS stream colon, or a multi-dot extension, is refused", async () => {
    const policy = policyV2({ fileTypes: { block: [".pem", ".tar.gz"] } });
    const names = ["C:\\docs\\notes.txt:payload.pem", "backups/site.TAR.GZ", "backups/site.tar.gz?x=1"];
    const { proxy, received } = harness(policy, names.map((_, i) => `r-g${i}`));
    for (const [i, body] of names.entries()) {
      const out = await proxy.call({ name: "memory.put", arguments: { id: `g${i}`, body } }, P);
      assert.match(out.content[0]?.text ?? "", /^denied:file-type-block:/, `not refused: ${body}`);
    }
    assert.equal(received.length, 0);
  });

  it("a file whose whole name is the blocked extension is refused (.env)", async () => {
    const policy = policyV2({ fileTypes: { block: [".env"] } });
    const names = ["/app/.env", "C:\\x\\.env:stream", "C:\\x\\.ENV."];
    const { proxy, received } = harness(policy, names.map((_, i) => `r-e${i}`));
    for (const [i, body] of names.entries()) {
      const out = await proxy.call({ name: "memory.put", arguments: { id: `e${i}`, body } }, P);
      assert.match(out.content[0]?.text ?? "", /^denied:file-type-block:\.env:/, `not refused: ${body}`);
    }
    assert.equal(received.length, 0);
  });

  it("an object key too long to scan is refused, whatever the class choices", async () => {
    const { proxy, received } = harness(policyV2(), ["r-longkey"]);
    const out = await proxy.call({ name: "memory.put", arguments: { id: "n16", body: { [`${"x".repeat(20_000)} ${TCKN}`]: 1 } } }, P);
    assert.equal(received.length, 0, "a key over the scan cap reached the tool");
    assert.match(out.content[0]?.text ?? "", /^denied:data-class-(unscanned|key)/);
  });

  // Cursor (Sol) review, 28 Oct: Verax's own _ref and _inputs were never scanned, and very deep
  // arguments threw instead of being refused.
  it("a class in _ref never reaches the ledger or the tool", async () => {
    const { proxy, ledger, received } = harness(policyV2(), ["r-meta-ref"]);
    const out = await proxy.call({ name: "memory.put", arguments: { id: "n17", body: "ok", _ref: TCKN } }, P);
    assert.equal(received.length, 0, "the call reached the tool");
    assert.match(out.content[0]?.text ?? "", /^denied:data-class-/);
    assert.ok(!out.content[0]?.text?.includes(TCKN), `the TCKN is in the result: ${out.content[0]?.text}`);
    assert.ok(!JSON.stringify(await ledger.decisions()).includes(TCKN), "the TCKN is in the ledger");
  });

  it("a class in _inputs never reaches the inputs log or the ledger", async () => {
    // A valid input reference, so the call reaches the record path instead of input-invalid.
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy: policyV2(),
      recordSigner: RECORD_SIGNER, effectSigner: EFFECT_SIGNER, ledger,
      now: tickingNow(), nonce: queuedNonce(["r-meta-in1", "r-meta-in2"]),
      resolveInput: async () => ({ versionHash: "a".repeat(64), validFromMs: 0, validUntilMs: 9_999_999_999_999 }),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const out = await proxy.call(
      { name: "memory.put", arguments: { id: "n18", body: "ok", _inputs: [{ id: "doc-1", versionHash: "a".repeat(64), source: { note: `mail ${EMAIL}` } }] } },
      P,
    );
    assert.doesNotMatch(out.content[0]?.text ?? "", /input-invalid|input-missing/, "the input reference itself was refused; the test did not reach the record path");
    const decisions = await ledger.decisions();
    assert.ok(!JSON.stringify(decisions).includes(EMAIL), "the e-mail address is in the ledger");
    for (const d of decisions) {
      const logged = JSON.stringify(await proxy.inputsLog.get(d.claims.ref ?? ""));
      assert.ok(!logged.includes(EMAIL), `the e-mail address is in the inputs log: ${logged}`);
    }
  });

  it("arguments nested too deep to scan are a signed deny, not a crash", async () => {
    const { proxy, ledger, received } = harness(policyV2(), ["r-deep"]);
    let body: unknown = `TC ${TCKN}`;
    for (let i = 0; i < 3_000; i++) body = { a: body };
    const out = await proxy.call({ name: "memory.put", arguments: { id: "n19", body } }, P);
    assert.equal(received.length, 0);
    assert.match(out.content[0]?.text ?? "", /^denied:data-class-/);
    const [rec] = await ledger.decisions();
    assert.equal(rec?.claims.decision, "deny");
  });

  // Security review of PR #247.
  it("a blocked extension inside a command, after a trailing slash or a dot segment, is refused", async () => {
    const names = [
      "cat keys/server.pem && echo ok",
      "keys/server.pem/",
      "keys/server.pem/.",
      "\"C:\\keys\\server.pem\"",
      "a.txt,keys/server.pem",
      "$(cat keys/server.pem)",
      "x=keys/server.pem",
      "[keys/server.pem]",
      "{keys/server.pem}",
    ];
    const { proxy, received } = harness(policyV2({ fileTypes: { block: [".pem"] } }), names.map((_, i) => `r-t${i}`));
    for (const [i, body] of names.entries()) {
      const out = await proxy.call({ name: "memory.put", arguments: { id: `t${i}`, body } }, P);
      assert.equal(out.content[0]?.text, `denied:file-type-block:.pem:r-t${i}`, `not refused: ${body}`);
    }
    assert.equal(received.length, 0);
  });

  const filesContaining = (dir: string, needle: string): string[] =>
    (readdirSync(dir, { recursive: true }) as string[])
      .map((f) => join(dir, f))
      .filter((f) => statSync(f).isFile() && readFileSync(f, "utf8").includes(needle));

  const inputsCall = {
    name: "memory.put",
    arguments: { id: "n20", body: "ok", _inputs: [{ id: "doc-1", versionHash: "a".repeat(64), source: { note: `mail ${EMAIL}` } }] },
  };
  const fileProxy = (dir: string) =>
    createProxy({
      policy: policyV2(),
      recordSigner: RECORD_SIGNER, effectSigner: EFFECT_SIGNER, ledger: new FileLedger(dir),
      now: tickingNow(), nonce: queuedNonce(["h1", "h2", "h3", "h4"]),
      resolveInput: async () => ({ versionHash: "a".repeat(64), validFromMs: 0, validUntilMs: 9_999_999_999_999 }),
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });

  it("a halted gate does not write a class from an inputs id to disk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dc-halt-id-"));
    writeFileSync(join(dir, "halted"), "", { encoding: "utf8" });
    const out = await fileProxy(dir).call(
      {
        name: "memory.put",
        arguments: { id: "n-halt-id", body: "ok", _inputs: [{ id: TCKN, versionHash: "a".repeat(64) }] },
      },
      P,
    );
    assert.match(out.content[0]?.text ?? "", /^denied:/);
    assert.deepEqual(filesContaining(dir, TCKN), [], "the TCKN was written to disk");
  });

  it("a gate low on disk does not write a class from an inputs id to disk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dc-disk-id-"));
    const orig = diskProbe.freeBytes;
    diskProbe.freeBytes = (probeDir) => (probeDir === dir ? 0 : orig(probeDir));
    try {
      const out = await fileProxy(dir).call(
        {
          name: "memory.put",
          arguments: { id: "n-disk-id", body: "ok", _inputs: [{ id: TCKN, versionHash: "a".repeat(64) }] },
        },
        P,
      );
      assert.match(out.content[0]?.text ?? "", /^denied:/);
      assert.deepEqual(filesContaining(dir, TCKN), [], "the TCKN was written to disk");
    } finally {
      diskProbe.freeBytes = orig;
    }
  });

  it("a halted gate does not write a class from _inputs to disk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dc-halt-"));
    writeFileSync(join(dir, "halted"), "", { encoding: "utf8" });
    const out = await fileProxy(dir).call(inputsCall, P);
    assert.match(out.content[0]?.text ?? "", /^denied:/);
    assert.deepEqual(filesContaining(dir, EMAIL), [], "the e-mail address was written to disk");
  });

  it("a gate low on disk does not write a class from _inputs to disk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dc-disk-"));
    const orig = diskProbe.freeBytes;
    diskProbe.freeBytes = (probeDir) => (probeDir === dir ? 0 : orig(probeDir));
    try {
      const out = await fileProxy(dir).call(inputsCall, P);
      assert.match(out.content[0]?.text ?? "", /^denied:/);
      assert.deepEqual(filesContaining(dir, EMAIL), [], "the e-mail address was written to disk");
    } finally {
      diskProbe.freeBytes = orig;
    }
  });

  it("an unscanned field is denied when any class is block, even if another is mask", async () => {
    const policy = policyV2({ dataClasses: { email: "mask", tckn: "block" } });
    const { proxy, received } = harness(policy, ["r-unscanned-mix"]);
    const out = await proxy.call(
      { name: "memory.put", arguments: { id: "n-mix", body: `${"x".repeat(20_000)} ${TCKN}` } },
      P,
    );
    assert.equal(received.length, 0, `an unscanned blocked field reached the tool: ${JSON.stringify(received)}`);
    assert.match(out.content[0]?.text ?? "", /^denied:data-class-unscanned:/);
  });

  it("a deferred call stores the masked arguments, not the raw ones", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dc-approve-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: policyV2({}, { mode: "approve" }),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce(["unused"]),
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call({ name: "memory.put", arguments: { id: "n-def", body: `mail ${EMAIL}`, _ref: "dc-store" } }, P);
      const pending = (await proxy.approvals.listPending())[0];
      assert.ok(pending, "no pending approval");
      const stored = JSON.stringify(pending.args);
      assert.ok(!stored.includes(EMAIL), `the e-mail address is in the stored args: ${stored}`);
      assert.ok(stored.includes("[MASKED_PII]"), `the stored args were not the forwarded ones: ${stored}`);
      assert.deepEqual(filesContaining(dir, EMAIL), [], "the e-mail address was written to disk");
    } finally {
      ledger.close();
    }
  });

  it("editing forwardedArgs on a deferred call is hash-mismatch, not an allow of a different call", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dc-bind-"));
    const ledger = new FileLedger(dir);
    const received: ToolCall[] = [];
    try {
      const proxy = createProxy({
        policy: policyV2({}, { mode: "approve" }),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce(["unused", "dc-bind-allow"]),
        inner: async (call) => {
          received.push(structuredClone({ name: call.name, arguments: call.arguments }));
          return { content: [{ type: "text", text: "ok" }], isError: false };
        },
      });
      const call = { name: "memory.put", arguments: { id: "n-bind", body: `mail ${EMAIL}`, _ref: "dc-bind" } };
      await proxy.call(call, P);
      const defer = (await ledger.decisions())[0];
      const inputs = await proxy.inputsLog.get("dc-bind");
      assert.ok(inputs?.dataClasses?.forwardedHash, "the signed defer did not commit to a forwardedHash");
      assert.equal(sha256Canonical(inputs), defer!.claims.inputsHash);

      const pending = (await proxy.approvals.listPending())[0];
      assert.ok(pending, "no pending approval");
      const other = { id: "n-bind", body: "other" };
      await proxy.approvals.append({
        ...pending,
        args: other,
        forwardedArgs: other,
        dataClasses: {
          masked: pending.dataClasses?.masked ?? {},
          forwardedHash: sha256Canonical({ name: "memory.put", arguments: other }),
        },
      });

      const result = await approvePending({
        ledger,
        recordSigner: RECORD_SIGNER,
        now: tickingNow(1_000),
        nonce: queuedNonce(["dc-bind-allow"]),
        ref: "dc-bind",
        approverId: "op-1",
        via: "cli",
        policyHash: defer!.claims.policyHash,
        approvals: proxy.approvals,
        inputsLog: proxy.inputsLog,
      });
      assert.equal(result.ok, false);
      assert.equal(result.reason, "hash-mismatch");
      assert.equal(received.length, 0, `a different call was sent: ${JSON.stringify(received)}`);
    } finally {
      ledger.close();
    }
  });

  it("a deferred call takes amount, payee and currency from the forwarded arguments", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-dc-payee-"));
    const ledger = new FileLedger(dir);
    try {
      const proxy = createProxy({
        policy: policyV2({}, { mode: "approve" }),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(),
        nonce: queuedNonce(["unused"]),
        inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
      });
      await proxy.call(
        { name: "memory.put", arguments: { payee: EMAIL, amount: 10, currency: "TRY", _ref: "dc-payee" } },
        P,
      );
      const pending = (await proxy.approvals.listPending())[0];
      assert.ok(pending, "no pending approval");
      const stored = JSON.stringify(pending);
      assert.ok(!stored.includes(EMAIL), `the e-mail address is on the approval row: ${stored}`);
      assert.deepEqual(filesContaining(dir, EMAIL), [], "the e-mail address was written to disk");
    } finally {
      ledger.close();
    }
  });

  it("an IP class is detected when the policy names it", async () => {
    const policy = policyV2({ dataClasses: { ip: "block" } });
    const { proxy, received } = harness(policy, ["r-ip"]);
    const out = await proxy.call({ name: "memory.put", arguments: { id: "n-ip", body: "host 192.168.1.1" } }, P);
    assert.equal(received.length, 0, `an IP address reached the tool: ${JSON.stringify(received)}`);
    assert.match(out.content[0]?.text ?? "", /^denied:data-class-block:ip:/);
  });

  it("a version 2 policy without dataClasses leaves arguments untouched", async () => {
    const policy = loadPolicy(
      JSON.stringify({
        version: 2,
        default: "deny",
        rules: [
          { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope." },
        ],
      }),
    );
    const { proxy, received } = harness(policy, ["r-v2-nogate"]);
    const dash = "2026\u20132027";
    const args = { id: "n-v2", body: `${"x".repeat(20_000)}${dash}` };
    await proxy.call({ name: "memory.put", arguments: args }, P);
    assert.deepEqual(received[0]?.arguments, args);
  });

  it("a version 1 policy forwards a 65-level argument as 0.7.0 did", async () => {
    const policy = loadPolicy(
      JSON.stringify({
        version: 1,
        default: "deny",
        rules: [
          { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope." },
        ],
      }),
    );
    let body: unknown = "ok";
    for (let i = 0; i < 65; i++) body = { a: body };
    const { proxy, received } = harness(policy, ["r-v1-deep"]);
    const out = await proxy.call({ name: "memory.put", arguments: { id: "n-deep", body } }, P);
    assert.equal(out.isError, false, `version 1 refused a deep argument: ${out.content[0]?.text}`);
    assert.equal(received.length, 1);
  });

  it("a version 1 policy forwards arguments untouched", async () => {
    const policy = loadPolicy(JSON.stringify({
      version: 1, default: "deny",
      rules: [{ id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope." }],
    }));
    const { proxy, received } = harness(policy, ["r-v1"]);
    const args = { id: "n8", body: `mail ${EMAIL} TC ${TCKN}` };
    await proxy.call({ name: "memory.put", arguments: args }, P);
    assert.deepEqual(received[0].arguments, args);
  });
});
