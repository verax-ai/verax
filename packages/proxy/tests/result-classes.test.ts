import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { verifyDecisionRecord, type SignedDecisionRecord } from "@cedulon/core";

import { explain } from "../src/explain.ts";
import { sha256Canonical } from "../src/hash.ts";
import { FileLedger, MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import type { Principal, ToolResult } from "../src/types.ts";
import { verifyLedger } from "../src/verify-ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

// Results and audio (docs/design/data-classes.md, "Results and audio"): what a
// tool returns is masked before the agent sees it, a recording is replaced by
// its masked transcript made on this machine, and a signed record says what was
// taken out, by count and hash, never by value.

const here = dirname(fileURLToPath(import.meta.url));
const FAKE_TRANSCRIBER = join(here, "fixtures", "fake-transcriber.mjs");

const TCKN = "10000000146";
const EMAIL = "ayse.yilmaz@example.com";
// The values as fixtures/transcript-tr.txt spells them.
const SPOKEN_TCKN = "1-0-0-0-0-0-0-0-1-4-6";
const SPOKEN_PHONE = "0532-123-4567";
const SPOKEN_IBAN_HEAD = "TR33-0006";
const TRANSCRIPT_WORDS = "kimlik numaram";

const AUDIO_B64 = Buffer.from("ID3\u0004\u0000fake-mpeg-frames-for-tests", "latin1").toString("base64");
const IMAGE_B64 = Buffer.from("\u0089PNG\r\n\u001a\nfake-png-for-tests", "latin1").toString("base64");
const AUDIO_BLOCK = { type: "audio", data: AUDIO_B64, mimeType: "audio/mpeg" };
const IMAGE_BLOCK = { type: "image", data: IMAGE_B64, mimeType: "image/png" };

const P: Principal = { brain: "brain-1", scopes: new Set(["verax:read"]) };
const CALL = { name: "media.read", arguments: { path: "notes/voice.mp3" } };
const REFS = ["r-1", "r-2", "r-3", "r-4", "r-5", "r-6"];

type ResultClassesInputs = {
  masked: Record<string, number>;
  transcribed: number;
  withheld: Record<string, number>;
  returnedHash: string;
};

function policy(doc: Record<string, unknown> = {}, ruleExtra: Record<string, unknown> = {}) {
  return loadPolicy(
    JSON.stringify({
      version: 2,
      default: "deny",
      ...doc,
      rules: [
        { id: "media-read", tool: "media.read", requires: ["verax:read"], text: "Reading needs the read scope.", ...ruleExtra },
      ],
    }),
  );
}

function transcriber(mode: "ok" | "fail" | "empty" | "slow" | "tree" | "escape", report?: string, timeoutMs = 20_000) {
  return {
    command: [process.execPath, FAKE_TRANSCRIBER, "{file}", mode, ...(report ? [report] : [])],
    timeoutMs,
  };
}

const ALL_MASK = { tckn: "mask", iban: "mask", email: "mask", phone: "mask" };

// Media blocks are not in ToolResult's text-only type today; the cast is the
// widening the design asks for.
function result(content: unknown[]): ToolResult {
  return { content, isError: false } as unknown as ToolResult;
}

function harness(pol: ReturnType<typeof loadPolicy>, returns: ToolResult, ledger: MemoryLedger | FileLedger = new MemoryLedger()) {
  let calls = 0;
  const proxy = createProxy({
    policy: pol,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: tickingNow(),
    nonce: queuedNonce(REFS),
    inner: async () => {
      calls += 1;
      return structuredClone(returns);
    },
  });
  return { proxy, ledger, calls: () => calls };
}

async function resultRecord(
  proxy: ReturnType<typeof createProxy>,
  ledger: MemoryLedger | FileLedger,
  callRef: string,
): Promise<{ rec: SignedDecisionRecord; inputs: { resultOf: string; resultClasses: ResultClassesInputs } } | null> {
  for (const rec of await ledger.decisions()) {
    const inputs = (await proxy.inputsLog.get(rec.claims.ref ?? "")) as
      | { resultOf?: string; resultClasses?: ResultClassesInputs }
      | null;
    if (inputs?.resultOf === callRef && inputs.resultClasses) {
      return { rec, inputs: inputs as { resultOf: string; resultClasses: ResultClassesInputs } };
    }
  }
  return null;
}

function blocks(res: ToolResult): { type: string; text?: string; data?: string; mimeType?: string }[] {
  return res.content as unknown as { type: string; text?: string; data?: string; mimeType?: string }[];
}

function textOf(res: ToolResult): string {
  return blocks(res)
    .map((b) => b.text ?? "")
    .join("\n");
}

function readReport(path: string): { file: string; size: number; base64: string; dirMode: number } {
  return JSON.parse(readFileSync(path, "utf8")) as { file: string; size: number; base64: string; dirMode: number };
}

describe("result classes: the policy document", () => {
  it("refuses resultClasses and media under version 1", () => {
    assert.throws(
      () => loadPolicy(JSON.stringify({ version: 1, default: "deny", resultClasses: { email: "mask" }, rules: [] })),
      /resultClasses/,
    );
    assert.throws(
      () => loadPolicy(JSON.stringify({ version: 1, default: "deny", media: { audio: "withhold" }, rules: [] })),
      /media/,
    );
  });

  it("refuses local, an unknown class and an unknown choice in resultClasses, in the document and in a rule", () => {
    assert.throws(() => policy({ resultClasses: { email: "local" }, localTools: ["media.read"] }), /local/);
    assert.throws(() => policy({ resultClasses: { "e-mail": "mask" } }), /e-mail/);
    assert.throws(() => policy({ resultClasses: { email: "redact" } }), /email/);
    assert.throws(() => policy({}, { resultClasses: { email: "local" } }), /local/);
  });

  it("refuses transcribe without a usable transcriber, and an unknown media kind or choice", () => {
    assert.throws(() => policy({ media: { audio: "transcribe" } }), /transcriber/);
    assert.throws(
      () => policy({ media: { audio: "transcribe", transcriber: { command: ["transcribe-local"] } } }),
      /transcriber/,
    );
    assert.throws(
      () => policy({ media: { audio: "transcribe", transcriber: { command: ["t{file}", "x"] } } }),
      /transcriber/,
    );
    assert.throws(
      () => policy({ media: { audio: "transcribe", transcriber: { command: ["t", "{file}", "{file}"] } } }),
      /transcriber/,
    );
    assert.throws(
      () => policy({ media: { audio: "transcribe", transcriber: { command: ["t", "{file}"], timeoutMs: 0 } } }),
      /transcriber/,
    );
    assert.throws(() => policy({ media: { audio: "mask" } }), /audio/);
    assert.throws(() => policy({ media: { image: "redact" } }), /image/);
    assert.throws(() => policy({ media: { video: "allow" } }), /video/);
  });

  it("loads a document with resultClasses, media and a transcriber", () => {
    assert.doesNotThrow(() =>
      policy({ resultClasses: ALL_MASK, media: { audio: "transcribe", image: "withhold", transcriber: transcriber("ok") } }),
    );
  });
});

describe("result classes: text results", () => {
  it("media without resultClasses leaves text blocks untouched", async () => {
    const dash = "2026\u20132027";
    const long = `${"x".repeat(100)} ${dash}`;
    const returns = result([{ type: "text", text: long }, AUDIO_BLOCK]);
    const { proxy } = harness(
      policy({ media: { audio: "withhold", image: "withhold" }, scanCharCap: 64 }),
      returns,
    );
    const res = await proxy.call(CALL, P);
    const texts = blocks(res).filter((b) => b.type === "text");
    assert.ok(
      texts.some((b) => b.text === long),
      `the text block was rewritten: ${JSON.stringify(texts)}`,
    );
    assert.ok(
      texts.some((b) => b.text === "[audio withheld]"),
      `the audio block was not withheld: ${JSON.stringify(texts)}`,
    );
  });

  it("a rule-level resultClasses does not run the masker on a tool that names no class", async () => {
    const dash = "2026\u20132027";
    const long = `${"x".repeat(20_000)}${dash}`;
    const pol = loadPolicy(
      JSON.stringify({
        version: 2,
        default: "deny",
        rules: [
          { id: "memory-put", tool: "memory.put", requires: ["verax:memory"], text: "Writing memory needs the memory scope.", resultClasses: { email: "mask" } },
          { id: "media-read", tool: "media.read", requires: ["verax:read"], text: "Reading needs the read scope." },
        ],
      }),
    );
    const { proxy } = harness(pol, result([{ type: "text", text: long }]));
    const res = await proxy.call(CALL, P);
    assert.equal(textOf(res), long, `the text result was rewritten: ${textOf(res)}`);
  });

  it("without resultClasses or media a result is returned unchanged, media blocks as media", async () => {
    const returns = result([{ type: "text", text: `TC ${TCKN}` }, AUDIO_BLOCK, IMAGE_BLOCK]);
    const { proxy, ledger } = harness(policy({ dataClasses: { email: "mask" } }), returns);
    const res = await proxy.call(CALL, P);
    assert.equal(res.isError, false);
    assert.deepEqual(blocks(res), blocks(returns));
    assert.equal(await resultRecord(proxy, ledger, "r-1"), null);
  });

  it("an IP class in a text result is blocked when the policy names it", async () => {
    const returns = result([{ type: "text", text: "host 192.168.1.1" }]);
    const { proxy } = harness(policy({ resultClasses: { ip: "block" } }), returns);
    const res = await proxy.call(CALL, P);
    assert.equal(res.isError, true);
    assert.match(textOf(res), /withheld:result-class-block:ip:/);
  });

  it("masks a class in a text result; the signed record counts it and hashes what the agent received", async () => {
    const returns = result([{ type: "text", text: `Musteri TC ${TCKN}, e-posta ${EMAIL}, tutar 1.250,00 TL` }]);
    const { proxy, ledger } = harness(policy({ resultClasses: { tckn: "mask", email: "mask" } }), returns);
    const res = await proxy.call(CALL, P);
    assert.equal(res.isError, false);
    const out = textOf(res);
    assert.ok(!out.includes(TCKN) && !out.includes(EMAIL), `a value reached the agent: ${out}`);
    assert.ok(out.includes("1.250,00 TL"), `an amount was masked: ${out}`);

    const found = await resultRecord(proxy, ledger, "r-1");
    assert.ok(found, "no signed record names the result of r-1");
    assert.equal(found.rec.claims.decision, "allow");
    assert.equal(found.rec.claims.reasonCode, "result-classes");
    assert.equal(verifyDecisionRecord(found.rec, RECORD_SIGNER.publicKeyPem), true);
    assert.equal(found.inputs.resultClasses.masked.tckn, 1);
    assert.equal(found.inputs.resultClasses.masked.email, 1);
    assert.equal(found.inputs.resultClasses.returnedHash, sha256Canonical(res));
    const effect = (await ledger.effects()).find((e) => e.row.ref === "r-1");
    assert.ok(effect?.resultHash, "the call has no effect row with a resultHash");
    assert.equal(found.rec.claims.requestHash, effect.resultHash);
    const kept = JSON.stringify(await ledger.decisions()) + JSON.stringify(found.inputs);
    assert.ok(!kept.includes(TCKN) && !kept.includes(EMAIL), `a masked value is in the record: ${kept}`);
  });

  it("a text result over the scan cap is masked in pieces; only a line over the cap is replaced whole", async () => {
    const lines = Array.from({ length: 40 }, (_, i) => `satir ${i} siradan metin`);
    lines[30] = `kimlik ${TCKN}`;
    lines.push("x".repeat(400));
    const returns = result([{ type: "text", text: lines.join("\n") }]);
    const { proxy, ledger } = harness(policy({ resultClasses: { tckn: "mask" }, scanCharCap: 256 }), returns);
    const res = await proxy.call(CALL, P);
    const out = textOf(res);
    assert.ok(!out.includes(TCKN), "the ID number in line 30 reached the agent");
    assert.ok(out.includes("satir 0 siradan metin") && out.includes("satir 39 siradan metin"), `ordinary lines were lost: ${out.slice(0, 200)}`);
    assert.ok(!out.includes("x".repeat(400)), "a line over the cap was not replaced");
    const found = await resultRecord(proxy, ledger, "r-1");
    assert.equal(found?.inputs.resultClasses.masked.tckn, 1);
  });

  it("a line exactly at the scan cap, followed by a line break, is scanned, not replaced whole", async () => {
    const atCap = "y".repeat(256);
    const returns = result([{ type: "text", text: `${atCap}\nkimlik ${TCKN}\n${"w".repeat(300)}` }]);
    const { proxy } = harness(policy({ resultClasses: { tckn: "mask" }, scanCharCap: 256 }), returns);
    const out = textOf(await proxy.call(CALL, P));
    assert.ok(out.startsWith(`${atCap}\n`), `the line at the cap was replaced: ${out.slice(0, 80)}`);
    assert.ok(!out.includes(TCKN));
  });

  it("text results and error text keep the text pipeline; only transcripts use speech", async () => {
    const plain = "Siparis no 1234567, tutar 1 250 000 TL, kontrol et dosya nokta com";
    const { proxy } = harness(policy({ resultClasses: ALL_MASK }), result([{ type: "text", text: plain }]));
    assert.equal(textOf(await proxy.call(CALL, P)), plain);

    const failing = createProxy({
      policy: policy({ resultClasses: ALL_MASK }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: new MemoryLedger(),
      now: tickingNow(),
      nonce: queuedNonce(["e-1", "e-2", "e-3"]),
      inner: async () => {
        throw new Error(`lookup failed: ${plain}`);
      },
    });
    let caught: unknown;
    try {
      await failing.call(CALL, P);
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof Error, "the tool's throw did not reach the caller as an error");
    assert.ok(caught.message.includes(plain), `error text was read with speech rules: ${caught.message}`);
  });

  it("a tool's error text is masked like a result before it leaves the gate", async () => {
    const failing = createProxy({
      policy: policy({ resultClasses: { tckn: "mask", email: "mask" } }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: new MemoryLedger(),
      now: tickingNow(),
      nonce: queuedNonce(["e-1", "e-2", "e-3"]),
      inner: async () => {
        throw new Error(`lookup failed for ${EMAIL} TC ${TCKN}`);
      },
    });
    let caught: unknown;
    try {
      await failing.call(CALL, P);
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof Error, "the tool's throw did not reach the caller as an error");
    const seen = `${caught.message} ${String((caught as { cause?: unknown }).cause ?? "")}`;
    assert.ok(!seen.includes(EMAIL) && !seen.includes(TCKN), `a value left in the error: ${seen}`);
    assert.ok(caught.message.includes("lookup failed"), `the rest of the error text was lost: ${caught.message}`);
  });

  for (const [label, makeThrow] of [
    ["a thrown string", () => `lookup failed for TC ${TCKN}`],
    ["a frozen Error", () => Object.freeze(new Error(`lookup failed for TC ${TCKN}`))],
    [
      "an Error whose stack was read before the throw",
      () => {
        const e = new Error(`lookup failed for TC ${TCKN}`);
        void e.stack;
        return e;
      },
    ],
    [
      "an Error whose name carries the value",
      () => {
        const e = new Error(`lookup failed for TC ${TCKN}`);
        e.name = `LookupError TC ${TCKN}`;
        return e;
      },
    ],
    [
      "an Error with a cause that cannot be removed",
      () => {
        const e = new Error(`lookup failed for TC ${TCKN}`);
        Object.defineProperty(e, "cause", { value: new Error(`raw TC ${TCKN}`), configurable: false, enumerable: false });
        return e;
      },
    ],
  ] as const) {
    it(`${label} leaves the gate masked`, async () => {
      const failing = createProxy({
        policy: policy({ resultClasses: { tckn: "mask" } }),
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger: new MemoryLedger(),
        now: tickingNow(),
        nonce: queuedNonce(["e-1", "e-2", "e-3"]),
        inner: async () => {
          throw makeThrow();
        },
      });
      let caught: unknown;
      try {
        await failing.call(CALL, P);
      } catch (err) {
        caught = err;
      }
      assert.ok(caught !== undefined, "the throw did not reach the caller");
      const c = caught as { message?: unknown; stack?: unknown; cause?: unknown };
      const seen = [String(caught), String(c.message ?? ""), String(c.stack ?? ""), String(c.cause ?? "")].join(" | ");
      assert.ok(!seen.includes(TCKN), `the ID number left in the error: ${seen}`);
      assert.ok(String(c.message ?? caught).includes("lookup failed"), `the rest of the error text was lost: ${seen}`);
    });
  }

  it("without resultClasses or media, the tool's own error object leaves, even a thenable one", async () => {
    const thrown = Object.assign(new Error("plain failure"), {
      then(resolve: (v: unknown) => void) {
        resolve("replacement");
      },
    });
    const failing = createProxy({
      policy: policy({ dataClasses: { email: "mask" } }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: new MemoryLedger(),
      now: tickingNow(),
      nonce: queuedNonce(["e-1", "e-2", "e-3"]),
      inner: async () => {
        throw thrown;
      },
    });
    let caught: unknown;
    try {
      await failing.call(CALL, P);
    } catch (err) {
      caught = err;
    }
    assert.equal(caught, thrown);
  });

  it("a line exactly at the scan cap, followed by CRLF, is scanned, not replaced whole", async () => {
    const atCap = "y".repeat(256);
    const returns = result([{ type: "text", text: `${atCap}\r\nkimlik ${TCKN}` }]);
    const { proxy } = harness(policy({ resultClasses: { tckn: "mask" }, scanCharCap: 256 }), returns);
    const out = textOf(await proxy.call(CALL, P));
    assert.ok(out.startsWith(`${atCap}\r\n`), `the line at the cap was replaced: ${out.slice(0, 80)}`);
    assert.ok(!out.includes(TCKN));
  });

  it("a block class in a tool's error text withholds the text", async () => {
    const failing = createProxy({
      policy: policy({ resultClasses: { tckn: "block" } }),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: new MemoryLedger(),
      now: tickingNow(),
      nonce: queuedNonce(["e-1", "e-2", "e-3"]),
      inner: async () => {
        throw new Error(`no row for TC ${TCKN}`);
      },
    });
    let caught: unknown;
    try {
      await failing.call(CALL, P);
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof Error);
    assert.equal(caught.message, "withheld:result-class-block:tckn:e-1");
  });

  it("a whole-field mask with a block class withholds the result", async () => {
    const line = `${"x".repeat(80)} TC ${TCKN}`;
    const returns = result([{ type: "text", text: line }, { type: "text", text: "other block" }]);
    const { proxy } = harness(policy({ resultClasses: { tckn: "block" }, scanCharCap: 64 }), returns);
    const res = await proxy.call(CALL, P);
    assert.equal(res.isError, true);
    assert.match(textOf(res), /withheld:result-class-block:tckn:/);
    assert.ok(!textOf(res).includes("other block"), `the other block reached the agent: ${textOf(res)}`);
    assert.ok(!textOf(res).includes("[MASKED_PII]"), `a whole-field mask left as text: ${textOf(res)}`);
  });

  it("explain reads a result record as bound to its call's effect row", async () => {
    const returns = result([{ type: "text", text: `TC ${TCKN}` }]);
    const { proxy, ledger } = harness(policy({ resultClasses: { tckn: "mask" } }), returns);
    await proxy.call(CALL, P);
    const found = await resultRecord(proxy, ledger, "r-1");
    assert.ok(found, "no result record");
    const explained = await explain(ledger, found.rec.claims.ref as string);
    assert.notEqual(explained.finding.code, "missing-effect", JSON.stringify(explained.finding));
    assert.notEqual(explained.finding.code, "receipt-without-settlement", JSON.stringify(explained.finding));
    assert.equal(explained.effect?.row.ref, "r-1");
  });

  it("a block class in a text result withholds the whole result; the tool ran and its effect stands", async () => {
    const returns = result([{ type: "text", text: `TC ${TCKN}` }, { type: "text", text: "second block" }]);
    const { proxy, ledger, calls } = harness(policy({ resultClasses: { tckn: "block", email: "mask" } }), returns);
    const res = await proxy.call(CALL, P);
    assert.equal(calls(), 1);
    assert.equal(res.isError, true);
    assert.equal(blocks(res).length, 1);
    assert.equal(textOf(res), "withheld:result-class-block:tckn:r-1");
    assert.ok((await ledger.effects()).some((e) => e.row.ref === "r-1"), "the effect row of r-1 is missing");
    const found = await resultRecord(proxy, ledger, "r-1");
    assert.ok(found, "no signed record names the withheld result");
    assert.equal(found.rec.claims.decision, "deny");
    assert.equal(found.rec.claims.reasonCode, "result-class-block:tckn");
  });

  it("a rule's resultClasses overrides the document for its tool; nothing changed, no record", async () => {
    const returns = result([{ type: "text", text: `mail ${EMAIL}` }]);
    const { proxy, ledger } = harness(
      policy({ resultClasses: { email: "mask" } }, { resultClasses: { email: "allow" } }),
      returns,
    );
    const res = await proxy.call(CALL, P);
    assert.equal(textOf(res), `mail ${EMAIL}`);
    assert.equal(await resultRecord(proxy, ledger, "r-1"), null);
  });
});

describe("result classes: audio", () => {
  it("transcribe: the audio block is replaced by the masked transcript; the recording does not reach the agent", async () => {
    const report = join(mkdtempSync(join(tmpdir(), "verax-stt-")), "report.json");
    const returns = result([{ type: "text", text: "file follows" }, AUDIO_BLOCK]);
    const { proxy, ledger } = harness(
      policy({ resultClasses: ALL_MASK, media: { audio: "transcribe", transcriber: transcriber("ok", report) } }),
      returns,
    );
    const res = await proxy.call(CALL, P);
    assert.equal(res.isError, false);
    assert.ok(!blocks(res).some((b) => b.type === "audio"), "an audio block reached the agent");
    assert.ok(!JSON.stringify(res).includes(AUDIO_B64), "the recording's bytes reached the agent");
    const spoken = blocks(res).find((b) => b.type === "text" && b.text?.startsWith("[audio transcript] "));
    assert.ok(spoken?.text, `no transcript block: ${JSON.stringify(res)}`);
    assert.ok(spoken.text.includes(TRANSCRIPT_WORDS), spoken.text);
    for (const value of [SPOKEN_TCKN, SPOKEN_PHONE, SPOKEN_IBAN_HEAD]) {
      assert.ok(!spoken.text.includes(value), `${value} reached the agent: ${spoken.text}`);
    }

    const seen = readReport(report);
    assert.equal(seen.base64, AUDIO_B64, "the transcriber was not given the recording's bytes");
    assert.equal(existsSync(seen.file), false, "the temporary audio file is still on disk");
    assert.equal(existsSync(dirname(seen.file)), false, "the temporary directory is still on disk");
    if (process.platform !== "win32") assert.equal(seen.dirMode & 0o077, 0, "the temporary directory is readable by others");

    const found = await resultRecord(proxy, ledger, "r-1");
    assert.ok(found, "no signed record names the transcribed result");
    assert.equal(found.inputs.resultClasses.transcribed, 1);
    assert.equal(found.inputs.resultClasses.masked.tckn, 1);
    assert.equal(found.inputs.resultClasses.masked.phone, 1);
    assert.equal(found.inputs.resultClasses.masked.iban, 1);
    const kept = JSON.stringify(await ledger.decisions()) + JSON.stringify(found.inputs);
    for (const value of [SPOKEN_TCKN, SPOKEN_PHONE, TRANSCRIPT_WORDS, AUDIO_B64]) {
      assert.ok(!kept.includes(value), `${value} is in the record`);
    }
  });

  it("transcribe: speech rules catch the IBAN tail and the e-mail address without its @", async () => {
    const returns = result([AUDIO_BLOCK]);
    const { proxy } = harness(
      policy({ resultClasses: ALL_MASK, media: { audio: "transcribe", transcriber: transcriber("ok") } }),
      returns,
    );
    const out = textOf(await proxy.call(CALL, P));
    assert.ok(!out.includes("8413-26"), `the IBAN tail reached the agent: ${out}`);
    assert.ok(!out.includes("example.com"), `the e-mail address reached the agent: ${out}`);
  });

  it("withhold: the audio block is replaced by a label", async () => {
    const { proxy, ledger } = harness(policy({ resultClasses: { tckn: "mask" }, media: { audio: "withhold" } }), result([AUDIO_BLOCK]));
    const res = await proxy.call(CALL, P);
    assert.equal(textOf(res), "[audio withheld]");
    assert.ok(!JSON.stringify(res).includes(AUDIO_B64));
    const found = await resultRecord(proxy, ledger, "r-1");
    assert.deepEqual({ ...found?.inputs.resultClasses.withheld }, { audio: 1 });
  });

  it("a media kind the policy does not name is withheld once resultClasses is set; allow passes it as media", async () => {
    const returns = result([IMAGE_BLOCK, AUDIO_BLOCK]);
    const unnamed = harness(policy({ resultClasses: { tckn: "mask" } }), returns);
    const res = await unnamed.proxy.call(CALL, P);
    assert.deepEqual(
      blocks(res).map((b) => b.text),
      ["[image withheld]", "[audio withheld]"],
    );
    assert.ok(!JSON.stringify(res).includes(IMAGE_B64) && !JSON.stringify(res).includes(AUDIO_B64));

    const allowed = harness(policy({ resultClasses: { tckn: "mask" }, media: { image: "allow", audio: "allow" } }), returns);
    const passed = await allowed.proxy.call(CALL, P);
    assert.deepEqual(blocks(passed), blocks(returns));
  });

  for (const [mode, label] of [
    ["fail", "exits non-zero"],
    ["empty", "prints nothing"],
    ["slow", "runs past its timeout"],
  ] as const) {
    it(`a transcriber that ${label} withholds the audio and leaves no file behind`, async () => {
      const report = join(mkdtempSync(join(tmpdir(), "verax-stt-")), "report.json");
      const { proxy, ledger } = harness(
        policy({ resultClasses: ALL_MASK, media: { audio: "transcribe", transcriber: transcriber(mode, report, 1_000) } }),
        result([AUDIO_BLOCK]),
      );
      const started = Date.now();
      const res = await proxy.call(CALL, P);
      assert.ok(Date.now() - started < 8_000, "the gate waited past the transcriber's timeout");
      assert.equal(textOf(res), "[audio withheld: transcriber-failed]");
      assert.ok(!JSON.stringify(res).includes(AUDIO_B64));
      const seen = readReport(report);
      assert.equal(existsSync(dirname(seen.file)), false, "the temporary directory is still on disk");
      const found = await resultRecord(proxy, ledger, "r-1");
      assert.deepEqual({ ...found?.inputs.resultClasses.withheld }, { audio: 1 });
    });
  }

  it("a timed-out transcriber is stopped with every process it started, and no file is left", async () => {
    const report = join(mkdtempSync(join(tmpdir(), "verax-stt-")), "report.json");
    const { proxy } = harness(
      policy({ resultClasses: ALL_MASK, media: { audio: "transcribe", transcriber: transcriber("tree", report, 1_000) } }),
      result([AUDIO_BLOCK]),
    );
    const res = await proxy.call(CALL, P);
    assert.equal(textOf(res), "[audio withheld: transcriber-failed]");
    const seen = readReport(report) as ReturnType<typeof readReport> & { holderPid?: number };
    assert.equal(typeof seen.holderPid, "number", "the stand-in did not start its child");
    let holderAlive = true;
    for (let i = 0; i < 30 && holderAlive; i += 1) {
      try {
        process.kill(seen.holderPid!, 0);
        await new Promise((r) => setTimeout(r, 100));
      } catch {
        holderAlive = false;
      }
    }
    if (holderAlive) process.kill(seen.holderPid!);
    assert.equal(holderAlive, false, "the transcriber's child still runs and holds the recording");
    assert.equal(existsSync(dirname(seen.file)), false, "the temporary directory is still on disk");
  });

  it("a timed-out transcriber whose child escaped with stdout open does not hold the call past the timeout", async () => {
    const report = join(mkdtempSync(join(tmpdir(), "verax-stt-")), "report.json");
    const { proxy } = harness(
      policy({ resultClasses: ALL_MASK, media: { audio: "transcribe", transcriber: transcriber("escape", report, 1_000) } }),
      result([AUDIO_BLOCK]),
    );
    const started = Date.now();
    let res: ToolResult | undefined;
    try {
      res = await proxy.call(CALL, P);
    } finally {
      const seen = readReport(report) as ReturnType<typeof readReport> & { holderPid?: number };
      try {
        if (seen.holderPid !== undefined) process.kill(seen.holderPid);
      } catch {
        // Already gone.
      }
    }
    assert.ok(Date.now() - started < 8_000, `the call waited ${Date.now() - started} ms for a timeout of 1000 ms`);
    assert.equal(textOf(res), "[audio withheld: transcriber-failed]");
  });

  it("a block class in the transcript withholds the whole result", async () => {
    const { proxy } = harness(
      policy({ resultClasses: { tckn: "block" }, media: { audio: "transcribe", transcriber: transcriber("ok") } }),
      result([AUDIO_BLOCK]),
    );
    const res = await proxy.call(CALL, P);
    assert.equal(res.isError, true);
    assert.equal(textOf(res), "withheld:result-class-block:tckn:r-1");
  });
});

describe("result classes: the ledger", () => {
  it("a ledger with masked and transcribed results verifies, and holds no value, transcript or audio", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-rc-"));
    const ledger = new FileLedger(dir);
    try {
      const pol = policy({ resultClasses: ALL_MASK, media: { audio: "transcribe", transcriber: transcriber("ok") } });
      const text = harness(pol, result([{ type: "text", text: `TC ${TCKN}` }]), ledger);
      await text.proxy.call(CALL, P);
      const audio = createProxy({
        policy: pol,
        recordSigner: RECORD_SIGNER,
        effectSigner: EFFECT_SIGNER,
        ledger,
        now: tickingNow(1_000),
        nonce: queuedNonce(["a-1", "a-2"]),
        inner: async () => result([AUDIO_BLOCK]),
      });
      await audio.call(CALL, P);
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir, { boundaryAllowanceMs: 0 });
    assert.equal(verified.ok, true, JSON.stringify(verified.problems));
    for (const name of readdirSync(dir, { recursive: true }) as string[]) {
      const path = join(dir, name);
      if (!statSync(path).isFile()) continue;
      const body = readFileSync(path, "utf8");
      for (const value of [TCKN, SPOKEN_TCKN, TRANSCRIPT_WORDS, AUDIO_B64]) {
        assert.ok(!body.includes(value), `${value} is on disk in ${name}`);
      }
    }
  });

  it("when the result record cannot be written, the result is not delivered", async () => {
    class SecondRecordFails extends MemoryLedger {
      private n = 0;
      override async appendDecisionChained(build: (prev: string | null) => SignedDecisionRecord): Promise<void> {
        this.n += 1;
        if (this.n === 2) throw new Error("disk-full");
        return super.appendDecisionChained(build);
      }
    }
    const { proxy } = harness(
      policy({ resultClasses: { tckn: "mask" } }),
      result([{ type: "text", text: `TC ${TCKN}` }]),
      new SecondRecordFails(),
    );
    const res = await proxy.call(CALL, P);
    assert.equal(res.isError, true);
    assert.equal(textOf(res), "result-unrecorded:r-1");
  });
});
