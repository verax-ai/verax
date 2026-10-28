import { strict as assert } from "node:assert";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { maskField } from "@conarium-ai/mask";

import { sha256Canonical } from "../src/hash.ts";
import { loadPolicy } from "../src/policy.ts";
import { gateResultClasses, type ResultRecordWriter } from "../src/result-classes.ts";
import type { Principal, ToolResult } from "../src/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const FAKE_TRANSCRIBER = join(here, "fixtures", "fake-transcriber.mjs");

const TCKN = "10000000146";
const SECRET = `TC ${TCKN} must-not-leak`;
const P: Principal = { brain: "brain-1", scopes: new Set(["verax:read"]) };
const CALL_REF = "r-1";
const AUDIO_B64 = Buffer.from("ID3\u0004\u0000fake-mpeg-frames-for-tests", "latin1").toString("base64");

function policy(doc: Record<string, unknown> = {}) {
  return loadPolicy(
    JSON.stringify({
      version: 2,
      default: "deny",
      resultClasses: { tckn: "mask" },
      ...doc,
      rules: [
        { id: "media-read", tool: "media.read", requires: ["verax:read"], text: "Reading needs the read scope." },
      ],
    }),
  );
}

async function runGate(
  result: ToolResult,
  masker: typeof maskField,
  pol = policy(),
): Promise<{ gated: ToolResult; writes: Array<Parameters<ResultRecordWriter>[0]> }> {
  const writes: Array<Parameters<ResultRecordWriter>[0]> = [];
  const gated = await gateResultClasses(result, "media.read", CALL_REF, sha256Canonical(result), P, {
    policy: pol,
    nonce: () => "r-2",
    now: () => 100,
    writeRecord: async (opts) => {
      writes.push(opts);
    },
    masker,
  });
  return { gated, writes };
}

function assertClassError(gated: ToolResult, writes: Array<Parameters<ResultRecordWriter>[0]>): void {
  assert.equal(gated.isError, true);
  assert.equal(gated.content.length, 1);
  assert.equal(gated.content[0]?.type, "text");
  assert.equal(gated.content[0] && "text" in gated.content[0] ? gated.content[0].text : "", `withheld:result-class-error:${CALL_REF}`);
  const body = JSON.stringify(gated);
  assert.ok(!body.includes(TCKN), `unmasked text reached the agent: ${body}`);
  assert.ok(!body.includes("must-not-leak"), `unmasked text reached the agent: ${body}`);
  assert.equal(writes.length, 1);
  const rec = writes[0]!;
  assert.equal(rec.decision, "deny");
  assert.equal(rec.reasonCode, "result-class-error");
  assert.equal(rec.effectHash, null);
  assert.equal(rec.inputs.resultOf, CALL_REF);
  assert.ok(rec.inputs.resultClasses, "the deny has no resultClasses inputs");
  assert.equal(rec.inputs.resultClasses.returnedHash, sha256Canonical(gated));
}

describe("result classes: the masker throws", () => {
  it("withholds the whole text result and writes a deny, not the unmasked piece", async () => {
    let n = 0;
    const { gated, writes } = await runGate(
      {
        content: [
          { type: "text", text: "ordinary first block" },
          { type: "text", text: SECRET },
        ],
        isError: false,
      },
      (text, opts) => {
        n += 1;
        if (n === 1) return maskField(text, opts);
        throw new Error("masker-failed");
      },
    );
    assertClassError(gated, writes);
    const body = JSON.stringify(gated);
    assert.ok(!body.includes("ordinary first block"), `an earlier block reached the agent: ${body}`);
  });

  it("withholds a transcript when the masker throws while scanning it", async () => {
    const result: ToolResult = {
      content: [{ type: "audio", data: AUDIO_B64, mimeType: "audio/mpeg" }],
      isError: false,
    };
    const { gated, writes } = await runGate(result, () => {
      throw new Error("masker-failed");
    }, policy({
      media: {
        audio: "transcribe",
        transcriber: { command: [process.execPath, FAKE_TRANSCRIBER, "{file}", "ok"], timeoutMs: 20_000 },
      },
    }));
    assertClassError(gated, writes);
    const body = JSON.stringify(gated);
    assert.ok(!body.includes("[audio transcript]"), `the transcript reached the agent: ${body}`);
    assert.ok(!body.includes(AUDIO_B64), `the recording reached the agent: ${body}`);
  });
});
