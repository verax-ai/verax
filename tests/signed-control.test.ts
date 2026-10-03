import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { canonical, signDecisionRecord, type SignedDecisionRecord } from "@cedulon/core";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";

import { FileLedger } from "@verax-ai/proxy";

import { listen } from "../packages/body/src/server.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { controlChallenge, verifyControlSignatures } from "../packages/body/src/control-signature.ts";
import { historyTail } from "../packages/body/src/halt.ts";
import { saveCredential } from "../packages/body/src/operator-credentials.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { startDevIssuer } from "./issuer-helper.ts";
import { assertWithSoftwarePasskey, mintSoftwarePasskey, type SoftwarePasskey } from "./software-passkey.ts";

const RP_ID = "localhost";
const ORIGIN = "http://localhost:4173";

async function withRp<T>(fn: () => Promise<T>): Promise<T> {
  const prevId = process.env.VERAX_RP_ID;
  const prevOrigins = process.env.VERAX_RP_ORIGINS;
  process.env.VERAX_RP_ID = RP_ID;
  process.env.VERAX_RP_ORIGINS = ORIGIN;
  try {
    return await fn();
  } finally {
    if (prevId === undefined) delete process.env.VERAX_RP_ID;
    else process.env.VERAX_RP_ID = prevId;
    if (prevOrigins === undefined) delete process.env.VERAX_RP_ORIGINS;
    else process.env.VERAX_RP_ORIGINS = prevOrigins;
  }
}

type Door = {
  base: string;
  stateDir: string;
  operator: string;
  auditor: string;
  close: () => Promise<void>;
};

function openPolicy(dir: string): string {
  const path = join(dir, "control-policy.json");
  writeFileSync(path, JSON.stringify({ version: 1, default: "deny", rules: [] }), "utf8");
  return path;
}

async function openDoor(register: SoftwarePasskey | null, stateDir = mkdtempSync(join(tmpdir(), "verax-signed-control-"))): Promise<Door> {
  if (register) {
    saveCredential(stateDir, {
      id: register.id,
      publicKey: isoBase64URL.fromBuffer(register.publicKeyCose.slice()),
      counter: 0,
      sub: "operator-1",
    });
  }
  const audience = "http://127.0.0.1/verax-signed-control";
  const issuer = await startDevIssuer(0, audience);
  const server = await listen({
    issuer: issuer.issuer,
    jwksUrl: issuer.jwksUrl,
    audience,
    stateDir,
    bindHost: "127.0.0.1",
    bindPort: 0,
    policyFile: openPolicy(stateDir),
    tlsTerminated: false,
  });
  const port = (server.address() as { port: number }).port;
  const operator = await issuer.sign({ scope: "verax:audit verax:approve", sub: "operator-7" });
  const auditor = await issuer.sign({ scope: "verax:audit", sub: "auditor-3" });
  return {
    base: `http://127.0.0.1:${port}`,
    stateDir,
    operator,
    auditor,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await issuer.close();
    },
  };
}

function post(door: Door, path: string, body?: unknown, token = door.operator): Promise<Response> {
  return fetch(`${door.base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

function sign(passkey: SoftwarePasskey, action: "halt" | "resume", prev: string | null, counter?: number): AuthenticationResponseJSON {
  return assertWithSoftwarePasskey(passkey, {
    challenge: controlChallenge({ action, prev }),
    rpID: RP_ID,
    origin: ORIGIN,
    ...(counter !== undefined ? { counter } : {}),
  });
}

type HistoryRow = { action: string; via: string; by: string; signature?: { prev?: string | null; sub?: string } };

function history(stateDir: string): HistoryRow[] {
  return readFileSync(join(stateDir, "halt-history.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as HistoryRow);
}

function lineHashAt(stateDir: string, index: number): string {
  const raw = readFileSync(join(stateDir, "halt-history.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "")[index];
  assert.ok(raw);
  return createHash("sha256").update(canonical(raw), "utf8").digest("hex");
}

function controlInputs(stateDir: string): Array<{ subject: string; signature?: unknown }> {
  const inputs = new Map<string, { control?: { signature?: unknown } }>();
  for (const line of readFileSync(join(stateDir, "inputs.jsonl"), "utf8").split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref: string; inputs: { control?: { signature?: unknown } } };
    inputs.set(row.ref, row.inputs);
  }
  const out: Array<{ subject: string; signature?: unknown }> = [];
  for (const line of readFileSync(join(stateDir, "decisions.jsonl"), "utf8").split("\n")) {
    if (line === "") continue;
    const rec = JSON.parse(line) as SignedDecisionRecord;
    if (rec.claims.subject !== "verax.halt" && rec.claims.subject !== "verax.resume") continue;
    const control = inputs.get(rec.claims.ref ?? "")?.control;
    out.push({ subject: rec.claims.subject, ...(control?.signature ? { signature: control.signature } : {}) });
  }
  return out;
}

async function verifyText(stateDir: string): Promise<{ code: number; text: string }> {
  const lines: string[] = [];
  const code = await runVerify([stateDir], (s) => lines.push(s));
  return { code, text: lines.join("\n") };
}

describe("signed halt and resume over HTTP", () => {
  it("C1 with an operator enrolled, an unsigned resume is refused and the body stays halted", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      try {
        assert.equal((await post(door, "/api/halt")).status, 200);
        const res = await post(door, "/api/resume");
        assert.equal(res.status, 403);
        assert.equal(((await res.json()) as { error?: string }).error, "resume-signature-required");
        const state = await fetch(`${door.base}/api/halt`, { headers: { authorization: `Bearer ${door.operator}` } });
        assert.equal(((await state.json()) as { halted: boolean }).halted, true);
        assert.deepEqual(
          history(door.stateDir).map((row) => row.action),
          ["halt"],
        );
      } finally {
        await door.close();
      }
    });
  });

  it("C2 a signed resume is written with its prev, copied into the ledger, and verified offline", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      try {
        assert.equal((await post(door, "/api/halt")).status, 200);
        const challengeRes = await fetch(`${door.base}/api/resume/challenge`, {
          headers: { authorization: `Bearer ${door.operator}` },
        });
        assert.equal(challengeRes.status, 200);
        const offered = (await challengeRes.json()) as { challenge: string; prev: string | null; rpId: string };
        const tail = historyTail(door.stateDir);
        assert.equal(offered.prev, tail);
        assert.equal(offered.challenge, controlChallenge({ action: "resume", prev: tail }));
        const res = await post(door, "/api/resume", { assertion: sign(passkey, "resume", tail) });
        assert.equal(res.status, 200, await res.clone().text());
        assert.equal(((await res.json()) as { halted: boolean }).halted, false);
        const rows = history(door.stateDir);
        assert.equal(rows[1]?.action, "resume");
        assert.equal(rows[1]?.signature?.prev, tail);
        assert.equal(rows[1]?.signature?.sub, "operator-1");
      } finally {
        await door.close();
      }
      const recorded = controlInputs(door.stateDir);
      assert.deepEqual(
        recorded.map((row) => [row.subject, row.signature !== undefined]),
        [
          ["verax.halt", false],
          ["verax.resume", true],
        ],
      );
      const report = await verifyControlSignatures(door.stateDir);
      assert.equal(report.signedVerified, 1);
      assert.equal(report.signedFailed, 0);
      assert.equal(report.unsignedHttp, 1);
      const out = await verifyText(door.stateDir);
      assert.equal(out.code, 0, out.text);
      assert.match(out.text, /control signatures {3}signed-verified 1 · signed-failed 0 · unsigned-http 1/);
    });
  });

  it("C3 a resume assertion does not fit a later halt window", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      try {
        await post(door, "/api/halt");
        const first = sign(passkey, "resume", historyTail(door.stateDir), 1);
        assert.equal((await post(door, "/api/resume", { assertion: first })).status, 200);
        await post(door, "/api/halt");
        // Same assertion, replayed against the next halt.
        const replay = await post(door, "/api/resume", { assertion: first });
        assert.equal(replay.status, 403);
        assert.equal(((await replay.json()) as { error?: string }).error, "control-signature-invalid");
        // A fresh assertion over the new tail, with a higher counter, is accepted.
        const second = sign(passkey, "resume", historyTail(door.stateDir), 2);
        assert.equal((await post(door, "/api/resume", { assertion: second })).status, 200);
      } finally {
        await door.close();
      }
      const out = await verifyText(door.stateDir);
      assert.equal(out.code, 0, out.text);
      assert.match(out.text, /signed-verified 2 · signed-failed 0 · unsigned-http 2/);
    });
  });

  it("C4 a halt is never refused for its signature: a bad one stops unsigned and says so", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      try {
        const wrong = sign(passkey, "halt", "0".repeat(64));
        const res = await post(door, "/api/halt", { assertion: wrong });
        assert.equal(res.status, 200);
        const body = (await res.json()) as { halted: boolean; signatureRefused?: string };
        assert.equal(body.halted, true);
        assert.equal(body.signatureRefused, "control-signature-invalid");
        assert.equal(history(door.stateDir)[0]?.signature, undefined);

        // A body that is not JSON at all still stops.
        const resume = sign(passkey, "resume", historyTail(door.stateDir), 5);
        assert.equal((await post(door, "/api/resume", { assertion: resume })).status, 200);
        const raw = await fetch(`${door.base}/api/halt`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${door.operator}` },
          body: "{not json",
        });
        assert.equal(raw.status, 200);
        assert.equal(((await raw.json()) as { signatureRefused?: string }).signatureRefused, "bad-body");
      } finally {
        await door.close();
      }
    });
  });

  it("C5 a signed halt is recorded and verified", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      try {
        const res = await post(door, "/api/halt", { assertion: sign(passkey, "halt", null) });
        assert.equal(res.status, 200);
        assert.equal(((await res.json()) as { signatureRefused?: string }).signatureRefused, undefined);
        assert.equal(history(door.stateDir)[0]?.signature?.prev, null);
      } finally {
        await door.close();
      }
      const report = await verifyControlSignatures(door.stateDir);
      assert.equal(report.signedVerified, 1);
      assert.equal(report.signedFailed, 0);
    });
  });

  it("C6 a genuine signature copied onto a later line fails verify", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      try {
        await post(door, "/api/halt");
        await post(door, "/api/resume", { assertion: sign(passkey, "resume", historyTail(door.stateDir), 1) });
        await post(door, "/api/halt");
      } finally {
        await door.close();
      }
      // Someone who can write the state directory lifts the second halt by
      // hand with the first resume's signature on the line.
      const rows = history(door.stateDir);
      const copied = { action: "resume", atMs: Date.now(), by: "operator-7", via: "http", signature: rows[1]?.signature };
      appendFileSync(join(door.stateDir, "halt-history.jsonl"), `${JSON.stringify(copied)}\n`, "utf8");
      rmSync(join(door.stateDir, "halted"), { force: true });
      // The body copies the line as it is when it opens again.
      const reopened = await openDoor(null, door.stateDir);
      await reopened.close();
      const report = await verifyControlSignatures(door.stateDir);
      assert.equal(report.signedVerified, 1);
      assert.equal(report.signedFailed, 1);
      const out = await verifyText(door.stateDir);
      assert.equal(out.code, 1, out.text);
      assert.match(out.text, /control signatures: 1 did not verify/);
    });
  });

  it("C9 a signed resume record copied by a holder of the body key counts once", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      try {
        await post(door, "/api/halt");
        await post(door, "/api/resume", { assertion: sign(passkey, "resume", historyTail(door.stateDir), 1) });
      } finally {
        await door.close();
      }
      // The body never writes one history line twice. Someone holding the
      // record key can: same inputs under a new ref, signed and chained.
      const rows = readFileSync(join(door.stateDir, "inputs.jsonl"), "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as { ref: string; inputs: { control?: { signature?: unknown } } });
      const signedRow = rows.find((row) => row.inputs.control?.signature !== undefined);
      assert.ok(signedRow);
      const original = readFileSync(join(door.stateDir, "decisions.jsonl"), "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as SignedDecisionRecord)
        .find((rec) => rec.claims.ref === signedRow.ref);
      assert.ok(original);
      const { recordSigner } = loadOrCreateSigners(door.stateDir);
      appendFileSync(
        join(door.stateDir, "inputs.jsonl"),
        `${JSON.stringify({ ref: "forged-copy", inputs: signedRow.inputs })}\n`,
        "utf8",
      );
      const ledger = new FileLedger(door.stateDir);
      try {
        await ledger.appendDecisionChained((prevRecordHash) =>
          signDecisionRecord(
            { ...original.claims, ref: "forged-copy", nonce: "forged-copy", prevRecordHash },
            recordSigner.privateKeyPem,
            recordSigner.publicKeyPem,
          ),
        );
      } finally {
        ledger.close();
      }
      const report = await verifyControlSignatures(door.stateDir);
      assert.equal(report.signedVerified, 1);
      assert.equal(report.signedFailed, 1);
    });
  });

  it("C10 an assertion the body never used does not fit a line after a different tail", async () => {
    await withRp(async () => {
      const passkey = mintSoftwarePasskey();
      const door = await openDoor(passkey);
      let unused: AuthenticationResponseJSON;
      try {
        await post(door, "/api/halt");
        await post(door, "/api/resume", { assertion: sign(passkey, "resume", historyTail(door.stateDir), 1) });
        // Not halted: this signed resume is accepted and writes nothing.
        unused = sign(passkey, "resume", historyTail(door.stateDir), 2);
        assert.equal((await post(door, "/api/resume", { assertion: unused })).status, 200);
        assert.equal(history(door.stateDir).length, 2);
        await post(door, "/api/halt");
      } finally {
        await door.close();
      }
      // Someone who can write the state directory lifts the halt with it.
      const sig = unused.response;
      const line = {
        action: "resume",
        atMs: Date.now(),
        by: "operator-7",
        via: "http",
        signature: {
          credentialId: passkey.id,
          sub: "operator-1",
          authenticatorData: sig.authenticatorData,
          clientDataJSON: sig.clientDataJSON,
          signature: sig.signature,
          rpId: RP_ID,
          // What the operator signed over: the tail when only two lines existed.
          prev: lineHashAt(door.stateDir, 1),
        },
      };
      appendFileSync(join(door.stateDir, "halt-history.jsonl"), `${JSON.stringify(line)}\n`, "utf8");
      rmSync(join(door.stateDir, "halted"), { force: true });
      const reopened = await openDoor(null, door.stateDir);
      await reopened.close();
      const report = await verifyControlSignatures(door.stateDir);
      assert.equal(report.signedVerified, 1);
      assert.equal(report.signedFailed, 1);
    });
  });

  it("C7 with no operator enrolled an unsigned resume still works and is counted unsigned", async () => {
    await withRp(async () => {
      const door = await openDoor(null);
      try {
        assert.equal((await post(door, "/api/halt")).status, 200);
        assert.equal((await post(door, "/api/resume")).status, 200);
      } finally {
        await door.close();
      }
      const out = await verifyText(door.stateDir);
      assert.equal(out.code, 0, out.text);
      assert.match(out.text, /signed-verified 0 · signed-failed 0 · unsigned-http 2/);
    });
  });

  it("C8 the resume challenge needs the approve scope; the halt challenge does not", async () => {
    await withRp(async () => {
      const door = await openDoor(mintSoftwarePasskey());
      try {
        const resume = await fetch(`${door.base}/api/resume/challenge`, { headers: { authorization: `Bearer ${door.auditor}` } });
        assert.equal(resume.status, 403);
        const halt = await fetch(`${door.base}/api/halt/challenge`, { headers: { authorization: `Bearer ${door.auditor}` } });
        assert.equal(halt.status, 200);
        const body = (await halt.json()) as { challenge: string; prev: string | null };
        assert.equal(body.prev, null);
        assert.equal(body.challenge, controlChallenge({ action: "halt", prev: null }));
      } finally {
        await door.close();
      }
    });
  });
});
