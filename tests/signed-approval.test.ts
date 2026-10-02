import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from "@simplewebauthn/server";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import { createProxy, FileLedger, loadPolicy } from "@verax-ai/proxy";

import { listen } from "../packages/body/src/server.ts";
import { approvalChallenge, verifyApprovalSignatures } from "../packages/body/src/approval-signature.ts";
import { coseKeyToPublicKey, verifyAssertion } from "../packages/body/src/webauthn-verify.ts";
import { runApprove } from "../packages/body/src/approve-cli.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { saveCredential } from "../packages/body/src/operator-credentials.ts";
import { runVerify } from "../packages/body/src/verify-cli.ts";
import { sha256Canonical } from "../packages/proxy/src/hash.ts";
import { startDevIssuer } from "./issuer-helper.ts";
import { assertWithSoftwarePasskey, mintSoftwarePasskey, type SoftwarePasskey } from "./software-passkey.ts";

const RP_ID = "localhost";
const ORIGIN = "http://localhost:4173";

function approvePolicyFile(dir: string): string {
  const path = join(dir, "approve-policy.json");
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "put-approve",
          tool: "memory.put",
          requires: ["verax:memory"],
          mode: "approve",
          text: "Writes need operator approval.",
        },
      ],
    }),
    "utf8",
  );
  return path;
}

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
  brain: string;
  operator: string;
  close: () => Promise<void>;
};

async function openDoor(register: SoftwarePasskey | null): Promise<Door> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-signed-approval-"));
  if (register) {
    saveCredential(stateDir, {
      id: register.id,
      publicKey: isoBase64URL.fromBuffer(register.publicKeyCose.slice()),
      counter: 0,
      sub: "operator-1",
    });
  }
  const audience = "http://127.0.0.1/verax-signed-approval";
  const issuer = await startDevIssuer(0, audience);
  const server = await listen({
    issuer: issuer.issuer,
    jwksUrl: issuer.jwksUrl,
    audience,
    stateDir,
    bindHost: "127.0.0.1",
    bindPort: 0,
    policyFile: approvePolicyFile(stateDir),
    tlsTerminated: false,
  });
  const port = (server.address() as { port: number }).port;
  const brain = await issuer.sign({ scope: "verax:memory" });
  const operator = await issuer.sign({ scope: "verax:audit verax:approve", sub: "operator-7" });
  return {
    base: `http://127.0.0.1:${port}`,
    stateDir,
    brain,
    operator,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await issuer.close();
    },
  };
}

async function hold(door: Door, id: string): Promise<void> {
  await fetch(`${door.base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${door.brain}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "memory.put",
        arguments: {
          id,
          body: { t: 1 },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      },
    }),
  });
}

type Pending = { ref: string; requestHash: string; status?: string };

async function waiting(door: Door): Promise<Pending[]> {
  const listed = await fetch(`${door.base}/api/ledger?from=0&to=${Number.MAX_SAFE_INTEGER}`, {
    headers: { authorization: `Bearer ${door.operator}` },
  });
  const body = (await listed.json()) as { approvals?: Pending[] };
  return (body.approvals ?? []).filter((row) => row.status === "pending" || row.status === undefined);
}

function deferOf(stateDir: string, ref: string): { recordHash: string; requestHash: string } {
  const lines = readFileSync(join(stateDir, "decisions.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "");
  for (const line of lines) {
    const row = JSON.parse(line) as SignedDecisionRecord;
    if (row.claims.ref === ref && row.claims.decision === "defer") {
      return { recordHash: decisionRecordHash(row), requestHash: row.claims.requestHash };
    }
  }
  throw new Error(`no defer for ${ref}`);
}

function signApproval(
  passkey: SoftwarePasskey,
  stateDir: string,
  ref: string,
  requestHash: string,
  over: { origin?: string; counter?: number; challenge?: string } = {},
): AuthenticationResponseJSON {
  const defer = deferOf(stateDir, ref);
  assert.equal(defer.requestHash, requestHash);
  const challenge =
    over.challenge ??
    approvalChallenge({ ref, requestHash: defer.requestHash, deferRecordHash: defer.recordHash });
  return assertWithSoftwarePasskey(passkey, {
    challenge,
    rpID: RP_ID,
    origin: over.origin ?? ORIGIN,
    ...(over.counter !== undefined ? { counter: over.counter } : {}),
  });
}

function postApprove(door: Door, body: unknown): Promise<Response> {
  return fetch(`${door.base}/api/approve`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${door.operator}`,
    },
    body: JSON.stringify(body),
  });
}

type InputsRow = {
  ref: string;
  inputs: {
    approver?: {
      via?: string;
      signature?: {
        credentialId?: string;
        sub?: string;
        deferRecordHash?: string;
        signature?: string;
        authenticatorData?: string;
        clientDataJSON?: string;
      };
    };
  };
};

function inputsFor(stateDir: string, ref: string): InputsRow | undefined {
  return readFileSync(join(stateDir, "inputs.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as InputsRow)
    .find((row) => row.ref === ref);
}

function allowRecord(stateDir: string, ref: string): SignedDecisionRecord {
  const lines = readFileSync(join(stateDir, "decisions.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "");
  for (const line of lines) {
    const row = JSON.parse(line) as SignedDecisionRecord;
    if (row.claims.ref === ref && row.claims.decision === "allow") return row;
  }
  throw new Error(`no allow for ${ref}`);
}

describe("signed approval", () => {
  it("A1 accepts a passkey assertion and binds it into the allow inputs", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      try {
        await hold(door, "n1");
        const pending = await waiting(door);
        assert.equal(pending.length, 1);
        const row = pending[0]!;
        const assertion = signApproval(passkey, door.stateDir, row.ref, row.requestHash);
        const ok = await postApprove(door, { ref: row.ref, requestHash: row.requestHash, assertion });
        assert.equal(ok.status, 200);
        const body = (await ok.json()) as { allowRef?: string };
        assert.ok(body.allowRef);
        const inputs = inputsFor(door.stateDir, body.allowRef);
        const signature = inputs?.inputs.approver?.signature;
        assert.ok(inputs);
        assert.ok(signature);
        assert.equal(signature.credentialId, passkey.id);
        assert.equal(signature.sub, "operator-1");
        assert.equal(signature.deferRecordHash, deferOf(door.stateDir, row.ref).recordHash);
        assert.equal(allowRecord(door.stateDir, body.allowRef).claims.inputsHash, sha256Canonical(inputs.inputs));
      } finally {
        await door.close();
      }
    });
  });

  it("A2 refuses an approval with no assertion when an operator is registered", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      try {
        await hold(door, "n1");
        const pending = await waiting(door);
        const row = pending[0]!;
        const refused = await postApprove(door, { ref: row.ref, requestHash: row.requestHash });
        assert.equal(refused.status, 403);
        assert.equal(((await refused.json()) as { error?: string }).error, "approve-signature-required");
        const still = await waiting(door);
        assert.equal(still.length, 1);
        assert.equal(still[0]!.ref, row.ref);
      } finally {
        await door.close();
      }
    });
  });

  it("A3 rejects an assertion signed for a different ref", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      try {
        await hold(door, "n1");
        const row = (await waiting(door))[0]!;
        const defer = deferOf(door.stateDir, row.ref);
        const assertion = signApproval(passkey, door.stateDir, row.ref, row.requestHash, {
          challenge: approvalChallenge({
            ref: "other-ref",
            requestHash: defer.requestHash,
            deferRecordHash: defer.recordHash,
          }),
        });
        const refused = await postApprove(door, { ref: row.ref, requestHash: row.requestHash, assertion });
        assert.equal(refused.status, 403);
        assert.equal(((await refused.json()) as { error?: string }).error, "approve-signature-invalid");
        assert.equal((await waiting(door)).length, 1);
      } finally {
        await door.close();
      }
    });
  });

  it("A4 rejects a second assertion that repeats the authenticator counter", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      try {
        await hold(door, "n1");
        await hold(door, "n2");
        const pending = await waiting(door);
        assert.equal(pending.length, 2);
        const first = pending[0]!;
        const second = pending[1]!;
        const firstAssertion = signApproval(passkey, door.stateDir, first.ref, first.requestHash);
        const ok = await postApprove(door, {
          ref: first.ref,
          requestHash: first.requestHash,
          assertion: firstAssertion,
        });
        assert.equal(ok.status, 200);
        const replay = signApproval(passkey, door.stateDir, second.ref, second.requestHash, { counter: 1 });
        const refused = await postApprove(door, {
          ref: second.ref,
          requestHash: second.requestHash,
          assertion: replay,
        });
        assert.equal(refused.status, 403);
        assert.equal(((await refused.json()) as { error?: string }).error, "cloned-authenticator");
        const left = await waiting(door);
        assert.equal(left.length, 1);
        assert.equal(left[0]!.ref, second.ref);
      } finally {
        await door.close();
      }
    });
  });

  it("A5 rejects an assertion whose origin is not allowed", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      try {
        await hold(door, "n1");
        const row = (await waiting(door))[0]!;
        const assertion = signApproval(passkey, door.stateDir, row.ref, row.requestHash, {
          origin: "http://evil.example",
        });
        const refused = await postApprove(door, { ref: row.ref, requestHash: row.requestHash, assertion });
        assert.equal(refused.status, 403);
        assert.equal(((await refused.json()) as { error?: string }).error, "approve-signature-invalid");
        assert.equal((await waiting(door)).length, 1);
      } finally {
        await door.close();
      }
    });
  });

  it("A6 keeps unsigned HTTP approval when no operator is registered", async () => {
    await withRp(async () => {
      const door = await openDoor(null);
      try {
        await hold(door, "n1");
        const row = (await waiting(door))[0]!;
        const ok = await postApprove(door, { ref: row.ref, requestHash: row.requestHash });
        assert.equal(ok.status, 200);
        const body = (await ok.json()) as { allowRef?: string };
        assert.ok(body.allowRef);
        assert.equal(inputsFor(door.stateDir, body.allowRef)?.inputs.approver?.signature, undefined);
        assert.equal(inputsFor(door.stateDir, body.allowRef)?.inputs.approver?.via, "http");
      } finally {
        await door.close();
      }
    });
  });

  it("A7 returns the defer-bound challenge and 404 for an unknown ref", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      try {
        await hold(door, "n1");
        const row = (await waiting(door))[0]!;
        const defer = deferOf(door.stateDir, row.ref);
        const res = await fetch(`${door.base}/api/approve/challenge?ref=${encodeURIComponent(row.ref)}`, {
          headers: { authorization: `Bearer ${door.operator}` },
        });
        assert.equal(res.status, 200);
        const body = (await res.json()) as {
          challenge?: string;
          rpId?: string;
          allowCredentials?: { id: string; type: string }[];
        };
        assert.equal(
          body.challenge,
          approvalChallenge({ ref: row.ref, requestHash: defer.requestHash, deferRecordHash: defer.recordHash }),
        );
        assert.equal(body.rpId, RP_ID);
        assert.deepEqual(body.allowCredentials, [{ id: passkey.id, type: "public-key" }]);
        const missing = await fetch(`${door.base}/api/approve/challenge?ref=no-such-ref`, {
          headers: { authorization: `Bearer ${door.operator}` },
        });
        assert.equal(missing.status, 404);
        assert.equal(((await missing.json()) as { error?: string }).error, "unknown-ref");
      } finally {
        await door.close();
      }
    });
  });

  it("A8 verifies a clean approval signature and fails a forged one", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      let allowRef = "";
      try {
        await hold(door, "n1");
        const row = (await waiting(door))[0]!;
        const assertion = signApproval(passkey, door.stateDir, row.ref, row.requestHash);
        const ok = await postApprove(door, { ref: row.ref, requestHash: row.requestHash, assertion });
        assert.equal(ok.status, 200);
        allowRef = ((await ok.json()) as { allowRef: string }).allowRef;
        const clean = await verifyApprovalSignatures(door.stateDir);
        assert.equal(clean.signedVerified, 1);
        assert.equal(clean.signedFailed, 0);
        assert.equal(clean.ok, true);
        assert.match(clean.line, /signed-verified 1/);
        assert.equal(clean.trustSource, "in-ledger");
        const lines: string[] = [];
        const code = await runVerify([door.stateDir], (s) => lines.push(s));
        assert.equal(code, 0, lines.join("\n"));
        assert.match(lines.join("\n"), /signed-verified 1/);
      } finally {
        await door.close();
      }
      const inputsPath = join(door.stateDir, "inputs.jsonl");
      const inputs = readFileSync(inputsPath, "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as InputsRow);
      const target = inputs.find((row) => row.ref === allowRef);
      const signature = target?.inputs.approver?.signature;
      if (!target || !signature?.signature) throw new Error("missing signature");
      // Change a byte inside the signature. Swapping the last base64url character
      // only touched padding bits for 18 of 200 P-256 signatures, which left the
      // bytes, and the verdict, unchanged.
      const bytes = Buffer.from(signature.signature, "base64url");
      bytes[Math.floor(bytes.length / 2)]! ^= 0x01;
      const flipped = bytes.toString("base64url");
      assert.notEqual(flipped, signature.signature);
      signature.signature = flipped;
      writeFileSync(inputsPath, `${inputs.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
      const decisionsPath = join(door.stateDir, "decisions.jsonl");
      const decisions = readFileSync(decisionsPath, "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as SignedDecisionRecord);
      const allow = decisions.find((row) => row.claims.ref === allowRef);
      assert.ok(allow);
      allow.claims.inputsHash = sha256Canonical(target.inputs);
      writeFileSync(decisionsPath, `${decisions.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
      const dirty = await verifyApprovalSignatures(door.stateDir);
      assert.equal(dirty.signedFailed, 1);
      assert.equal(dirty.signedVerified, 0);
      assert.equal(dirty.ok, false);
    });
  });

  it("A10 verify fails a valid signature whose authenticator data does not say the user was verified", async () => {
    const passkey = mintSoftwarePasskey();
    await withRp(async () => {
      const door = await openDoor(passkey);
      let allowRef = "";
      let challenge = "";
      try {
        await hold(door, "n1");
        const row = (await waiting(door))[0]!;
        const defer = deferOf(door.stateDir, row.ref);
        challenge = approvalChallenge({ ref: row.ref, requestHash: defer.requestHash, deferRecordHash: defer.recordHash });
        const assertion = signApproval(passkey, door.stateDir, row.ref, row.requestHash);
        const ok = await postApprove(door, { ref: row.ref, requestHash: row.requestHash, assertion });
        assert.equal(ok.status, 200);
        allowRef = ((await ok.json()) as { allowRef: string }).allowRef;
      } finally {
        await door.close();
      }
      // Same key, same challenge, a correct signature, but only the user-present bit.
      const presentOnly = assertWithSoftwarePasskey(passkey, { challenge, rpID: RP_ID, origin: ORIGIN, flags: 0x01 });
      const inputsPath = join(door.stateDir, "inputs.jsonl");
      const inputs = readFileSync(inputsPath, "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as InputsRow);
      const target = inputs.find((row) => row.ref === allowRef);
      const signature = target?.inputs.approver?.signature;
      if (!target || !signature) throw new Error("missing signature");
      signature.authenticatorData = presentOnly.response.authenticatorData;
      signature.clientDataJSON = presentOnly.response.clientDataJSON;
      signature.signature = presentOnly.response.signature;
      writeFileSync(inputsPath, `${inputs.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
      const decisionsPath = join(door.stateDir, "decisions.jsonl");
      const decisions = readFileSync(decisionsPath, "utf8")
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as SignedDecisionRecord);
      const allow = decisions.find((row) => row.claims.ref === allowRef);
      assert.ok(allow);
      allow.claims.inputsHash = sha256Canonical(target.inputs);
      writeFileSync(decisionsPath, `${decisions.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
      const report = await verifyApprovalSignatures(door.stateDir);
      assert.equal(report.signedVerified, 0);
      assert.equal(report.signedFailed, 1);
      assert.equal(report.ok, false);
    });
  });

  /** One signed approval through the door; returns the state dir and the allow ref it wrote. */
  async function oneSignedApproval(passkey: SoftwarePasskey): Promise<{ stateDir: string; allowRef: string }> {
    let out: { stateDir: string; allowRef: string } | null = null;
    await withRp(async () => {
      const door = await openDoor(passkey);
      try {
        await hold(door, "n1");
        const row = (await waiting(door))[0]!;
        const assertion = signApproval(passkey, door.stateDir, row.ref, row.requestHash);
        const ok = await postApprove(door, { ref: row.ref, requestHash: row.requestHash, assertion });
        assert.equal(ok.status, 200);
        out = { stateDir: door.stateDir, allowRef: ((await ok.json()) as { allowRef: string }).allowRef };
      } finally {
        await door.close();
      }
    });
    if (!out) throw new Error("no approval");
    return out;
  }

  function readJsonl<T>(path: string): T[] {
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as T);
  }

  function writeJsonl(path: string, rows: unknown[]): void {
    writeFileSync(path, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
  }

  it("A11 verify fails a genuine signature attached to an allow for another request", async () => {
    const { stateDir, allowRef } = await oneSignedApproval(mintSoftwarePasskey());
    const clean = await verifyApprovalSignatures(stateDir);
    assert.equal(clean.signedVerified, 1);
    // A body that holds the record key mints an allow for a different request
    // and attaches the operator's signature from the real one.
    const decisionsPath = join(stateDir, "decisions.jsonl");
    const decisions = readJsonl<SignedDecisionRecord>(decisionsPath);
    const allow = decisions.find((row) => row.claims.ref === allowRef);
    assert.ok(allow);
    allow.claims.requestHash = "cd".repeat(32);
    writeJsonl(decisionsPath, decisions);
    const report = await verifyApprovalSignatures(stateDir);
    assert.equal(report.signedVerified, 0);
    assert.equal(report.signedFailed, 1);
    assert.equal(report.ok, false);
  });

  it("A12 verify counts a second signed allow for the same defer as failed", async () => {
    const { stateDir, allowRef } = await oneSignedApproval(mintSoftwarePasskey());
    const decisionsPath = join(stateDir, "decisions.jsonl");
    const inputsPath = join(stateDir, "inputs.jsonl");
    const decisions = readJsonl<SignedDecisionRecord>(decisionsPath);
    const inputs = readJsonl<InputsRow>(inputsPath);
    const allow = decisions.find((row) => row.claims.ref === allowRef);
    const allowInputs = inputs.find((row) => row.ref === allowRef);
    assert.ok(allow && allowInputs);
    const copyRef = `${allowRef}-again`;
    writeJsonl(decisionsPath, [...decisions, { ...allow, claims: { ...allow.claims, ref: copyRef } }]);
    writeJsonl(inputsPath, [...inputs, { ...allowInputs, ref: copyRef }]);
    const report = await verifyApprovalSignatures(stateDir);
    assert.equal(report.signedVerified, 1);
    assert.equal(report.signedFailed, 1);
    assert.equal(report.ok, false);
  });

  it("A13 verify does not throw on a parsed line that is not a decision record", async () => {
    const { stateDir } = await oneSignedApproval(mintSoftwarePasskey());
    const decisionsPath = join(stateDir, "decisions.jsonl");
    writeFileSync(decisionsPath, `${readFileSync(decisionsPath, "utf8")}{}\nnull\n`, "utf8");
    const report = await verifyApprovalSignatures(stateDir);
    assert.equal(report.signedVerified, 1);
    assert.equal(report.signedFailed, 0);
  });

  it("A9 counts a CLI approval as cli and does not expect a signature", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-signed-approval-cli-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy: loadPolicy({
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
      }),
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => Date.now(),
      nonce: () => "d-cli",
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    await proxy.call(
      {
        name: "memory.put",
        arguments: { id: "n1", body: "x", source: { kind: "t" }, validUntilMs: 9_999 },
      },
      { brain: "brain-1", scopes: new Set(["verax:memory"]) },
    );
    ledger.close();
    const code = await runApprove(
      ["approve", "--from-script", dir, "d-cli"],
      () => {},
      () => {},
      { isTTY: false, ask: async () => "" },
      { elevated: () => false },
    );
    assert.equal(code, 0);
    const allow = allowRecord(dir, readAllowRef(dir));
    const inputs = inputsFor(dir, allow.claims.ref!);
    assert.equal(inputs?.inputs.approver?.via, "cli-script");
    assert.equal(inputs?.inputs.approver?.signature, undefined);
    const report = await verifyApprovalSignatures(dir);
    assert.equal(report.cli, 1);
    assert.equal(report.signedVerified, 0);
    assert.equal(report.signedFailed, 0);
    assert.equal(report.ok, true);
    const lines: string[] = [];
    const verifyCode = await runVerify([dir], (s) => lines.push(s));
    assert.equal(verifyCode, 0, lines.join("\n"));
    assert.match(lines.join("\n"), /cli 1/);
  });

  it("D1 agrees with verifyAuthenticationResponse for P-256 and Ed25519", async () => {
    // crossOrigin true with a topOrigin is the case the referee rejects: it
    // was not given expectedTopOrigin. verifyAssertion refuses every
    // crossOrigin true, including one that names no topOrigin, which this
    // referee would accept.
    const challenge = "challenge-1";
    const origin = "http://localhost:4173";
    const rpID = "localhost";
    for (const alg of ["ES256", "Ed25519"] as const) {
      const passkey = mintSoftwarePasskey(alg);
      const publicKeyCose = isoBase64URL.fromBuffer(passkey.publicKeyCose.slice());
      const rows: {
        name: string;
        assertion: AuthenticationResponseJSON;
        expectedChallenge: string;
        expectedOrigin: string;
        rpId: string;
      }[] = [
        {
          name: "valid",
          assertion: assertWithSoftwarePasskey(passkey, { challenge, rpID, origin }),
          expectedChallenge: challenge,
          expectedOrigin: origin,
          rpId: rpID,
        },
        {
          name: "wrong-challenge",
          assertion: assertWithSoftwarePasskey(passkey, { challenge: "other-challenge", rpID, origin }),
          expectedChallenge: challenge,
          expectedOrigin: origin,
          rpId: rpID,
        },
        {
          name: "wrong-origin",
          assertion: assertWithSoftwarePasskey(passkey, { challenge, rpID, origin: "http://evil.example" }),
          expectedChallenge: challenge,
          expectedOrigin: origin,
          rpId: rpID,
        },
        {
          name: "up-only",
          assertion: assertWithSoftwarePasskey(passkey, { challenge, rpID, origin, flags: 0x01 }),
          expectedChallenge: challenge,
          expectedOrigin: origin,
          rpId: rpID,
        },
        (() => {
          const assertion = assertWithSoftwarePasskey(passkey, { challenge, rpID, origin });
          const signature = assertion.response.signature;
          const flipped = signature.slice(0, -1) + (signature.endsWith("A") ? "B" : "A");
          return {
            name: "bad-signature",
            assertion: { ...assertion, response: { ...assertion.response, signature: flipped } },
            expectedChallenge: challenge,
            expectedOrigin: origin,
            rpId: rpID,
          };
        })(),
        {
          name: "wrong-rp-id",
          assertion: assertWithSoftwarePasskey(passkey, { challenge, rpID, origin }),
          expectedChallenge: challenge,
          expectedOrigin: origin,
          rpId: "evil.example",
        },
        {
          name: "cross-origin",
          assertion: assertWithSoftwarePasskey(passkey, {
            challenge,
            rpID,
            origin,
            crossOrigin: true,
            topOrigin: "https://parent.example",
          }),
          expectedChallenge: challenge,
          expectedOrigin: origin,
          rpId: rpID,
        },
      ];
      for (const row of rows) {
        const ours = verifyAssertion({
          response: row.assertion,
          expectedChallenge: row.expectedChallenge,
          expectedOrigins: [row.expectedOrigin],
          rpId: row.rpId,
          publicKeyCose,
        });
        let referee = false;
        try {
          const result = await verifyAuthenticationResponse({
            response: row.assertion,
            expectedChallenge: row.expectedChallenge,
            expectedOrigin: row.expectedOrigin,
            expectedRPID: row.rpId,
            requireUserVerification: true,
            credential: { id: passkey.id, publicKey: new Uint8Array(passkey.publicKeyCose), counter: 0 },
          });
          referee = result.verified;
        } catch {
          referee = false;
        }
        assert.equal(ours.ok, referee, `${alg} ${row.name}`);
        if (row.name === "valid") assert.equal(ours.ok, true, `${alg} valid`);
      }
      const bare = assertWithSoftwarePasskey(passkey, { challenge, rpID, origin, crossOrigin: true });
      assert.equal(
        verifyAssertion({
          response: bare,
          expectedChallenge: challenge,
          expectedOrigins: [origin],
          rpId: rpID,
          publicKeyCose,
        }).ok,
        false,
        `${alg} cross-origin without topOrigin`,
      );
    }
  });

  it("D2 rejects an unsupported COSE key without throwing", () => {
    const passkey = mintSoftwarePasskey();
    const assertion = assertWithSoftwarePasskey(passkey, {
      challenge: "challenge-1",
      rpID: "localhost",
      origin: "http://localhost:4173",
    });
    const p384: Array<[number, number | Uint8Array]> = [
      [1, 2],
      [3, -7],
      [-1, 2],
      [-2, new Uint8Array(48)],
      [-3, new Uint8Array(48)],
    ];
    const es384: Array<[number, number | Uint8Array]> = [
      [1, 2],
      [3, -35],
      [-1, 1],
      [-2, new Uint8Array(32)],
      [-3, new Uint8Array(32)],
    ];
    const keys = [coseMap(p384), coseMap(es384)];
    for (const encoded of keys) {
      const publicKeyCose = isoBase64URL.fromBuffer(new Uint8Array(encoded));
      let key: ReturnType<typeof coseKeyToPublicKey> = null;
      assert.doesNotThrow(() => {
        key = coseKeyToPublicKey(publicKeyCose);
      });
      assert.equal(key, null);
      let verdict: ReturnType<typeof verifyAssertion> = { ok: false, reason: "unset" };
      assert.doesNotThrow(() => {
        verdict = verifyAssertion({
          response: assertion,
          expectedChallenge: "challenge-1",
          expectedOrigins: ["http://localhost:4173"],
          rpId: "localhost",
          publicKeyCose,
        });
      });
      assert.equal(verdict.ok, false);
    }
  });

  it("D4 refuses a crossOrigin that is the string \"true\" rather than false or absent", async () => {
    const { createHash, createSign } = await import("node:crypto");
    const passkey = mintSoftwarePasskey();
    const origin = "http://localhost:5173";
    const challenge = isoBase64URL.fromBuffer(new Uint8Array(32).fill(7));
    const base = assertWithSoftwarePasskey(passkey, { challenge, rpID: "localhost", origin });
    const clientDataJSON = JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: "true" });
    const authenticatorData = Buffer.from(isoBase64URL.toBuffer(base.response.authenticatorData));
    const signature = createSign("SHA256")
      .update(Buffer.concat([authenticatorData, createHash("sha256").update(clientDataJSON).digest()]))
      .sign(passkey.privateKey);
    const result = verifyAssertion({
      response: {
        ...base,
        response: {
          ...base.response,
          clientDataJSON: isoBase64URL.fromUTF8String(clientDataJSON),
          signature: isoBase64URL.fromBuffer(new Uint8Array(signature)),
        },
      },
      expectedChallenge: challenge,
      expectedOrigins: [origin],
      rpId: "localhost",
      publicKeyCose: isoBase64URL.fromBuffer(new Uint8Array(passkey.publicKeyCose)),
    });
    assert.deepEqual(result, { ok: false, reason: "cross-origin" });
  });

  it("D3 body source does not import @simplewebauthn", () => {
    const src = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "body", "src");
    const importPattern =
      /(?:import|export)\s*(?:[\s\S]{0,500}?from\s*)?["']@simplewebauthn\b|import\s*\(\s*["']@simplewebauthn\b|require\s*\(\s*["']@simplewebauthn\b/;
    const hits: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
          continue;
        }
        if (!entry.name.endsWith(".ts")) continue;
        if (importPattern.test(readFileSync(full, "utf8"))) hits.push(full);
      }
    };
    walk(src);
    assert.deepEqual(hits, []);
  });
});

function coseMap(entries: Array<[number, number | Uint8Array]>): Uint8Array {
  const map = new Map<number, number | Uint8Array>();
  for (const [key, value] of entries) map.set(key, value);
  return isoCBOR.encode(map);
}

function readAllowRef(dir: string): string {
  const lines = readFileSync(join(dir, "decisions.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "");
  for (const line of lines) {
    const row = JSON.parse(line) as SignedDecisionRecord;
    if (row.claims.decision === "allow" && row.claims.ref) return row.claims.ref;
  }
  throw new Error("no allow");
}
