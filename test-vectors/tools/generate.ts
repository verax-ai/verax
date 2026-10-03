/**
 * Writes `test-vectors/v1/` from two captured ledgers.
 *
 * `valid-*` vectors are the captured ledgers as the body wrote them. Each
 * `fail-*` vector changes one thing in a copy of `valid-full`. Where that
 * change alters a record's octets, every later record is re-linked and
 * re-signed, and the checkpoint is re-signed, so the only check that can fail
 * is the one the vector names. The private keys that re-signing needs stay in
 * the capture directory, which is removed at the end.
 *
 * v1 is append-only once published. Running this again produces different
 * keys, nonces and times; it is for building a new version directory, never
 * for rewriting this one.
 */
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildCheckpointClaims,
  signCheckpoint,
  totalsFromDecisionRecords,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import {
  decisionRecordHash,
  decisionRecordToCbor,
  signDecisionRecord,
  type SignedDecisionRecord,
} from "@cedulon/core";
import { cborMap, encodeCbor, kidFromPublicKeyPem } from "@cedulon/cose";

import { sha256Canonical } from "../../packages/proxy/src/hash.ts";
import { capture } from "./capture.ts";
import { STAGES, type Stage } from "./stages.ts";

const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, "..", "v1");

type KeyPair = { privateKeyPem: string; publicKeyPem: string };
type Row = Record<string, unknown>;
type Ledger = {
  decisions: SignedDecisionRecord[];
  effects: Row[];
  inputs: Row[];
  index: Row[];
  checkpoints: SignedCheckpoint[];
};
type Captured = { ledger: Ledger; record: KeyPair; witness: KeyPair; credentials: string };
type Vector = {
  id: string;
  description: string;
  spec: string[];
  stage: Stage | null;
  ledger: Ledger;
  pins?: { record?: string };
};

function readJsonl<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as T);
}

function pair(dir: string, name: string): KeyPair {
  return {
    privateKeyPem: readFileSync(join(dir, "keys", `${name}.private.pem`), "utf8"),
    publicKeyPem: readFileSync(join(dir, "keys", `${name}.public.pem`), "utf8"),
  };
}

function load(stateDir: string): Captured {
  return {
    ledger: {
      decisions: readJsonl(join(stateDir, "decisions.jsonl")),
      effects: readJsonl(join(stateDir, "effects.jsonl")),
      inputs: readJsonl(join(stateDir, "inputs.jsonl")),
      index: readJsonl(join(stateDir, "index.jsonl")),
      checkpoints: readJsonl(join(stateDir, "checkpoints.jsonl")),
    },
    record: pair(stateDir, "record"),
    witness: pair(stateDir, "witness"),
    credentials: readFileSync(join(stateDir, "operator-credentials.json"), "utf8"),
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** The row shape the body writes, keys in the same order. */
function recordRow(claims: SignedDecisionRecord["claims"], publicKeyPem: string, coseHex: string): SignedDecisionRecord {
  return { claims, coseHex, encoding: "cose", publicKeyPem } as SignedDecisionRecord;
}

/**
 * A Decision Record signed with an arbitrary protected header and no claim
 * rules applied. `signDecisionRecord` refuses both, which is right for the
 * body and wrong for a vector whose point is that a verifier refuses them.
 */
function signRaw(
  claims: SignedDecisionRecord["claims"],
  key: KeyPair,
  header: { alg: number; contentType: string },
): SignedDecisionRecord {
  const payload = decisionRecordToCbor(claims);
  const protectedHeader = encodeCbor(
    cborMap([
      [1, header.alg],
      [3, header.contentType],
      [4, kidFromPublicKeyPem(key.publicKeyPem)],
    ]),
  );
  const toBeSigned = encodeCbor(["Signature1", protectedHeader, new Uint8Array(0), payload]);
  const signature = sign(null, Buffer.from(toBeSigned), key.privateKeyPem);
  const cose = encodeCbor([protectedHeader, cborMap([]), payload, new Uint8Array(signature)]);
  return recordRow(claims, key.publicKeyPem, Buffer.from(cose).toString("hex"));
}

const CTY_RECORD = "application/cedulon-decision-record+cbor";

/** Re-signs records after `from` so each names its predecessor's hash again. */
function relink(ledger: Ledger, from: number, key: KeyPair): void {
  for (let i = from + 1; i < ledger.decisions.length; i += 1) {
    const claims = { ...ledger.decisions[i]!.claims, prevRecordHash: decisionRecordHash(ledger.decisions[i - 1]!) };
    ledger.decisions[i] = signDecisionRecord(claims, key.privateKeyPem, key.publicKeyPem);
  }
}

/** Signs the checkpoint again over the records as they now stand, same window. */
function resignCheckpoint(
  ledger: Ledger,
  witness: KeyPair,
  over: (claims: SignedCheckpoint["claims"]) => SignedCheckpoint["claims"] = (c) => c,
): void {
  const old = ledger.checkpoints[0];
  if (!old) return;
  const { epoch, startMs, endMs } = old.claims;
  const inWindow = ledger.decisions.filter((d) => d.claims.timestampMs >= startMs && d.claims.timestampMs < endMs);
  const claims = buildCheckpointClaims(
    epoch,
    inWindow,
    startMs,
    endMs,
    null,
    totalsFromDecisionRecords,
    (row: SignedDecisionRecord) => decisionRecordHash(row),
  );
  ledger.checkpoints = [signCheckpoint(over(claims), witness.privateKeyPem, witness.publicKeyPem)];
}

/** Replaces record `i`, then restores the chain and the checkpoint around it. */
function replaceRecord(c: Captured, ledger: Ledger, i: number, row: SignedDecisionRecord): void {
  ledger.decisions[i] = row;
  relink(ledger, i, c.record);
  resignCheckpoint(ledger, c.witness);
}

function flipHexByte(hex: string, fromEnd: number): string {
  const at = hex.length - 2 * fromEnd;
  const byte = Number.parseInt(hex.slice(at, at + 2), 16) ^ 0x01;
  return hex.slice(0, at) + byte.toString(16).padStart(2, "0") + hex.slice(at + 2);
}

function flipBase64UrlByte(b64: string, at: number): string {
  const bytes = Buffer.from(b64, "base64url");
  bytes[at] = bytes[at]! ^ 0x01;
  return bytes.toString("base64url");
}

function indexOf(ledger: Ledger, pick: (c: SignedDecisionRecord["claims"]) => boolean): number {
  const i = ledger.decisions.findIndex((d) => pick(d.claims));
  if (i < 0) throw new Error("vector-source-record-missing");
  return i;
}

function dropRef(ledger: Ledger, ref: string): void {
  ledger.decisions = ledger.decisions.filter((d) => d.claims.ref !== ref);
  ledger.effects = ledger.effects.filter((e) => (e.row as Row | undefined)?.ref !== ref);
  ledger.inputs = ledger.inputs.filter((r) => r.ref !== ref);
  ledger.index = ledger.index.filter((r) => r.ref !== ref);
}

function vectors(full: Captured, denyOnly: Captured): Vector[] {
  const out: Vector[] = [];
  const base = () => clone(full.ledger);
  const isSpendDeny = (c: SignedDecisionRecord["claims"]) => c.decision === "deny" && c.subject === "spend";

  out.push({
    id: "valid-full",
    description:
      "A ledger written by a running Verax body: a write deferred for approval, the operator's passkey approval, the agent's retry that runs it, an allowed read, a refused spend, a halt, a read refused while halted, a resume and an allowed read. Effects are witnessed by a second process; one checkpoint covers every record.",
    spec: ["decision-profile-03 4.1-4.4", "core-03 7.2"],
    stage: null,
    ledger: base(),
  });
  out.push({
    id: "valid-deny-only",
    description: "The smallest ledger: one refused call, one record, no effect. A first verifier needs only record and chain checks to pass it.",
    spec: ["decision-profile-03 4.1-4.2"],
    stage: null,
    ledger: clone(denyOnly.ledger),
  });

  {
    const l = base();
    const i = indexOf(l, isSpendDeny);
    const row = l.decisions[i]!;
    replaceRecord(full, l, i, { ...row, coseHex: flipHexByte(row.coseHex, 32) } as SignedDecisionRecord);
    out.push({
      id: "fail-record-signature",
      description:
        "One byte of the refused spend record's Ed25519 signature is flipped. Later records are re-linked to the changed octets and the checkpoint is re-signed, so only that signature fails.",
      spec: ["core-03 7.2"],
      stage: "record-signature",
      ledger: l,
    });
  }
  {
    const l = base();
    const i = indexOf(l, isSpendDeny);
    replaceRecord(full, l, i, signRaw(l.decisions[i]!.claims, full.record, { alg: -8, contentType: CTY_RECORD }));
    out.push({
      id: "fail-record-alg-8",
      description:
        "The refused spend record re-signed by the same key over the same payload, with protected alg -8 (generic EdDSA) instead of -19. The signature is valid; the profile requires -19.",
      spec: ["core-03 7.2 (MUST-T4-1)", "RFC 9864"],
      stage: "record-header",
      ledger: l,
    });
  }
  {
    const l = base();
    const i = indexOf(l, isSpendDeny);
    replaceRecord(
      full,
      l,
      i,
      signRaw(l.decisions[i]!.claims, full.record, { alg: -19, contentType: "application/cedulon-decision+cbor" }),
    );
    out.push({
      id: "fail-record-content-type",
      description:
        "The refused spend record re-signed with the Decision Token content type. The signature is valid; a record presented under the token type is refused before any claim is read.",
      spec: ["decision-profile-03 4.3 (MUST-DP-4)"],
      stage: "record-header",
      ledger: l,
    });
  }
  {
    const l = base();
    out.push({
      id: "fail-record-key-not-pinned",
      description:
        "The ledger of valid-full, checked against a pinned record key that did not sign it. The records carry the signer's key beside them; a carried key is not an identity source.",
      spec: ["core-03 7.2 (kid)", "core-03 7.3 (MUST-T4-11)"],
      stage: "record-header",
      ledger: l,
      pins: { record: generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString() },
    });
  }
  {
    const l = base();
    const i = indexOf(l, isSpendDeny);
    const row = l.decisions[i]!;
    l.decisions[i] = { ...row, claims: { ...row.claims, decision: "allow", reasonCode: "allow" } };
    out.push({
      id: "fail-record-claims-mismatch",
      description:
        "The decoded claims presented beside the refused spend record say allow; the signed payload says deny. The COSE octets are untouched, so the signature and the chain still verify.",
      spec: ["core-03 7.3", "decision-profile-03 4.3"],
      stage: "record-claims",
      ledger: l,
    });
  }
  {
    const l = base();
    const i = indexOf(l, isSpendDeny);
    const claims = { ...l.decisions[i]!.claims, effectHash: sha256Canonical({ vector: "refusal-with-effect-hash" }) };
    replaceRecord(full, l, i, signRaw(claims, full.record, { alg: -19, contentType: CTY_RECORD }));
    out.push({
      id: "fail-record-claim-rule",
      description:
        "The refused spend record re-signed with a non-null effectHash, which the claim rules forbid on a refusal. Header, signature and chain are valid; the verifier must apply the rules itself.",
      spec: ["decision-profile-03 4.2 (MUST-DP-2, MUST-DP-3)"],
      stage: "record-claims",
      ledger: l,
    });
  }
  {
    const l = base();
    const ref = l.decisions[indexOf(l, isSpendDeny)]!.claims.ref as string;
    // The index line and the inputs row go too, so the chain is the only check left that sees it.
    dropRef(l, ref);
    out.push({
      id: "fail-chain-removed",
      description:
        "The refused spend record is removed from the middle of the ledger, with its index line and inputs row. Nothing is re-signed: the next record still names the removed record's hash.",
      spec: ["decision-profile-03 4.4 (MUST-DP-5)"],
      stage: "chain",
      ledger: l,
    });
  }
  {
    const l = base();
    const i = indexOf(l, (c) => c.reasonCode === "approved-by-operator");
    const allowRef = l.decisions[i]!.claims.ref;
    const at = l.inputs.findIndex((r) => r.ref === allowRef);
    const row = clone(l.inputs[at]!) as { inputs: { approver: { via: string; signature?: unknown } } };
    row.inputs.approver.via = "cli";
    delete row.inputs.approver.signature;
    l.inputs[at] = row as unknown as Row;
    out.push({
      id: "fail-inputs-approver-downgraded",
      description:
        "The inputs row of the approved write is edited to read as an unsigned command-line approval: the passkey assertion is removed. The approve record's signed inputsHash still commits to the original row.",
      spec: ["decision-profile-03 4.1 (inputsHash)"],
      stage: "inputs-binding",
      ledger: l,
    });
  }
  {
    const l = base();
    const i = indexOf(l, (c) => c.reasonCode === "approved-by-operator");
    const allowRef = l.decisions[i]!.claims.ref;
    const at = l.inputs.findIndex((r) => r.ref === allowRef);
    const row = clone(l.inputs[at]!) as { inputs: { approver: { signature: { signature: string } } } };
    row.inputs.approver.signature.signature = flipBase64UrlByte(row.inputs.approver.signature.signature, 8);
    l.inputs[at] = row as unknown as Row;
    const claims = { ...l.decisions[i]!.claims, inputsHash: sha256Canonical((row as unknown as { inputs: unknown }).inputs) };
    replaceRecord(full, l, i, signDecisionRecord(claims, full.record.privateKeyPem, full.record.publicKeyPem));
    out.push({
      id: "fail-approval-signature",
      description:
        "One byte of the operator's passkey (WebAuthn) signature on the approval is flipped. The approve record is re-signed over the changed inputs and the chain and checkpoint are restored, so only the assertion fails.",
      spec: ["Verax approval binding (STATUS v0.4.2)", "WebAuthn Level 3 7.2"],
      stage: "approval-signature",
      ledger: l,
    });
  }
  {
    const l = base();
    const at = l.effects.findIndex((e) => (e.row as Row).effectClass === "memory.get");
    const row = clone(l.effects[at]!) as { row: { effectHash: string } };
    row.row.effectHash = sha256Canonical({ vector: "different-effect" });
    l.effects[at] = row as unknown as Row;
    out.push({
      id: "fail-effect-hash",
      description:
        "The first read's effect row claims a different effectHash than the allow that admitted it. The records and checkpoint are untouched.",
      spec: ["decision-profile-03 6 (binding)"],
      stage: "effect-binding",
      ledger: l,
    });
  }
  {
    const l = base();
    const cp = l.checkpoints[0]!;
    l.checkpoints = [{ ...cp, coseHex: flipHexByte(cp.coseHex, 32) }];
    out.push({
      id: "fail-checkpoint-signature",
      description: "One byte of the witness's signature on the checkpoint is flipped.",
      spec: ["core-03 11.1", "core-03 7.2"],
      stage: "checkpoint-signature",
      ledger: l,
    });
  }
  {
    const l = base();
    const last = l.decisions[l.decisions.length - 1]!.claims.ref as string;
    dropRef(l, last);
    out.push({
      id: "fail-tail-truncated",
      description:
        "The newest record is removed with its effect row, inputs row and index line. The chain of what remains is intact; only the checkpoint, which counted it, still knows it was there.",
      spec: ["decision-profile-03 4.4", "core-03 11.1"],
      stage: "checkpoint-coverage",
      ledger: l,
    });
  }
  {
    const l = base();
    resignCheckpoint(l, full.witness, (claims) => ({
      ...claims,
      totals: { ...(claims.totals as Record<string, string>), allow: String(Number((claims.totals as Record<string, string>).allow) - 1) },
    }));
    out.push({
      id: "fail-checkpoint-totals",
      description:
        "The checkpoint is re-signed by the witness key with an allow total one lower than the records in its window. Signature, count and head all match.",
      spec: ["decision-profile-03 4.4 (checkpoint-total-mismatch)"],
      stage: "checkpoint-totals",
      ledger: l,
    });
  }
  {
    const l = base();
    const i = indexOf(l, (c) => c.decision === "deny" && c.reasonCode === "halted");
    const claims = {
      ...l.decisions[i]!.claims,
      decision: "allow" as const,
      reasonCode: "allow",
      effectHash: sha256Canonical({ vector: "allowed-while-halted" }),
    };
    replaceRecord(full, l, i, signDecisionRecord(claims, full.record.privateKeyPem, full.record.publicKeyPem));
    out.push({
      id: "fail-allow-while-halted",
      description:
        "The read refused while halted is re-signed as an allow by the record key, chain and checkpoint restored. Every signature verifies; the allow sits inside the halt window.",
      spec: ["Verax control records (STATUS v0.4.2)"],
      stage: "control",
      ledger: l,
    });
  }
  return out;
}

function writeJsonl(path: string, rows: unknown[]): void {
  writeFileSync(path, rows.map((r) => `${JSON.stringify(r)}\n`).join(""), "utf8");
}

function write(vector: Vector, c: Captured): void {
  const dir = join(OUT, vector.id);
  mkdirSync(join(dir, "ledger"), { recursive: true });
  mkdirSync(join(dir, "pins"), { recursive: true });
  const l = vector.ledger;
  writeJsonl(join(dir, "ledger", "decisions.jsonl"), l.decisions);
  writeJsonl(join(dir, "ledger", "effects.jsonl"), l.effects);
  writeJsonl(join(dir, "ledger", "inputs.jsonl"), l.inputs);
  writeJsonl(join(dir, "ledger", "index.jsonl"), l.index);
  if (l.checkpoints.length > 0) writeJsonl(join(dir, "ledger", "checkpoints.jsonl"), l.checkpoints);
  writeFileSync(join(dir, "pins", "record-key.pem"), vector.pins?.record ?? c.record.publicKeyPem, "utf8");
  writeFileSync(join(dir, "pins", "witness-key.pem"), c.witness.publicKeyPem, "utf8");
  writeFileSync(join(dir, "pins", "operator-credentials.json"), c.credentials, "utf8");
  const expected = {
    id: vector.id,
    description: vector.description,
    spec: vector.spec,
    expected_result: vector.stage === null ? "VALID" : "INVALID",
    first_failing_stage: vector.stage,
    records: l.decisions.length,
    effects: l.effects.length,
    checkpoints: l.checkpoints.length,
    record_hashes: l.decisions.map((d) => decisionRecordHash(d)),
  };
  writeFileSync(join(dir, "expected.json"), `${JSON.stringify(expected, null, 2)}\n`, "utf8");
}

if (existsSync(OUT)) throw new Error(`${OUT} exists: v1 is append-only; build a new version directory instead`);
const fullCapture = await capture();
const denyCapture = await capture({ denyOnly: true });
try {
  const full = load(fullCapture.stateDir);
  const deny = load(denyCapture.stateDir);
  const list = vectors(full, deny);
  for (const v of list) {
    if (v.stage !== null && !STAGES.includes(v.stage)) throw new Error(`unknown stage ${v.stage}`);
    write(v, v.id === "valid-deny-only" ? deny : full);
  }
  const manifest = {
    version: "v1",
    stability: "append-only",
    producer: "Verax body (packages/body) over HTTP, with a witness process; see tools/capture.ts",
    stages: STAGES,
    vectors: list.map((v) => ({
      id: v.id,
      dir: `v1/${v.id}`,
      expected_result: v.stage === null ? "VALID" : "INVALID",
      first_failing_stage: v.stage,
    })),
  };
  writeFileSync(join(OUT, "..", "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`wrote ${list.length} vectors`);
} finally {
  rmSync(fullCapture.stateDir, { recursive: true, force: true });
  rmSync(denyCapture.stateDir, { recursive: true, force: true });
}
process.exit(0);
