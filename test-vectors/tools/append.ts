/**
 * Appends vectors to `test-vectors/v1/` from a fresh capture, without
 * touching a file that is already there.
 *
 * The private keys of the first capture were discarded, so a vector that has
 * to re-sign an effect extract cannot be cut from `valid-full`. This runs the
 * same scenario again under new keys and publishes that ledger as
 * `valid-full-2`, so each `fail-*` vector below still changes one thing in a
 * copy of a published valid ledger. Each vector carries its own pins.
 *
 * It refuses to run if any directory it would write exists. New lines go to
 * the end of `manifest.json` and `SHA256SUMS`; earlier lines are not changed.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildCheckpointClaims,
  signCheckpoint,
  totalsFromDecisionRecords,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { decisionRecordHash, signDecisionRecord, type SignedDecisionRecord } from "@cedulon/core";
import { signEffectExtract } from "@cedulon/effect-extract";

import { sha256Canonical } from "../../packages/proxy/src/hash.ts";
import { signEffectAttestation } from "../../packages/proxy/src/ledger.ts";
import { capture } from "./capture.ts";
import { STAGES, type Stage } from "./stages.ts";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = join(here, "..");
const OUT = join(ROOT, "v1");

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
type Vector = { id: string; description: string; spec: string[]; stage: Stage | null; ledger: Ledger };

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

/** Same as generate.ts: re-signs records after `from` so each names its predecessor again. */
function relink(ledger: Ledger, from: number, key: KeyPair): void {
  for (let i = from + 1; i < ledger.decisions.length; i += 1) {
    const claims = { ...ledger.decisions[i]!.claims, prevRecordHash: decisionRecordHash(ledger.decisions[i - 1]!) };
    ledger.decisions[i] = signDecisionRecord(claims, key.privateKeyPem, key.publicKeyPem);
  }
}

/** Same as generate.ts: signs the checkpoint again over the records as they now stand, same window. */
function resignCheckpoint(ledger: Ledger, witness: KeyPair): void {
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
  ledger.checkpoints = [signCheckpoint(claims, witness.privateKeyPem, witness.publicKeyPem)];
}

function indexOf(ledger: Ledger, pick: (c: SignedDecisionRecord["claims"]) => boolean): number {
  const i = ledger.decisions.findIndex((d) => pick(d.claims));
  if (i < 0) throw new Error("vector-source-record-missing");
  return i;
}

function vectors(c: Captured): Vector[] {
  const base = () => clone(c.ledger);
  const out: Vector[] = [];

  out.push({
    id: "valid-full-2",
    description:
      "The scenario of valid-full captured again under new keys, by a body that signs the resume with the operator's passkey: a write deferred for approval, the operator's passkey approval, the retry that runs it, an allowed read, a refused spend, a halt, a read refused while halted, a resume and an allowed read. The vectors appended with it change one thing in a copy of this ledger.",
    spec: ["decision-profile-03 4.1-4.4", "cedulon-08 6.2"],
    stage: null,
    ledger: base(),
  });

  {
    const l = base();
    const at = l.effects.findIndex((e) => (e.row as Row).effectClass === "memory.get");
    if (at < 0) throw new Error("vector-source-effect-missing");
    const e = clone(l.effects[at]!) as { receipt: { body: { effects: Row[] } & Row } };
    const body = clone(e.receipt.body);
    body.effects[0] = { ...body.effects[0]!, effectHash: sha256Canonical({ vector: "extract-body-changed" }) };
    e.receipt = signEffectExtract(
      body as unknown as Parameters<typeof signEffectExtract>[0],
      c.witness.privateKeyPem,
      c.witness.publicKeyPem,
    ) as unknown as typeof e.receipt;
    l.effects[at] = e as unknown as Row;
    out.push({
      id: "fail-effect-extract-body",
      description:
        "The first read's effect extract is re-signed by the witness key over a body whose row carries a different effectHash. The presented row, its attestation, the records and the checkpoint are untouched, so the presented row still matches its allow and differs only from the row the extract signs.",
      spec: ["decision-profile-03 6 (binding)", "cedulon-08 11.4 step 4"],
      stage: "effect-binding",
      ledger: l,
    });
  }

  {
    const l = base();
    const i = indexOf(l, (cl) => cl.decision === "deny" && cl.reasonCode === "halted");
    const claims = {
      ...l.decisions[i]!.claims,
      decision: "allow" as const,
      reasonCode: "allow",
      effectHash: sha256Canonical({ vector: "allowed-while-halted" }),
    };
    l.decisions[i] = signDecisionRecord(claims, c.record.privateKeyPem, c.record.publicKeyPem);
    relink(l, i, c.record);
    resignCheckpoint(l, c.witness);
    const row = {
      ref: claims.ref as string,
      effectHash: claims.effectHash,
      effectClass: (claims.effectClass as string | null) ?? "memory.get",
      timestampMs: (claims.timestampMs as number) + 1,
      actor: "agent-1",
    };
    const resultHash = sha256Canonical({ vector: "allowed-while-halted-result" });
    const signed = signEffectAttestation(row, "same-org", resultHash, c.witness);
    // Key order as the body writes an effect row.
    const effect: Row = { attestation: signed.attestation, receipt: signed.receipt, resultHash, row, witnessClass: "same-org" };
    const after = l.effects.findIndex((e) => ((e.row as Row).timestampMs as number) > row.timestampMs);
    l.effects.splice(after < 0 ? l.effects.length : after, 0, effect);
    out.push({
      id: "fail-allow-while-halted-witnessed",
      description:
        "As fail-allow-while-halted, and the forged allow is also given an effect row the witness key signs, bound to its effectHash. Every signature verifies and every allow has its row; the allow sits inside the halt window, so only control fails.",
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
  writeFileSync(join(dir, "pins", "record-key.pem"), c.record.publicKeyPem, "utf8");
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

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

const IDS = ["valid-full-2", "fail-effect-extract-body", "fail-allow-while-halted-witnessed"];
for (const id of IDS) {
  if (existsSync(join(OUT, id))) throw new Error(`${id} exists: v1 is append-only`);
}
const captured = await capture();
try {
  const c = load(captured.stateDir);
  const list = vectors(c);
  if (list.map((v) => v.id).join() !== IDS.join()) throw new Error("vector list and IDS disagree");
  for (const v of list) {
    if (v.stage !== null && !STAGES.includes(v.stage)) throw new Error(`unknown stage ${v.stage}`);
    write(v, c);
  }
  const manifestPath = join(ROOT, "manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { vectors: Row[] };
  for (const v of list) {
    manifest.vectors.push({
      id: v.id,
      dir: `v1/${v.id}`,
      expected_result: v.stage === null ? "VALID" : "INVALID",
      first_failing_stage: v.stage,
    });
  }
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const sums: string[] = [];
  for (const v of list) {
    for (const f of filesUnder(join(OUT, v.id))) {
      const digest = createHash("sha256").update(readFileSync(f)).digest("hex");
      sums.push(`${digest}  ${relative(ROOT, f).split("\\").join("/")}`);
    }
  }
  const sumsPath = join(ROOT, "SHA256SUMS");
  const old = readFileSync(sumsPath, "utf8");
  writeFileSync(sumsPath, `${old.endsWith("\n") ? old : `${old}\n`}${sums.join("\n")}\n`, "utf8");
  console.log(`appended ${list.length} vectors, ${sums.length} SHA256SUMS lines`);
} finally {
  rmSync(captured.stateDir, { recursive: true, force: true });
}
process.exit(0);
