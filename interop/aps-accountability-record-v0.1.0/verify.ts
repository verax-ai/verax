/**
 * Runs the `accountability-record` fixtures of aeoess/aps-conformance-suite
 * v0.1.0 through checks written here from the fixture README and schema.
 * Canonicalization is Cedulon's RFC 8785 implementation (@cedulon/core),
 * signatures are node:crypto Ed25519. No code from that repository is used.
 *
 *   node --experimental-strip-types verify.ts <aps-conformance-suite> [--json]
 *
 * Stages, in order: SCHEMA, CANONICAL, DIGEST, SIGNATURE. Every stage runs on
 * every vector and is reported. A negative passes when the stage its
 * rejection_kind names fails; the first failing stage is reported beside it.
 */
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { canonical } from "@cedulon/core";

type Record_ = Record<string, unknown>;
type Vector = {
  name: string;
  record: Record_;
  signing_input_bytes_hex: string;
  canonical_sha256: string;
  expected_verification: boolean;
  rejection_kind?: "schema" | "signature" | "digest_mismatch";
  expected_error_code?: string;
};
type Fixture = { keypair: { publicKeyHex: string }; vectors: Vector[] };

const STAGES = ["SCHEMA", "CANONICAL", "DIGEST", "SIGNATURE"] as const;
type Stage = (typeof STAGES)[number];
type StageResult = "pass" | "fail" | "skipped";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
// RFC 3339 date-time, as JSON Schema's "date-time" format names it.
const DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;
const URI = /^[A-Za-z][A-Za-z0-9+.-]*:\S+$/;

/** The schema's constraints, applied by hand. Returns the first violation or null. */
function schemaProblem(r: Record_): string | null {
  const allowed = new Set([
    "spec_version", "record_type", "action_ref", "action_digest", "action", "signer_did", "agent_did",
    "delegation_ref", "principal_ref", "decision", "executed", "issued_at", "settlement_ref",
    "settlement_rail", "sig", "sig_alg",
  ]);
  for (const key of Object.keys(r)) if (!allowed.has(key)) return `additional property ${key}`;
  for (const key of [
    "spec_version", "record_type", "action_ref", "action_digest", "signer_did", "agent_did",
    "delegation_ref", "principal_ref", "decision", "executed", "issued_at", "sig", "sig_alg",
  ]) {
    if (!(key in r)) return `missing ${key}`;
  }
  if (typeof r.spec_version !== "string") return "spec_version is not a string";
  if (r.record_type !== "accountability_record") return "record_type is not accountability_record";
  if (typeof r.action_ref !== "string" || !HEX64.test(r.action_ref)) return "action_ref pattern";
  const digest = r.action_digest as Record_ | undefined;
  if (!digest || typeof digest !== "object" || Array.isArray(digest)) return "action_digest is not an object";
  if (Object.keys(digest).some((k) => k !== "sha256")) return "action_digest additional property";
  if (typeof digest.sha256 !== "string" || !HEX64.test(digest.sha256)) return "action_digest.sha256 pattern";
  if ("action" in r) {
    const a = r.action as Record_;
    if (!a || typeof a !== "object" || Array.isArray(a)) return "action is not an object";
    if (Object.keys(a).some((k) => !["type", "scope", "timestamp"].includes(k))) return "action additional property";
    if (typeof a.type !== "string") return "action.type";
    if (!Array.isArray(a.scope) || !a.scope.every((s) => typeof s === "string")) return "action.scope";
    if (typeof a.timestamp !== "string" || !DATE_TIME.test(a.timestamp)) return "action.timestamp format";
  }
  for (const key of ["signer_did", "agent_did"]) {
    if (typeof r[key] !== "string" || !URI.test(r[key] as string)) return `${key} format`;
  }
  for (const key of ["delegation_ref", "principal_ref"]) if (typeof r[key] !== "string") return `${key} type`;
  if (!["allow", "deny", "halt"].includes(r.decision as string)) return `decision ${JSON.stringify(r.decision)} is not in the enum`;
  if (typeof r.executed !== "boolean") return "executed is not a boolean";
  if (typeof r.issued_at !== "string" || !DATE_TIME.test(r.issued_at)) return "issued_at format";
  for (const key of ["settlement_ref", "settlement_rail"]) if (key in r && typeof r[key] !== "string") return `${key} type`;
  if (typeof r.sig !== "string" || !HEX128.test(r.sig)) return "sig pattern";
  if (r.sig_alg !== "Ed25519") return `sig_alg ${JSON.stringify(r.sig_alg)} is not the const Ed25519`;
  return null;
}

const sha256Hex = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
// RFC 8410 SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 key.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function check(v: Vector, publicKeyHex: string) {
  const stages: Record<Stage, StageResult> = { SCHEMA: "skipped", CANONICAL: "skipped", DIGEST: "skipped", SIGNATURE: "skipped" };
  const notes: string[] = [];
  const schema = schemaProblem(v.record);
  stages.SCHEMA = schema === null ? "pass" : "fail";
  if (schema) notes.push(`SCHEMA: ${schema}`);

  const { sig, ...unsigned } = v.record;
  const signingInput = Buffer.from(canonical(unsigned), "utf8");
  const parity = signingInput.toString("hex") === v.signing_input_bytes_hex;
  const fullParity = sha256Hex(Buffer.from(canonical(v.record), "utf8")) === v.canonical_sha256;
  stages.CANONICAL = parity && fullParity ? "pass" : "fail";
  if (!parity) notes.push("CANONICAL: signing input bytes differ from signing_input_bytes_hex");
  if (!fullParity) notes.push("CANONICAL: SHA-256 of the full record's JCS differs from canonical_sha256");

  const action = v.record.action;
  if (action === undefined) {
    notes.push("DIGEST: payload-unverified (action not inline)");
  } else {
    const ok = sha256Hex(Buffer.from(canonical(action), "utf8")) === (v.record.action_digest as Record_)?.sha256;
    stages.DIGEST = ok ? "pass" : "fail";
    if (!ok) notes.push("DIGEST: sha256(JCS(action)) differs from action_digest.sha256");
  }

  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]), format: "der", type: "spki" });
  const sigOk = typeof sig === "string" && HEX128.test(sig) && verifySignature(null, signingInput, key, Buffer.from(sig, "hex"));
  stages.SIGNATURE = sigOk ? "pass" : "fail";
  if (!sigOk) notes.push("SIGNATURE: Ed25519 over the signing input does not verify under keypair.publicKeyHex");

  const first = STAGES.find((s) => stages[s] === "fail") ?? null;
  return { stages, first, notes };
}

const KIND_STAGE: Record<string, Stage> = { schema: "SCHEMA", signature: "SIGNATURE", digest_mismatch: "DIGEST" };

const suite = process.argv[2];
if (!suite) {
  console.error("usage: verify.ts <aps-conformance-suite> [--json]");
  process.exit(2);
}
const fixture = JSON.parse(
  readFileSync(join(suite, "fixtures", "accountability-record", "accountability-record-fixture-v1.json"), "utf8"),
) as Fixture;

const results = fixture.vectors.map((v) => {
  const r = check(v, fixture.keypair.publicKeyHex);
  const verified = r.first === null;
  const wantStage = v.rejection_kind ? KIND_STAGE[v.rejection_kind] ?? null : null;
  // A negative passes when the stage it declares fails. A vector can fail at
  // more than one stage (negative-type-relabel also breaks the record_type
  // const, as its description says); the first failing stage is reported too.
  const match = verified === v.expected_verification && (wantStage === null || r.stages[wantStage] === "fail");
  return {
    name: v.name,
    expected_verification: v.expected_verification,
    expected_stage: wantStage,
    verified,
    first_failing_stage: r.first,
    stages: r.stages,
    notes: r.notes,
    outcome: match ? "PASS" : "MISMATCH",
  };
});

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ results }, null, 2));
} else {
  for (const r of results) {
    const s = STAGES.map((k) => `${k}=${r.stages[k]}`).join(" ");
    console.log(`${r.outcome.padEnd(8)} ${r.name.padEnd(34)} ${String(r.first_failing_stage ?? "-").padEnd(9)} ${s}`);
  }
  console.log(`${results.filter((r) => r.outcome === "PASS").length}/${results.length} as expected`);
}
process.exit(results.every((r) => r.outcome === "PASS") ? 0 : 1);
