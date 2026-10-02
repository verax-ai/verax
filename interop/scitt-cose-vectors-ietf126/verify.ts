/**
 * A verifier for the `vectors-ietf126` set of action-state-group/scitt-cose.
 * The CBOR, COSE_Sign1 and RFC 9162 inclusion code is Verax's own receipt
 * reader (packages/proxy/src/transparency-receipt.ts), the code `verax verify`
 * checks anchor receipts with; the stages around it follow the set's README.
 * No code from that repository is used.
 *
 *   node --experimental-strip-types verify.ts <path-to-scitt-cose>/test-vectors [--json]
 *   node --experimental-strip-types verify.ts <path> --mutate
 *
 * Stages, in order: statement-decode, statement-sig, leaf-entry, vds-gate,
 * receipt-decode, inclusion, receipt-sig. A vector the receipt profile here
 * does not cover (vds other than 1 on a VALID vector) is reported SCOPE-OUT
 * rather than counted as a pass or a failure.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  decodeCborItem as decodeCbor,
  decodeSign1,
  rootFromInclusion,
  sign1Structure as sigStructure,
  verifyCoseSignature as verifyCose,
} from "../../packages/proxy/src/transparency-receipt.ts";

const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();

// ---- one vector ----

const STAGES = [
  "statement-decode",
  "statement-sig",
  "leaf-entry",
  "vds-gate",
  "receipt-decode",
  "inclusion",
  "receipt-sig",
] as const;
type Stage = (typeof STAGES)[number];

type Files = {
  statement: Uint8Array;
  receipt: Uint8Array;
  issuerKey: string;
  logKey: string;
  expected: { result: string; failure_code?: string; leaf_entry: string; reconstructed_root: string | null };
};

type Verdict = { result: "VALID" | "INVALID"; stage: Stage | null; detail: string; root: string | null };

class StageFailure extends Error {
  readonly stage: Stage;
  constructor(stage: Stage, message: string) {
    super(message);
    this.stage = stage;
  }
}

function run(f: Files): Verdict {
  let stage: Stage = "statement-decode";
  let root: string | null = null;
  try {
    const statement = decodeSign1(f.statement);
    if (statement.payload === null) throw new StageFailure(stage, "statement payload is detached; none supplied");
    stage = "statement-sig";
    const alg = statement.protectedHeader.get(1);
    if (!verifyCose(alg, f.issuerKey, sigStructure(statement.protectedBytes, statement.payload), statement.signature)) {
      throw new StageFailure(stage, `statement signature (alg ${String(alg)}) does not verify`);
    }
    // README: the leaf entry is SHA-256 over the complete statement bytes.
    stage = "leaf-entry";
    const leafEntry = sha256(f.statement);
    if (leafEntry.toString("hex") !== f.expected.leaf_entry) throw new StageFailure(stage, "leaf entry differs from expected.json");
    stage = "vds-gate";
    const receipt = decodeSign1(f.receipt);
    // vds (label 395) is read from the protected header only.
    const vds = receipt.protectedHeader.get(395);
    if (vds !== 1) throw new StageFailure(stage, `vds ${String(vds)} is not RFC9162_SHA256 (1)`);
    stage = "receipt-decode";
    const vdp = receipt.unprotected.get(396);
    if (!(vdp instanceof Map)) throw new StageFailure(stage, "no vdp map at unprotected label 396");
    const proofs = vdp.get(-1);
    if (!Array.isArray(proofs) || proofs.length !== 1 || !(proofs[0] instanceof Uint8Array)) {
      throw new StageFailure(stage, "vdp -1 is not one inclusion proof");
    }
    const proof = decodeCbor(proofs[0]);
    if (!Array.isArray(proof) || proof.length !== 3) throw new StageFailure(stage, "inclusion proof is not [tree_size, leaf_index, path]");
    const [treeSize, leafIndex, path] = proof as [unknown, unknown, unknown];
    if (typeof treeSize !== "number" || typeof leafIndex !== "number" || !Array.isArray(path) || !path.every((p) => p instanceof Uint8Array)) {
      throw new StageFailure(stage, "inclusion proof member types");
    }
    if (receipt.payload !== null) throw new StageFailure(stage, "receipt payload must be detached (the root)");
    stage = "inclusion";
    const computed = rootFromInclusion(leafEntry, leafIndex, treeSize, path as Uint8Array[]);
    root = computed.toString("hex");
    stage = "receipt-sig";
    const ralg = receipt.protectedHeader.get(1);
    if (!verifyCose(ralg, f.logKey, sigStructure(receipt.protectedBytes, computed), receipt.signature)) {
      throw new StageFailure(stage, `receipt signature (alg ${String(ralg)}) does not verify over the reconstructed root`);
    }
    return { result: "VALID", stage: null, detail: "all stages pass", root };
  } catch (err) {
    const failed = err instanceof StageFailure ? err.stage : stage;
    return { result: "INVALID", stage: failed, detail: err instanceof Error ? err.message : String(err), root };
  }
}

// ---- the set ----

/** The set's failure codes, against the stage this verifier names first. */
const CODE_STAGE: Record<string, Stage> = {
  BAD_STATEMENT_SIGNATURE: "statement-sig",
  UNSUPPORTED_VDS: "vds-gate",
  TAMPERED_INCLUSION_PATH: "receipt-sig",
};

function load(dir: string): Files {
  return {
    statement: readFileSync(join(dir, "statement.cose")),
    receipt: readFileSync(join(dir, "receipt.cose")),
    issuerKey: readFileSync(join(dir, "issuer-key.pub"), "utf8"),
    logKey: readFileSync(join(dir, "log-key.pub"), "utf8"),
    expected: JSON.parse(readFileSync(join(dir, "expected.json"), "utf8")) as Files["expected"],
  };
}

function checkSums(root: string): string[] {
  const bad: string[] = [];
  for (const line of readFileSync(join(root, "SHA256SUMS"), "utf8").split("\n")) {
    const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line.trim());
    if (!m) continue;
    const digest = createHash("sha256").update(readFileSync(join(root, m[2]!))).digest("hex");
    if (digest !== m[1]) bad.push(m[2]!);
  }
  return bad;
}

function flip(bytes: Uint8Array, at: number): Uint8Array {
  const copy = Uint8Array.from(bytes);
  copy[at] = copy[at]! ^ 0x01;
  return copy;
}

const root = process.argv[2];
if (!root) {
  console.error("usage: verify.ts <scitt-cose>/test-vectors [--json | --mutate]");
  process.exit(2);
}
const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")) as {
  vectors: { id: string; dir: string; expected_result: string; failure_code?: string }[];
};

if (process.argv.includes("--mutate")) {
  // One payload byte, one signature byte, one audit-path byte, on the honest EdDSA vector.
  const base = load(join(root, "v1", "valid-eddsa"));
  const st = decodeSign1(base.statement);
  const payloadAt = Buffer.from(base.statement).indexOf(Buffer.from(st.payload!)) + 1;
  const proofBytes = (decodeSign1(base.receipt).unprotected.get(396) as Map<unknown, unknown[]>).get(-1)![0] as Uint8Array;
  const pathAt = Buffer.from(base.receipt).indexOf(Buffer.from(proofBytes)) + proofBytes.length - 1;
  const cases: { name: string; files: Files; stage: Stage }[] = [
    { name: "statement payload byte", files: { ...base, statement: flip(base.statement, payloadAt) }, stage: "statement-sig" },
    { name: "statement signature byte", files: { ...base, statement: flip(base.statement, base.statement.length - 10) }, stage: "statement-sig" },
    { name: "receipt audit-path byte", files: { ...base, receipt: flip(base.receipt, pathAt) }, stage: "receipt-sig" },
  ];
  let misses = 0;
  for (const c of cases) {
    const v = run(c.files);
    const ok = v.result === "INVALID" && v.stage === c.stage;
    if (!ok) misses += 1;
    console.log(`${ok ? "ok  " : "FAIL"} mutate ${c.name.padEnd(26)} ${v.result} at ${v.stage}: ${v.detail}`);
  }
  process.exit(misses === 0 ? 0 : 1);
}

const sums = checkSums(root);
const results = manifest.vectors.map((entry) => {
  const files = load(join(root, entry.dir));
  const v = run(files);
  const wantStage = entry.failure_code ? CODE_STAGE[entry.failure_code] ?? null : null;
  const scopeOut = entry.expected_result === "VALID" && v.stage === "vds-gate";
  const match = scopeOut ? null : v.result === entry.expected_result && v.stage === wantStage;
  // Null when either side has no root: expected.json names none, or this run stopped before the inclusion stage.
  const rootAgrees =
    files.expected.reconstructed_root === null || v.root === null ? null : v.root === files.expected.reconstructed_root;
  return {
    id: entry.id,
    expected: entry.expected_result,
    failure_code: entry.failure_code ?? null,
    got: v.result,
    stage: v.stage,
    detail: v.detail,
    reconstructed_root_agrees: rootAgrees,
    outcome: scopeOut ? "SCOPE-OUT" : match ? "PASS" : "MISMATCH",
  };
});

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ sha256sums_mismatches: sums, results }, null, 2));
} else {
  console.log(`SHA256SUMS: ${sums.length === 0 ? "every listed file verifies" : `mismatch: ${sums.join(", ")}`}`);
  for (const r of results) {
    console.log(`${r.outcome.padEnd(9)} ${r.id.padEnd(24)} ${r.got.padEnd(8)} ${String(r.stage ?? "-").padEnd(14)} ${r.detail}`);
  }
}
process.exit(sums.length === 0 && results.every((r) => r.outcome !== "MISMATCH") ? 0 : 1);
