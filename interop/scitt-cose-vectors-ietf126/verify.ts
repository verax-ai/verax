/**
 * A verifier for the `vectors-ietf126` set of action-state-group/scitt-cose,
 * written from RFC 8949 (CBOR), RFC 9052 (COSE_Sign1), RFC 9162 (Merkle
 * inclusion) and the set's own README. It uses Node built-ins only and no
 * code from that repository.
 *
 *   node --experimental-strip-types verify.ts <path-to-scitt-cose>/test-vectors [--json]
 *   node --experimental-strip-types verify.ts <path> --mutate
 *
 * Stages, in order: statement-decode, statement-sig, leaf-entry, vds-gate,
 * receipt-decode, inclusion, receipt-sig. A vector the receipt profile here
 * does not cover (vds other than 1 on a VALID vector) is reported SCOPE-OUT
 * rather than counted as a pass or a failure.
 */
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// ---- CBOR (RFC 8949): the subset these objects use ----

class Tagged {
  readonly tag: number;
  readonly value: unknown;
  constructor(tag: number, value: unknown) {
    this.tag = tag;
    this.value = value;
  }
}

function decodeCbor(bytes: Uint8Array): unknown {
  let at = 0;
  const need = (n: number) => {
    if (at + n > bytes.length) throw new Error("cbor-eof");
  };
  const length = (ai: number): number => {
    if (ai < 24) return ai;
    const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : 0;
    if (size === 0) throw new Error("cbor-indefinite-or-reserved");
    need(size);
    let n = 0n;
    for (let i = 0; i < size; i += 1) n = (n << 8n) | BigInt(bytes[at + i]!);
    at += size;
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("cbor-int-too-large");
    return Number(n);
  };
  const item = (depth: number): unknown => {
    if (depth > 32) throw new Error("cbor-too-deep");
    need(1);
    const ib = bytes[at]!;
    at += 1;
    const major = ib >> 5;
    const ai = ib & 31;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      throw new Error("cbor-simple-or-float");
    }
    const n = length(ai);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
        need(n);
        at += n;
        return bytes.slice(at - n, at);
      case 3:
        need(n);
        at += n;
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes.slice(at - n, at));
      case 4: {
        const out: unknown[] = [];
        for (let i = 0; i < n; i += 1) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const out = new Map<unknown, unknown>();
        for (let i = 0; i < n; i += 1) {
          const key = item(depth + 1);
          if (out.has(key)) throw new Error("cbor-duplicate-key");
          out.set(key, item(depth + 1));
        }
        return out;
      }
      case 6:
        return new Tagged(n, item(depth + 1));
      default:
        throw new Error("cbor-major");
    }
  };
  const value = item(0);
  if (at !== bytes.length) throw new Error("cbor-trailing");
  return value;
}

function head(major: number, n: number): Uint8Array {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

const bstr = (b: Uint8Array) => Buffer.concat([head(2, b.length), b]);
const tstr = (s: string) => {
  const b = Buffer.from(s, "utf8");
  return Buffer.concat([head(3, b.length), b]);
};

/** RFC 9052 4.4: Sig_structure = ["Signature1", body_protected, external_aad, payload]. */
function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Buffer {
  return Buffer.concat([head(4, 4), tstr("Signature1"), bstr(protectedBytes), bstr(new Uint8Array(0)), bstr(payload)]);
}

// ---- COSE_Sign1 (RFC 9052) ----

type Sign1 = {
  protectedBytes: Uint8Array;
  protectedHeader: Map<unknown, unknown>;
  unprotected: Map<unknown, unknown>;
  payload: Uint8Array | null;
  signature: Uint8Array;
};

function decodeSign1(bytes: Uint8Array): Sign1 {
  let value = decodeCbor(bytes);
  // Tag 18 is COSE_Sign1 (RFC 9052 2); the untagged form is accepted too.
  if (value instanceof Tagged) {
    if (value.tag !== 18) throw new Error(`tag ${value.tag} is not COSE_Sign1`);
    value = value.value;
  }
  if (!Array.isArray(value) || value.length !== 4) throw new Error("not a four-element COSE_Sign1 array");
  const [p, u, payload, signature] = value as [unknown, unknown, unknown, unknown];
  if (!(p instanceof Uint8Array) || !(u instanceof Map) || !(signature instanceof Uint8Array)) {
    throw new Error("COSE_Sign1 member types");
  }
  if (payload !== null && !(payload instanceof Uint8Array)) throw new Error("payload is neither bstr nor nil");
  const protectedHeader = p.length === 0 ? new Map() : decodeCbor(p);
  if (!(protectedHeader instanceof Map)) throw new Error("protected header is not a map");
  return { protectedBytes: p, protectedHeader, unprotected: u, payload, signature };
}

/** COSE alg (RFC 9053, RFC 9864) to a Node verify call. */
function verifyCose(alg: unknown, keyPem: string, data: Buffer, signature: Uint8Array): boolean {
  const key = createPublicKey(keyPem);
  if (alg === -8 || alg === -19) {
    if (key.asymmetricKeyType !== "ed25519") return false;
    return verifySignature(null, data, key, signature);
  }
  if (alg === -7) {
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") return false;
    return verifySignature("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  }
  if (alg === -35) {
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "secp384r1") return false;
    return verifySignature("sha384", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  }
  throw new Error(`alg ${String(alg)} is not supported`);
}

// ---- RFC 9162 2.1.1 and 2.1.3.2 ----

const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();

function rootFromInclusion(leafEntry: Uint8Array, leafIndex: number, treeSize: number, path: Uint8Array[]): Buffer {
  if (leafIndex >= treeSize) throw new Error("leaf_index is not below tree_size");
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = sha256(Uint8Array.of(0x00), leafEntry);
  for (const p of path) {
    if (p.length !== 32) throw new Error("audit path node is not 32 bytes");
    if (sn === 0) throw new Error("audit path is longer than the tree");
    if (fn % 2 === 1 || fn === sn) {
      r = sha256(Uint8Array.of(0x01), p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = sha256(Uint8Array.of(0x01), r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error("audit path is shorter than the tree");
  return r;
}

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
