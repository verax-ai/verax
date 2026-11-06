/**
 * `verax anchor <stateDir> --service <url>` registers each checkpoint this
 * ledger holds with a SCITT Transparency Service that someone else runs, and
 * keeps the COSE Receipt it returns in `checkpoint-anchors.jsonl`.
 *
 * Only the checkpoint hash leaves the machine: `POST <service>/register` with
 * `{"capsule_id": <SHA-256 of the checkpoint's COSE octets>}`. The window, the
 * counts and the head stay here. A checkpoint already anchored at that service
 * is not sent again.
 *
 * `--service-key <pem>` checks each receipt as it arrives and refuses to keep
 * one that does not verify. Without it the receipt is kept and `verax verify
 * --anchor-key` is where it is first checked.
 */
import { createHash, createPublicKey, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  anchorEntryHash,
  appendAnchor,
  checkpointStatement,
  decodeCborItem,
  isEntryId,
  readAnchors,
  readCcfReceipt,
  readCheckpointFile,
  readIssuerChain,
  verifyCcfReceipt,
  verifyReceipt,
  type AnchorRow,
} from "@verax-ai/proxy";
import { checkpointHash } from "@cedulon/checkpoint";

export const EX_ANCHOR_FAILED = 1;
const EX_USAGE = 64;

function usage(): string {
  return [
    "usage: verax anchor <stateDir> --service <url> [--x5chain <chain.pem>] [--service-key <public.pem>] [--json]",
    "",
    "  --service <url>        the Transparency Service, for example https://witness.agentactioncapsule.org.",
    "                         https only; http is accepted for a loopback address.",
    "  --x5chain <file>       register over SCRAPI (POST /entries) as a Signed Statement the witness key signs;",
    "                         the file is the PEM chain for that key, leaf first, then its CA certificates",
    "  --service-key <file>   the service's public key; each receipt must verify under it before it is kept",
    "  --json                 one JSON object per anchored checkpoint",
    "",
    "Sends the SHA-256 of each checkpoint not yet anchored at that service, and nothing else;",
    "with --x5chain that hash travels inside a Signed Statement that also carries the chain.",
  ].join("\n");
}

/** https only; http is accepted for a loopback address. No credentials, query or fragment. */
export function serviceUrl(raw: string): URL | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") return null;
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]";
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && loopback) return url;
  return null;
}

// A receipt is a few hundred bytes; the reader refuses CBOR over 64 KiB.
const MAX_ANSWER_BYTES = 256 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_RECEIPT_B64 = Math.ceil(MAX_RECEIPT_BYTES / 3) * 4;

/** The body, refused once it passes `max` octets rather than held in full. */
async function boundedBytes(res: Response, max: number = MAX_ANSWER_BYTES): Promise<Buffer> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > max) throw new Error("answer too large");
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > max) {
      await reader.cancel();
      throw new Error("answer too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

async function boundedText(res: Response): Promise<string> {
  return (await boundedBytes(res)).toString("utf8");
}

type RegisterAnswer = { receipt_b64?: unknown; entry_hash?: unknown; leaf_index?: unknown; tree_size?: unknown };

/** The name a service's rows are kept under: origin and path, no trailing slash. */
export function serviceNameOf(service: URL): string {
  return service.origin + service.pathname.replace(/\/+$/, "");
}

export type Registered =
  | { ok: true; row: AnchorRow; checked: boolean }
  | { ok: false; reason: "unreachable" | "wrong-receipt" | "receipt-unverified"; message: string };

/**
 * Registers one checkpoint hash at `serviceName` and returns the row to keep.
 * Nothing is written here; the caller appends the row. With `serviceKey` the
 * receipt must verify under it, at the tree size and leaf the service named.
 */
export async function registerCheckpoint(
  serviceName: string,
  hash: string,
  serviceKey: string | null,
  fetchImpl: typeof fetch = fetch,
  now: () => number = Date.now,
): Promise<Registered> {
  const entryHash = anchorEntryHash(hash, "register");
  let answer: RegisterAnswer;
  try {
    const res = await fetchImpl(`${serviceName}/register`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ capsule_id: hash }),
      signal: AbortSignal.timeout(15_000),
      redirect: "error",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    answer = JSON.parse(await boundedText(res)) as RegisterAnswer;
  } catch (err) {
    return { ok: false, reason: "unreachable", message: err instanceof Error ? err.message : String(err) };
  }
  // JSON `null` parses and is not an object: read through `?? {}` so it is refused below
  // like `[]` and `{}`, not thrown as a TypeError the caller has no row for.
  const { receipt_b64, entry_hash, leaf_index, tree_size } = (answer ?? {}) as RegisterAnswer;
  if (
    typeof receipt_b64 !== "string" ||
    receipt_b64.length > MAX_RECEIPT_B64 ||
    Buffer.from(receipt_b64, "base64").length > MAX_RECEIPT_BYTES ||
    entry_hash !== entryHash ||
    !Number.isSafeInteger(leaf_index) ||
    !Number.isSafeInteger(tree_size)
  ) {
    return {
      ok: false,
      reason: "wrong-receipt",
      message: "the service answered with a receipt for another entry, or no receipt",
    };
  }
  if (serviceKey) {
    const check = verifyReceipt(Buffer.from(receipt_b64, "base64"), Buffer.from(entryHash, "hex"), serviceKey);
    if (!check.ok || check.treeSize !== tree_size || check.leafIndex !== leaf_index) {
      return { ok: false, reason: "receipt-unverified", message: "receipt does not verify under the service key" };
    }
  }
  return {
    ok: true,
    checked: serviceKey !== null,
    row: {
      v: 1,
      checkpointHash: hash,
      service: serviceName,
      route: "register",
      entryHash,
      leafIndex: leaf_index as number,
      treeSize: tree_size as number,
      receiptB64: receipt_b64,
      atMs: now(),
    },
  };
}

// SCRAPI (draft-ietf-scitt-scrapi) as scitt-ccf-ledger serves it when asked
// for this api-version: POST /entries answers 303 with the entry's location,
// GET /entries/{id} answers 302 while the entry is pending and 200 with the
// receipt once it is committed.
const SCRAPI_API_VERSION = "2026-03-26";
const POLL_INTERVAL_MS = 1_000;
const POLL_ATTEMPTS = 30;

/**
 * "HTTP <status>", with the title or detail of the concise problem details
 * (RFC 9290) the service sent, so the operator reads why it refused. The text
 * is the service's: it is cut short and printable ASCII only.
 */
export async function httpFailure(res: Response): Promise<string> {
  let detail = "";
  try {
    if ((res.headers.get("content-type") ?? "").includes("concise-problem-details+cbor")) {
      const body = decodeCborItem(await boundedBytes(res, 4096));
      const text = body instanceof Map ? (body.get(-2) ?? body.get(-1)) : undefined;
      if (typeof text === "string" && text !== "") detail = `: ${text.slice(0, 200).replace(/[^\x20-\x7e]/g, "?")}`;
    } else {
      await res.body?.cancel();
    }
  } catch {
    // The status alone is still the answer.
  }
  return `HTTP ${res.status}${detail}`;
}

/** The entry id at the end of a Location the service sent; its host is not followed. */
export function entryIdFromLocation(location: string | null, serviceName: string): string | null {
  if (!location) return null;
  let url: URL;
  try {
    url = new URL(location, `${serviceName}/`);
  } catch {
    return null;
  }
  const match = /\/entries\/([^/]+)$/.exec(url.pathname);
  if (!match) return null;
  let id: string;
  try {
    id = decodeURIComponent(match[1]!);
  } catch {
    return null;
  }
  return isEntryId(id) ? id : null;
}

/**
 * Registers one checkpoint's Signed Statement at `serviceName` over SCRAPI and
 * returns the row to keep. The receipt must commit to the SHA-256 of
 * `statement`; with `serviceKey` it must also verify under that key.
 */
export async function registerStatement(
  serviceName: string,
  hash: string,
  statement: Uint8Array,
  serviceKey: string | null,
  fetchImpl: typeof fetch = fetch,
  now: () => number = Date.now,
  wait: (ms: number) => Promise<void> = (ms) => new Promise((done) => setTimeout(done, ms)),
): Promise<Registered> {
  const query = `api-version=${SCRAPI_API_VERSION}`;
  let entryId: string | null;
  let receipt: Buffer | null = null;
  try {
    const res = await fetchImpl(`${serviceName}/entries?${query}`, {
      method: "POST",
      headers: { "content-type": "application/cose", accept: "application/scitt-receipt+cose" },
      body: new Uint8Array(statement),
      signal: AbortSignal.timeout(15_000),
      redirect: "manual",
    });
    if (res.status !== 303 && res.status !== 201) throw new Error(await httpFailure(res));
    entryId = entryIdFromLocation(res.headers.get("location"), serviceName);
    if (res.status === 201) receipt = await boundedBytes(res, MAX_RECEIPT_BYTES);
    else await res.body?.cancel();
    for (let attempt = 0; receipt === null && entryId !== null && attempt < POLL_ATTEMPTS; attempt += 1) {
      const got = await fetchImpl(`${serviceName}/entries/${encodeURIComponent(entryId)}?${query}`, {
        method: "GET",
        headers: { accept: "application/scitt-receipt+cose" },
        signal: AbortSignal.timeout(15_000),
        redirect: "manual",
      });
      if (got.status === 200) {
        receipt = await boundedBytes(got, MAX_RECEIPT_BYTES);
        break;
      }
      if (got.status !== 302 && got.status !== 202) throw new Error(await httpFailure(got));
      await got.body?.cancel();
      await wait(POLL_INTERVAL_MS);
    }
  } catch (err) {
    return { ok: false, reason: "unreachable", message: err instanceof Error ? err.message : String(err) };
  }
  if (entryId === null) {
    return { ok: false, reason: "wrong-receipt", message: "the service named no entry for the statement" };
  }
  if (receipt === null) {
    return { ok: false, reason: "unreachable", message: `entry ${entryId} was not committed in time` };
  }
  const digest = createHash("sha256").update(statement).digest();
  if (!readCcfReceipt(receipt, digest).ok) {
    return { ok: false, reason: "wrong-receipt", message: "the service answered with a receipt for another statement" };
  }
  if (serviceKey && !verifyCcfReceipt(receipt, digest, serviceKey).ok) {
    return { ok: false, reason: "receipt-unverified", message: "receipt does not verify under the service key" };
  }
  return {
    ok: true,
    checked: serviceKey !== null,
    row: {
      v: 2,
      checkpointHash: hash,
      service: serviceName,
      route: "entries",
      entryId,
      statementB64: Buffer.from(statement).toString("base64"),
      receiptB64: receipt.toString("base64"),
      atMs: now(),
    },
  };
}

/** Checkpoint hashes in this directory with no row at `serviceName`, in file order. */
export function pendingAnchors(dir: string, serviceName: string): { pending: string[]; problems: string[] } {
  const loaded = readCheckpointFile(dir);
  if (loaded.problems.length > 0) return { pending: [], problems: loaded.problems };
  const existing = readAnchors(dir);
  if (existing.problems.length > 0) return { pending: [], problems: existing.problems };
  const done = new Set(existing.rows.filter((r) => r.service === serviceName).map((r) => r.checkpointHash));
  return { pending: loaded.rows.map((row) => checkpointHash(row)).filter((hash) => !done.has(hash)), problems: [] };
}

export type StatementIssuer = { chain: Uint8Array[]; keys: { privateKeyPem: string; publicKeyPem: string } };

/**
 * The issuer chain read from `chainPem` with the witness keys in
 * `<stateDir>/keys`, when the chain's leaf holds the witness public key. The
 * keys are read, never created: a ledger with no witness has no checkpoint.
 */
export function statementIssuer(
  stateDir: string,
  chainPem: string,
): { ok: true; issuer: StatementIssuer } | { ok: false; reason: string } {
  let chain: Uint8Array[];
  try {
    chain = readIssuerChain(chainPem);
  } catch (err) {
    const code = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      reason: code === "issuer-chain-too-short"
        ? "the x5chain file must hold the witness certificate and at least one CA certificate, leaf first"
        : "the x5chain file holds something that is not a certificate",
    };
  }
  let keys: { privateKeyPem: string; publicKeyPem: string };
  try {
    keys = {
      privateKeyPem: readFileSync(join(stateDir, "keys", "witness.private.pem"), "utf8"),
      publicKeyPem: readFileSync(join(stateDir, "keys", "witness.public.pem"), "utf8"),
    };
  } catch {
    return { ok: false, reason: `no witness key in ${join(stateDir, "keys")}` };
  }
  const leafKey = new X509Certificate(chain[0]!).publicKey.export({ type: "spki", format: "der" });
  if (!leafKey.equals(createPublicKey(keys.publicKeyPem).export({ type: "spki", format: "der" }))) {
    return { ok: false, reason: "the x5chain leaf certificate does not hold this ledger's witness public key" };
  }
  return { ok: true, issuer: { chain, keys } };
}

export async function runAnchor(
  argv: readonly string[],
  out: (s: string) => void = (s) => process.stdout.write(`${s}\n`),
  fetchImpl: typeof fetch = fetch,
  now: () => number = Date.now,
  wait?: (ms: number) => Promise<void>,
): Promise<number> {
  const args = [...argv];
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    out(usage());
    return args.length === 0 ? EX_USAGE : 0;
  }
  const json = args.includes("--json");
  const take = (flag: string): string | null | undefined => {
    const at = args.indexOf(flag);
    if (at === -1) return undefined;
    const value = args[at + 1];
    if (!value || value.startsWith("-")) return null;
    args.splice(at, 2);
    return value;
  };
  const rawService = take("--service");
  if (!rawService) {
    out("anchor: --service <url> is required");
    return EX_USAGE;
  }
  const service = serviceUrl(rawService);
  if (!service) {
    out("anchor: --service must be an https URL with no credentials, query or fragment (http only on loopback)");
    return EX_USAGE;
  }
  const keyPath = take("--service-key");
  if (keyPath === null) {
    out("anchor: --service-key needs a file path");
    return EX_USAGE;
  }
  let serviceKey: string | null = null;
  if (keyPath) {
    try {
      serviceKey = readFileSync(keyPath, "utf8");
    } catch {
      out(`anchor: cannot read key file ${keyPath}`);
      return EX_USAGE;
    }
    if (serviceKey.trim() === "") {
      out(`anchor: key file ${keyPath} is empty`);
      return EX_USAGE;
    }
  }
  const chainPath = take("--x5chain");
  if (chainPath === null) {
    out("anchor: --x5chain needs a file path");
    return EX_USAGE;
  }
  const dir = args.find((a) => !a.startsWith("-"));
  if (!dir) {
    out(usage());
    return EX_USAGE;
  }
  const serviceName = serviceNameOf(service);
  const { pending, problems } = pendingAnchors(dir, serviceName);
  if (problems.length > 0) {
    for (const p of problems) out(`anchor: ${p}`);
    return EX_ANCHOR_FAILED;
  }
  if (pending.length === 0) {
    out(json ? JSON.stringify({ anchored: 0, service: serviceName }) : `nothing to anchor at ${serviceName}`);
    return 0;
  }
  let issuer: StatementIssuer | null = null;
  if (chainPath) {
    let chainPem: string;
    try {
      chainPem = readFileSync(chainPath, "utf8");
    } catch {
      out(`anchor: cannot read chain file ${chainPath}`);
      return EX_USAGE;
    }
    const found = statementIssuer(dir, chainPem);
    if (!found.ok) {
      out(`anchor: ${found.reason}`);
      return EX_USAGE;
    }
    issuer = found.issuer;
  }
  let failed = 0;
  for (const hash of pending) {
    const got = issuer
      ? await registerStatement(serviceName, hash, checkpointStatement(hash, issuer.chain, issuer.keys), serviceKey, fetchImpl, now, wait)
      : await registerCheckpoint(serviceName, hash, serviceKey, fetchImpl, now);
    if (!got.ok) {
      failed += 1;
      const short = hash.slice(0, 12);
      out(
        got.reason === "unreachable"
          ? `anchor: ${short} not registered: ${got.message}`
          : got.reason === "wrong-receipt"
            ? `anchor: ${short} ${got.message}`
            : `anchor: ${short} receipt does not verify under --service-key; not kept`,
      );
      continue;
    }
    const row = got.row;
    appendAnchor(dir, row);
    out(
      json
        ? JSON.stringify(row)
        : `anchored ${hash.slice(0, 12)} at ${serviceName}: ${row.v === 1 ? `leaf ${row.leafIndex} of ${row.treeSize}` : `entry ${row.entryId}`}${got.checked ? ", receipt verified" : ", receipt not yet checked"}`,
    );
  }
  return failed === 0 ? 0 : EX_ANCHOR_FAILED;
}
