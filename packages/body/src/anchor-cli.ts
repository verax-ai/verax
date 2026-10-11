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
import { readFileSync } from "node:fs";

import {
  anchorEntryHash,
  appendAnchor,
  readAnchors,
  readCheckpointFile,
  verifyReceipt,
  type AnchorRow,
} from "@verax-ai/proxy";
import { checkpointHash } from "@cedulon/checkpoint";

export const EX_ANCHOR_FAILED = 1;
const EX_USAGE = 64;

function usage(): string {
  return [
    "usage: verax anchor <stateDir> --service <url> [--service-key <public.pem>] [--json]",
    "",
    "  --service <url>        the Transparency Service, for example https://witness.agentactioncapsule.org.",
    "                         https only; http is accepted for a loopback address.",
    "  --service-key <file>   the service's public key; each receipt must verify under it before it is kept",
    "  --json                 one JSON object per anchored checkpoint",
    "",
    "Sends the SHA-256 of each checkpoint not yet anchored at that service, and nothing else.",
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

/** The body as text, refused once it passes MAX_ANSWER_BYTES rather than held in full. */
async function boundedText(res: Response): Promise<string> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > MAX_ANSWER_BYTES) throw new Error("answer too large");
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_ANSWER_BYTES) {
      await reader.cancel();
      throw new Error("answer too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
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
  const { receipt_b64, entry_hash, leaf_index, tree_size } = answer;
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

/** Checkpoint hashes in this directory with no row at `serviceName`, in file order. */
export function pendingAnchors(dir: string, serviceName: string): { pending: string[]; problems: string[] } {
  const loaded = readCheckpointFile(dir);
  if (loaded.problems.length > 0) return { pending: [], problems: loaded.problems };
  const existing = readAnchors(dir);
  if (existing.problems.length > 0) return { pending: [], problems: existing.problems };
  const done = new Set(existing.rows.filter((r) => r.service === serviceName).map((r) => r.checkpointHash));
  return { pending: loaded.rows.map((row) => checkpointHash(row)).filter((hash) => !done.has(hash)), problems: [] };
}

export async function runAnchor(
  argv: readonly string[],
  out: (s: string) => void = (s) => process.stdout.write(`${s}\n`),
  fetchImpl: typeof fetch = fetch,
  now: () => number = Date.now,
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
  let failed = 0;
  for (const hash of pending) {
    const got = await registerCheckpoint(serviceName, hash, serviceKey, fetchImpl, now);
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
        : `anchored ${hash.slice(0, 12)} at ${serviceName}: leaf ${row.leafIndex} of ${row.treeSize}${got.checked ? ", receipt verified" : ", receipt not yet checked"}`,
    );
  }
  return failed === 0 ? 0 : EX_ANCHOR_FAILED;
}
