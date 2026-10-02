/**
 * Checkpoints registered with a Transparency Service run by someone else.
 *
 * `verax anchor` sends a service the SHA-256 of a checkpoint's COSE octets
 * (the checkpoint hash core-03 defines) and nothing else: the window, the
 * counts and the head stay on this machine. The service appends that digest to
 * its RFC 9162 log and returns a COSE Receipt, which is kept here, one row per
 * checkpoint and service, so `verax verify` can check it later with no network.
 *
 * What a verified receipt adds is a second party: the service's log held this
 * checkpoint at the tree size in the receipt, under the service's key. A
 * receipt does not show the service agrees with anything the checkpoint
 * counts, and a reader who has only these files cannot tell whether a newer
 * checkpoint was registered and then removed from them; asking the service is
 * the check for that.
 */
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const ANCHORS_NAME = "checkpoint-anchors.jsonl";

/** `register`: the SCITT digest route; the log's leaf entry is SHA-256 of the 32 checkpoint-hash octets. */
export type AnchorRoute = "register";

export type AnchorRow = {
  v: 1;
  checkpointHash: string;
  service: string;
  route: AnchorRoute;
  entryHash: string;
  leafIndex: number;
  treeSize: number;
  receiptB64: string;
  atMs: number;
};

const HASH = /^[0-9a-f]{64}$/;

export function anchorsPath(dir: string): string {
  return join(dir, ANCHORS_NAME);
}

/** The leaf entry the service's log holds for this checkpoint under `route`. */
export function anchorEntryHash(checkpointHash: string, route: AnchorRoute): string {
  if (!HASH.test(checkpointHash)) throw new Error("anchor-checkpoint-hash");
  if (route === "register") return createHash("sha256").update(Buffer.from(checkpointHash, "hex")).digest("hex");
  throw new Error(`anchor-route-${String(route)}`);
}

function asRow(value: unknown): AnchorRow | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const r = value as Partial<AnchorRow>;
  if (r.v !== 1 || r.route !== "register") return null;
  if (typeof r.checkpointHash !== "string" || !HASH.test(r.checkpointHash)) return null;
  if (typeof r.entryHash !== "string" || !HASH.test(r.entryHash)) return null;
  if (typeof r.service !== "string" || r.service === "") return null;
  if (typeof r.receiptB64 !== "string" || r.receiptB64 === "") return null;
  if (!Number.isSafeInteger(r.leafIndex) || !Number.isSafeInteger(r.treeSize)) return null;
  if (typeof r.atMs !== "number") return null;
  return r as AnchorRow;
}

/** Rows in file order. A line that is not a row is named, not skipped silently. */
export function readAnchors(dir: string): { present: boolean; rows: AnchorRow[]; problems: string[] } {
  const path = anchorsPath(dir);
  if (!existsSync(path)) return { present: false, rows: [], problems: [] };
  if (lstatSync(path).isSymbolicLink()) return { present: true, rows: [], problems: [`symbolic link: ${path}`] };
  const rows: AnchorRow[] = [];
  const problems: string[] = [];
  const lines = readFileSync(path, "utf8").split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!.trim();
    if (line === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      problems.push(`anchor line ${i + 1} is not JSON`);
      continue;
    }
    const row = asRow(parsed);
    if (!row) {
      problems.push(`anchor line ${i + 1} is not an anchor row`);
      continue;
    }
    rows.push(row);
  }
  return { present: true, rows, problems };
}

export function appendAnchor(dir: string, row: AnchorRow): void {
  appendFileSync(anchorsPath(dir), `${JSON.stringify(row)}\n`, { encoding: "utf8" });
}
