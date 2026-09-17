import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { canonical } from "@cedulon/core";
import { readLedgerTail } from "@verax-ai/proxy";

function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

/**
 * The inputs documents behind these decisions, keyed by ref, each checked
 * against the hash its decision recorded. inputs.jsonl is written in the
 * same order as decisions.jsonl, so the rows for a window of decisions sit
 * near its end: the file is read from there, and the read stops once every
 * ref has been seen. The newest row for a ref is the one that counts.
 */
export async function matchingInputs(
  stateDir: string,
  decisions: { claims: { ref: string | null; inputsHash: string | null } }[],
): Promise<Record<string, unknown>> {
  const wanted = new Map<string, string>();
  for (const d of decisions) {
    if (d.claims.ref && typeof d.claims.inputsHash === "string") wanted.set(d.claims.ref, d.claims.inputsHash);
  }
  const out: Record<string, unknown> = {};
  if (wanted.size === 0) return out;
  const seen = new Set<string>();
  await readLedgerTail<{ ref?: unknown; inputs?: unknown }>(join(stateDir, "inputs.jsonl"), (row) => {
    if (typeof row.ref !== "string" || seen.has(row.ref)) return "skip";
    const hash = wanted.get(row.ref);
    if (hash === undefined) return "skip";
    seen.add(row.ref);
    if (sha256Canonical(row.inputs) === hash) out[row.ref] = row.inputs;
    return seen.size === wanted.size ? "stop" : "skip";
  });
  return out;
}

type InputsPrincipal = { brain?: unknown; iss?: unknown; tenant?: unknown; org?: unknown };

export async function inputsPrincipal(
  stateDir: string,
  ref: string,
): Promise<{ brain: string; iss?: string; tenant?: string; org?: string } | null> {
  let text: string;
  try {
    text = await readFile(join(stateDir, "inputs.jsonl"), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  let found: InputsPrincipal | null = null;
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref?: string; inputs?: { principal?: InputsPrincipal } };
    if (row.ref === ref) found = row.inputs?.principal ?? null;
  }
  if (!found || typeof found.brain !== "string") return null;
  return {
    brain: found.brain,
    ...(typeof found.iss === "string" ? { iss: found.iss } : {}),
    ...(typeof found.tenant === "string" ? { tenant: found.tenant } : {}),
    ...(typeof found.org === "string" ? { org: found.org } : {}),
  };
}
