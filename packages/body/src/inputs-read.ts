import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { canonical } from "@cedulon/core";

function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

export async function matchingInputs(
  stateDir: string,
  decisions: { claims: { ref: string | null; inputsHash: string | null } }[],
): Promise<Record<string, unknown>> {
  let text: string;
  try {
    text = await readFile(join(stateDir, "inputs.jsonl"), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw err;
  }
  const byRef = new Map<string, unknown>();
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref?: string; inputs?: unknown };
    if (typeof row.ref === "string") byRef.set(row.ref, row.inputs);
  }
  const out: Record<string, unknown> = {};
  for (const d of decisions) {
    const ref = d.claims.ref;
    if (!ref || typeof d.claims.inputsHash !== "string") continue;
    const doc = byRef.get(ref);
    if (doc !== undefined && sha256Canonical(doc) === d.claims.inputsHash) {
      out[ref] = doc;
    }
  }
  return out;
}

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
  let found: { brain?: unknown; iss?: unknown; tenant?: unknown; org?: unknown } | null = null;
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const row = JSON.parse(line) as { ref?: string; inputs?: { principal?: typeof found } };
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
