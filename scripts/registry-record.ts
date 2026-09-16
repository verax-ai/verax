/**
 * Reads a server record out of the MCP registry's search answer.
 *
 * The rows are wrapped: each one is `{ server: {...}, _meta: {...} }`, not the
 * server object itself. A reader that looks for `name` on the row finds
 * nothing and reports that the record is missing - which is what happened on
 * the first publish, after the record had in fact been written.
 */

export type RegistryRow = {
  server?: { name?: string; version?: string };
  name?: string;
  version?: string;
  _meta?: Record<string, { isLatest?: boolean; publishedAt?: string } | undefined>;
};

const OFFICIAL = "io.modelcontextprotocol.registry/official";

export type Found = { version: string; publishedAt: string | null } | null;

export function latestRecord(text: string, name: string): { found: Found; why: string } {
  let parsed: { servers?: RegistryRow[]; data?: RegistryRow[] };
  try {
    parsed = JSON.parse(text) as { servers?: RegistryRow[]; data?: RegistryRow[] };
  } catch (err) {
    return { found: null, why: `unreadable json: ${(err as Error).message}` };
  }
  const rows = parsed.servers ?? parsed.data ?? [];
  const mine = rows.filter((r) => (r.server?.name ?? r.name) === name);
  if (mine.length === 0) {
    return { found: null, why: `no row named ${name} among ${rows.length}` };
  }
  const latest = mine.find((r) => r._meta?.[OFFICIAL]?.isLatest === true);
  if (!latest) {
    return { found: null, why: `${mine.length} row(s) for ${name}, none marked isLatest` };
  }
  const version = latest.server?.version ?? latest.version;
  if (typeof version !== "string") {
    return { found: null, why: "the row marked isLatest carries no version" };
  }
  return { found: { version, publishedAt: latest._meta?.[OFFICIAL]?.publishedAt ?? null }, why: "" };
}
