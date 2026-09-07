import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { loadApprovalsFromDir, loadEffectsFromDir, loadPolicy, parseCardCsv, parseChannelJsonl, reconcile } from "@verax-ai/proxy";

const SNAPSHOT_NAME = /^[0-9a-f]{64}\.json$/;

function descriptorsFromDoc(doc: {
  rules?: Array<{ spend?: { payees?: unknown; descriptors?: unknown } }>;
}): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (!Array.isArray(doc.rules)) return out;
  for (const rule of doc.rules) {
    const spend = rule.spend;
    if (!spend || !Array.isArray(spend.payees) || !Array.isArray(spend.descriptors)) continue;
    const stamps = spend.descriptors.filter((d): d is string => typeof d === "string" && d !== "");
    if (stamps.length === 0) continue;
    for (const payee of spend.payees) {
      if (typeof payee === "string" && payee !== "") out[payee] = stamps;
    }
  }
  return out;
}

function loadDescriptorsFromDir(stateDir: string): {
  descriptorsByPayee: Record<string, string[]>;
  policyHash: string | null;
} {
  const dir = join(stateDir, "policies");
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return { descriptorsByPayee: {}, policyHash: null };
  }
  const candidates: { name: string; mtimeMs: number }[] = [];
  for (const name of names) {
    if (!SNAPSHOT_NAME.test(name)) continue;
    try {
      const st = statSync(join(dir, name));
      candidates.push({ name, mtimeMs: st.mtimeMs });
    } catch {
      // A missing snapshot is skipped.
    }
  }
  if (candidates.length === 0) return { descriptorsByPayee: {}, policyHash: null };
  candidates.sort((a, b) => a.mtimeMs - b.mtimeMs || a.name.localeCompare(b.name));
  const chosen = candidates[candidates.length - 1]!;
  const hash = chosen.name.slice(0, 64);
  try {
    const doc = JSON.parse(readFileSync(join(dir, chosen.name), "utf8")) as {
      rules?: Array<{ spend?: { payees?: unknown; descriptors?: unknown } }>;
    };
    if (loadPolicy(doc).hash !== hash) return { descriptorsByPayee: {}, policyHash: null };
    return { descriptorsByPayee: descriptorsFromDoc(doc), policyHash: hash };
  } catch {
    return { descriptorsByPayee: {}, policyHash: null };
  }
}

const CARD_TOLERANCE_MS = 3 * 86_400_000;
/** UTC-12 .. UTC+14 in minutes. */
const MAX_TZ_OFFSET_MIN = 840;

export function parseReconcileArgs(argv: string[]): {
  stateDir: string;
  channelPath: string;
  outPath: string;
  toleranceMs: number;
  window?: { startMs: number; endMs: number };
  channel?: "card";
  currency?: string;
  columns?: { date: string; amount: string; description: string; id?: string };
  delimiter?: ";" | ",";
  decimal?: "," | ".";
  tzOffsetMinutes?: number;
} | { error: string } {
  const rest = argv.slice(1);
  let tzOffsetMinutes: number | undefined;
  let toleranceMs: number | undefined;
  let outPath: string | undefined;
  let windowStart: number | undefined;
  let windowEnd: number | undefined;
  let channel: "card" | undefined;
  let currency: string | undefined;
  let columns: { date: string; amount: string; description: string; id?: string } | undefined;
  let delimiter: ";" | "," | undefined;
  let decimal: "," | "." | undefined;
  const positionals: string[] = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i]!;
    if (a === "--tolerance") {
      const raw = rest[i + 1];
      const n = Number(raw);
      if (!Number.isFinite(n) || n < 0) return { error: "tolerance-invalid" };
      toleranceMs = n;
      i += 1;
      continue;
    }
    if (a === "--window-start") {
      const n = Number(rest[i + 1]);
      if (!Number.isFinite(n)) return { error: "window-invalid" };
      windowStart = n;
      i += 1;
      continue;
    }
    if (a === "--window-end") {
      const n = Number(rest[i + 1]);
      if (!Number.isFinite(n)) return { error: "window-invalid" };
      windowEnd = n;
      i += 1;
      continue;
    }
    if (a === "--out") {
      const p = rest[i + 1];
      if (!p || p.startsWith("-")) return { error: "out-missing" };
      outPath = p;
      i += 1;
      continue;
    }
    if (a === "--channel") {
      const p = rest[i + 1];
      if (p !== "card") return { error: "channel-invalid" };
      channel = "card";
      i += 1;
      continue;
    }
    if (a === "--currency") {
      const p = rest[i + 1];
      if (!p || p.startsWith("-")) return { error: "currency-missing" };
      currency = p;
      i += 1;
      continue;
    }
    if (a === "--columns") {
      const p = rest[i + 1];
      if (!p || p.startsWith("-")) return { error: "columns-invalid" };
      const parsed = parseColumns(p);
      if (!parsed) return { error: "columns-invalid" };
      columns = parsed;
      i += 1;
      continue;
    }
    if (a === "--delimiter") {
      const p = rest[i + 1];
      if (p !== ";" && p !== ",") return { error: "delimiter-invalid" };
      delimiter = p;
      i += 1;
      continue;
    }
    if (a === "--tz-offset") {
      const n = Number(rest[i + 1]);
      if (!Number.isInteger(n) || Math.abs(n) > MAX_TZ_OFFSET_MIN) return { error: "tz-offset-invalid" };
      tzOffsetMinutes = n;
      i += 1;
      continue;
    }
    if (a === "--decimal") {
      const p = rest[i + 1];
      if (p !== "," && p !== ".") return { error: "decimal-invalid" };
      decimal = p;
      i += 1;
      continue;
    }
    if (a.startsWith("-")) return { error: `flag-unknown:${a}` };
    positionals.push(a);
  }
  const stateDir = positionals[0];
  const channelPath = positionals[1];
  if (!stateDir || !channelPath || !outPath) {
    return { error: "usage" };
  }
  if (channel === "card" && !currency) return { error: "currency-missing" };
  if ((windowStart === undefined) !== (windowEnd === undefined)) {
    return { error: "window-invalid" };
  }
  const window =
    windowStart !== undefined && windowEnd !== undefined
      ? { startMs: windowStart, endMs: windowEnd }
      : undefined;
  return {
    stateDir,
    channelPath,
    outPath,
    toleranceMs: toleranceMs ?? (channel === "card" ? CARD_TOLERANCE_MS : 60_000),
    window,
    channel,
    currency,
    columns,
    delimiter,
    decimal,
    tzOffsetMinutes,
  };
}

function parseColumns(raw: string): { date: string; amount: string; description: string; id?: string } | null {
  const map: Record<string, string> = {};
  for (const part of raw.split(",")) {
    const eq = part.indexOf("=");
    if (eq <= 0) return null;
    map[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  if (!map.date || !map.amount || !map.desc) return null;
  return {
    date: map.date,
    amount: map.amount,
    description: map.desc,
    ...(map.id ? { id: map.id } : {}),
  };
}

export function runReconcile(
  argv: string[],
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
): number {
  const parsed = parseReconcileArgs(argv);
  if ("error" in parsed) {
    if (parsed.error === "usage") {
      writeErr(
        "verax reconcile <stateDir> <channel.jsonl> [--tolerance 60000] [--window-start ms --window-end ms] [--tz-offset 180] --out report.json\n",
      );
      return 78;
    }
    writeErr(`${parsed.error}\n`);
    return 78;
  }
  try {
    const raw = readFileSync(parsed.channelPath, "utf8");
    const card =
      parsed.channel === "card" && parsed.currency
        ? parseCardCsv(raw, {
            currency: parsed.currency,
            columns: parsed.columns,
            delimiter: parsed.delimiter,
            decimal: parsed.decimal,
            tzOffsetMinutes: parsed.tzOffsetMinutes,
          })
        : undefined;
    const channel = card ?? parseChannelJsonl(raw);
    const effects = loadEffectsFromDir(parsed.stateDir);
    const loaded =
      parsed.channel === "card" ? loadDescriptorsFromDir(parsed.stateDir) : undefined;
    const descriptorsByPayee = loaded?.descriptorsByPayee;
    const report = reconcile(channel, effects, {
      toleranceMs: parsed.toleranceMs,
      window: parsed.window,
      approvals: parsed.channel === "card" ? loadApprovalsFromDir(parsed.stateDir) : undefined,
      skipped: card?.skipped,
      ...(descriptorsByPayee && Object.keys(descriptorsByPayee).length > 0
        ? { descriptorsByPayee }
        : {}),
    });
    if (loaded?.policyHash) report.scope.policyHash = loaded.policyHash;
    writeFileSync(parsed.outPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8" });
    if (parsed.channel === "card") {
      const mismatch = report.ghost.filter((g) => g.reason === "amount-mismatch").length;
      const unknown = report.ghost.filter((g) => g.reason === "amount-unknown").length;
      writeErr(
        `matched ${report.matched.length} · ghost ${report.ghost.length} · authorizedUnpaid ${report.authorizedUnpaid.length} · mismatch ${mismatch} · unknown ${unknown}\n`,
      );
    }
    return 0;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? (err instanceof Error ? err.message : "unknown");
    writeErr(`reconcile-failed:${code}\n`);
    return 1;
  }
}
