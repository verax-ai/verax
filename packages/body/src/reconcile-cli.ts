import { readFileSync, writeFileSync } from "node:fs";

import { loadEffectsFromDir, parseChannelJsonl, reconcile } from "@verax-ai/proxy";

export function parseReconcileArgs(argv: string[]): {
  stateDir: string;
  channelPath: string;
  outPath: string;
  toleranceMs: number;
} | { error: string } {
  const rest = argv.slice(1);
  let toleranceMs = 60_000;
  let outPath: string | undefined;
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
    if (a === "--out") {
      const p = rest[i + 1];
      if (!p || p.startsWith("-")) return { error: "out-missing" };
      outPath = p;
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
  return { stateDir, channelPath, outPath, toleranceMs };
}

export function runReconcile(
  argv: string[],
  writeErr: (s: string) => void = (s) => process.stderr.write(s),
): number {
  const parsed = parseReconcileArgs(argv);
  if ("error" in parsed) {
    if (parsed.error === "usage") {
      writeErr("verax reconcile <stateDir> <channel.jsonl> [--tolerance 60000] --out report.json\n");
      return 78;
    }
    writeErr(`${parsed.error}\n`);
    return 78;
  }
  try {
    const channel = parseChannelJsonl(readFileSync(parsed.channelPath, "utf8"));
    const effects = loadEffectsFromDir(parsed.stateDir);
    const report = reconcile(channel, effects, { toleranceMs: parsed.toleranceMs });
    writeFileSync(parsed.outPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8" });
    return 0;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? (err instanceof Error ? err.message : "unknown");
    writeErr(`reconcile-failed:${code}\n`);
    return 1;
  }
}
