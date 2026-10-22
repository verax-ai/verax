import { readFileSync } from "node:fs";
import { FileLedger } from "@verax-ai/proxy";
import { EX_CONFIG } from "./config.ts";
import { loadOrCreateSigners, resolveHeadDir, resolveKeysDir } from "./keys.ts";
import { listLegacyMemoryFiles, openMemoryStoreSync } from "./memory-store.ts";

function usage(): string {
  return "verax memory reattest <stateDir>\n";
}

function parseLegacy(raw: string): {
  id: string;
  body: unknown;
  source: unknown;
  validFromMs: number;
  validUntilMs: number;
} | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const item = parsed as Record<string, unknown>;
  if (typeof item.id !== "string" || item.id === "") return null;
  if (item.source === null || typeof item.source !== "object" || Array.isArray(item.source)) return null;
  if (typeof item.validUntilMs !== "number") return null;
  const validFromMs = typeof item.validFromMs === "number" ? item.validFromMs : 0;
  return { id: item.id, body: item.body, source: item.source, validFromMs, validUntilMs: item.validUntilMs };
}

/**
 * Convert 0.6.1 flat `<id>.json` files to revision 1 and append signed commits.
 * The body must be stopped: a running body holds the ledger lock.
 */
export async function runMemoryReattest(
  argv: string[],
  stdout: { write(s: string): unknown } = process.stdout,
  stderr: { write(s: string): unknown } = process.stderr,
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  if (argv[0] !== "reattest") {
    stderr.write(usage());
    return EX_CONFIG;
  }
  const stateDir = (argv[1] ?? env.VERAX_STATE_DIR ?? "").trim();
  if (stateDir === "") {
    stderr.write(usage());
    return EX_CONFIG;
  }
  let ledger: FileLedger;
  try {
    ledger = new FileLedger(stateDir);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "";
    if (msg.startsWith("ledger-locked")) {
      stderr.write("memory-reattest-body-running\n");
      return 1;
    }
    stderr.write(`memory-reattest-failed:${msg.split("\n")[0] ?? "unknown"}\n`);
    return 1;
  }
  try {
    const keysDir = resolveKeysDir(stateDir, env.VERAX_KEYS_DIR);
    const signers = loadOrCreateSigners(stateDir, keysDir);
    const store = openMemoryStoreSync({
      stateDir,
      publicKeyPem: signers.recordSigner.publicKeyPem,
      privateKeyPem: signers.recordSigner.privateKeyPem,
      headDir: resolveHeadDir(stateDir, keysDir, env.VERAX_MEMORY_HEAD_DIR),
    });
    if (store.historyUnavailable) {
      stderr.write("memory-reattest-history-unavailable\n");
      return 1;
    }
    const files = listLegacyMemoryFiles(stateDir);
    if (files.length === 0) {
      stdout.write("reattested:none\n");
      return 0;
    }
    for (const file of files) {
      const parsed = parseLegacy(readFileSync(file.path, "utf8"));
      if (parsed === null || parsed.id !== file.id) {
        stderr.write(`memory-reattest-skip:${file.tenantKey}/${file.id}\n`);
        continue;
      }
      const result = await store.reattestLegacy({
        tenantKey: file.tenantKey,
        id: file.id,
        body: parsed.body,
        source: parsed.source,
        validFromMs: parsed.validFromMs,
        validUntilMs: parsed.validUntilMs,
        legacyPath: file.path,
      });
      if ("skipped" in result) {
        stderr.write(`memory-reattest-skip:${file.tenantKey}/${file.id}\n`);
        continue;
      }
      stdout.write(`${file.id}\n`);
    }
    return 0;
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unknown";
    stderr.write(`memory-reattest-failed:${msg.split("\n")[0] ?? "unknown"}\n`);
    return 1;
  } finally {
    ledger.close();
  }
}
