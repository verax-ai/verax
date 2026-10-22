import { FileLedger } from "@verax-ai/proxy";
import { EX_CONFIG } from "./config.ts";
import { assertRecordKeyTrust, loadOrCreateSigners, resolveHeadDir } from "./keys.ts";
import { reheadMemoryFromChain } from "./memory-store.ts";

function usage(): string {
  return "verax memory rehead <stateDir>\n";
}

/**
 * Write a signed memory head from the current commit tip.
 * The body must be stopped: a running body holds the ledger lock.
 */
export async function runMemoryRehead(
  argv: string[],
  stdout: { write(s: string): unknown } = process.stdout,
  stderr: { write(s: string): unknown } = process.stderr,
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  if (argv[0] !== "rehead") {
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
      stderr.write("memory-rehead-body-running\n");
      return 1;
    }
    stderr.write(`memory-rehead-failed:${msg.split("\n")[0] ?? "unknown"}\n`);
    return 1;
  }
  try {
    const keysDir = env.VERAX_KEYS_DIR;
    const signers = loadOrCreateSigners(stateDir, keysDir);
    const publicKeyPem = assertRecordKeyTrust({
      stateDir,
      keysDir,
      recordSigner: signers.recordSigner,
    });
    const result = reheadMemoryFromChain({
      stateDir,
      publicKeyPem,
      privateKeyPem: signers.recordSigner.privateKeyPem,
      headDir: resolveHeadDir(stateDir, keysDir, env.VERAX_MEMORY_HEAD_DIR),
    });
    if (!result.ok) {
      stderr.write("memory-rehead-invalid\n");
      return 1;
    }
    const shortHash = result.lastHash === null ? "-" : result.lastHash.slice(0, 16);
    stdout.write(`${result.seq} ${shortHash}\n`);
    return 0;
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unknown";
    stderr.write(`memory-rehead-failed:${msg.split("\n")[0] ?? "unknown"}\n`);
    return 1;
  } finally {
    ledger.close();
  }
}
