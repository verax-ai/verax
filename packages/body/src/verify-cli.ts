/**
 * `verax verify <stateDir>` — read a ledger back without a body.
 *
 * The command exists for the moment a customer stops being a customer. A
 * ledger that only the vendor's running service can read is not evidence a
 * buyer holds; it is evidence they rent. This reads the directory on its own,
 * with nothing listening and nothing on the network, and says what still
 * holds together.
 *
 * It refuses to flatten four separate questions into one word. Signatures,
 * the chain, the binding between effects and decisions, and — the one worth
 * the most — **which key** answered. Verifying against the key lying in the
 * same directory proves the files agree with each other and nothing else;
 * that line is printed every time, not buried in a flag.
 */
import { readFileSync } from "node:fs";

import { verifyLedger, type VerifyResult } from "@verax-ai/proxy";
import { directoryAccess, unreadableSentence } from "./install.ts";

export const EX_VERIFY_FAILED = 1;

function usage(): string {
  return [
    "usage: verax verify <stateDir> [--key <public.pem>] [--effect-key <public.pem>] [--checkpoint-key <public.pem>] [--json]",
    "",
    "  <stateDir>        the directory holding decisions.jsonl and effects.jsonl",
    "  --key <file>      verify decision records against a public key you hold,",
    "                    instead of the one the records carry. This is the",
    "                    difference between 'these files agree with each other'",
    "                    and 'these files were signed by the key I was given'.",
    "  --effect-key <file>",
    "                    verify every effect row against a public key you hold,",
    "                    instead of one key taken from the effects. Same",
    "                    distinction as --key, for the effect signer.",
    "  --checkpoint-key <file>",
    "                    verify every checkpoint row against a public key you",
    "                    hold, instead of one key taken from the checkpoint",
    "                    file. Same distinction as --key, for the witness.",
    "  --json            machine-readable result on stdout",
    "",
    "Exit code is 0 when the ledger verifies and 1 when it does not.",
  ].join("\n");
}

/** Lines a person reads. The trust line is never omitted. */
export function renderVerify(r: VerifyResult): string {
  const lines: string[] = [];
  lines.push(`ledger        ${r.directory}`);
  lines.push(`decisions     ${r.decisions}`);
  lines.push(`effects       ${r.effects} (${r.effectsBound} bound to a decision, ${r.effectsOrphaned} with none)`);
  lines.push(`signatures    ${r.signaturesValid} verify, ${r.signaturesInvalid} do not`);
  lines.push(`chain         ${r.chainBreakAt === null ? "unbroken" : `breaks at record ${r.chainBreakAt}`}`);
  lines.push(
    `verified with ${
      r.trust.source === "pinned"
        ? "a key you supplied"
        : r.trust.source === "in-ledger"
          ? "the key carried in these files"
          : "no key"
    }`,
  );
  lines.push(`              ${r.trust.note}`);
  lines.push(
    `effects with ${
      r.effectTrust.source === "pinned"
        ? "a key you supplied"
        : r.effectTrust.source === "in-ledger"
          ? "the key carried in these files"
          : "no key"
    }`,
  );
  lines.push(`              ${r.effectTrust.note}`);
  lines.push(
    `checkpoints with ${
      r.checkpointTrust.source === "pinned"
        ? "a key you supplied"
        : r.checkpointTrust.source === "in-ledger"
          ? "the key carried in these files"
          : "no key"
    }`,
  );
  lines.push(`              ${r.checkpointTrust.note}`);
  lines.push(r.index.line);
  if (r.tail.checkpoint) {
    const head = r.tail.checkpoint.chainHeadHash ?? "(no head hash)";
    const holds =
      r.tail.checkpoint.ledgerHoldsRecord === null
        ? "no head hash to look up"
        : r.tail.checkpoint.ledgerHoldsRecord
          ? "ledger holds that record"
          : "ledger does not hold that record";
    const covered =
      r.tail.checkpoint.receiptCount === null
        ? "no record count"
        : `${r.tail.checkpoint.receiptCount} record(s)`;
    lines.push(`checkpoint    newest covers ${covered}, head ${head}, ${holds}`);
  }
  lines.push(r.tail.line);
  if (r.problems.length > 0) {
    lines.push("");
    lines.push("problems:");
    for (const p of r.problems.slice(0, 50)) lines.push(`  - ${p}`);
    if (r.problems.length > 50) lines.push(`  … and ${r.problems.length - 50} more`);
  }
  lines.push("");
  lines.push(r.ok ? "VERIFIED" : "NOT VERIFIED");
  return lines.join("\n");
}

export async function runVerify(
  argv: readonly string[],
  out: (s: string) => void = (s) => process.stdout.write(`${s}\n`),
): Promise<number> {
  const args = [...argv];
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    out(usage());
    return args.length === 0 ? EX_VERIFY_FAILED : 0;
  }
  const json = args.includes("--json");
  let publicKeyPem: string | undefined;
  let effectPublicKeyPem: string | undefined;
  let checkpointPublicKeyPem: string | undefined;
  const readKeyFlag = (flag: string): { ok: true; pem?: string } | { ok: false } => {
    const at = args.indexOf(flag);
    if (at === -1) return { ok: true };
    const path = args[at + 1];
    if (!path || path.startsWith("-")) {
      out(`verify: ${flag} needs a file path`);
      return { ok: false };
    }
    try {
      const pem = readFileSync(path, "utf8");
      args.splice(at, 2);
      return { ok: true, pem };
    } catch {
      out(`verify: cannot read key file ${path}`);
      return { ok: false };
    }
  };
  const recordKey = readKeyFlag("--key");
  if (!recordKey.ok) return EX_VERIFY_FAILED;
  publicKeyPem = recordKey.pem;
  const effectKey = readKeyFlag("--effect-key");
  if (!effectKey.ok) return EX_VERIFY_FAILED;
  effectPublicKeyPem = effectKey.pem;
  const checkpointKey = readKeyFlag("--checkpoint-key");
  if (!checkpointKey.ok) return EX_VERIFY_FAILED;
  checkpointPublicKeyPem = checkpointKey.pem;
  const dir = args.find((a) => !a.startsWith("-"));
  if (!dir) {
    out(usage());
    return EX_VERIFY_FAILED;
  }
  if (directoryAccess(dir) === "unreadable") {
    out(unreadableSentence(dir));
    return 77;
  }

  let result: VerifyResult;
  try {
    result = await verifyLedger(dir, {
      ...(publicKeyPem ? { publicKeyPem } : {}),
      ...(effectPublicKeyPem ? { effectPublicKeyPem } : {}),
      ...(checkpointPublicKeyPem ? { checkpointPublicKeyPem } : {}),
    });
  } catch (err) {
    const problem = err instanceof Error ? err.message : "ledger could not be read";
    const failed: VerifyResult = {
      ok: false,
      directory: dir,
      decisions: 0,
      effects: 0,
      signaturesValid: 0,
      signaturesInvalid: 0,
      chainBreakAt: null,
      effectsBound: 0,
      effectsOrphaned: 0,
      trust: { source: "none", publicKeyPem: null, note: problem },
      effectTrust: { source: "none", publicKeyPem: null, note: problem },
      checkpointTrust: { source: "none", publicKeyPem: null, note: problem },
      index: { present: false, missing: 0, line: "index: none (cannot check for removed records)" },
      tail: {
        line: "tail: no checkpoint; removing the newest records with their effects is not detectable from these files",
        checkpoint: null,
      },
      problems: [problem],
    };
    out(json ? JSON.stringify(failed, null, 2) : renderVerify(failed));
    return EX_VERIFY_FAILED;
  }
  out(json ? JSON.stringify(result, null, 2) : renderVerify(result));
  return result.ok ? 0 : EX_VERIFY_FAILED;
}
