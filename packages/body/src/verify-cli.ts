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
 * Third-party extracts require reader-held --third-party-key <file> pins
 * (repeatable). Their signed row binds to its decision, but resultHash is
 * unattested. A record, effect or witness key cannot be a third-party pin.
 */
import { readFileSync } from "node:fs";

import { verifyLedger, type VerifyResult } from "@verax-ai/proxy";
import { verifyApprovalSignatures, type ApprovalSignatureReport } from "./approval-signature.ts";
import { verifyControlSignatures, type ControlSignatureReport } from "./control-signature.ts";
import { directoryAccess, unreadableSentence } from "./install.ts";
import { readStartSummary, renderStarts, type StartSummary } from "./heartbeat.ts";

export const EX_VERIFY_FAILED = 1;

function usage(): string {
  return [
    "usage: verax verify <stateDir> [--key <public.pem>] [--effect-key <public.pem>] [--witness-key <public.pem>] [--checkpoint-key <public.pem>] [--anchor-key <public.pem>] [--operator-credentials <file>] [--json]",
    "",
    "  <stateDir>        the directory holding decisions.jsonl and effects.jsonl",
    "  --key <file>      verify decision records against a public key you hold,",
    "                    instead of the one the records carry. This is the",
    "                    difference between 'these files agree with each other'",
    "                    and 'these files were signed by the key I was given'.",
    "  --effect-key <file>",
    "                    verify self effect rows against a public key you hold,",
    "                    instead of one key taken from the first self row. Same",
    "                    distinction as --key, for the effect signer. When this",
    "                    is set and the ledger has a same-org row, --witness-key",
    "                    is required too.",
    "  --witness-key <file>",
    "                    verify same-org effect rows against a public key you",
    "                    hold, instead of one key taken from the first same-org",
    "                    row. Agreement is not trust, the same as --key. When",
    "                    this is set and the ledger has a self row, --effect-key",
    "                    is required too.",
    "  --third-party-key <file>",
    "                    pin a downstream effect-extract signer (repeatable).",
    "                    No key is taken from a third-party row. Its resultHash",
    "                    is not attested. Body record/effect/witness keys refuse.",
    "  --checkpoint-key <file>",
    "                    verify every checkpoint row against a public key you",
    "                    hold, instead of one key taken from the checkpoint",
    "                    file. Same distinction as --key, for the witness.",
    "  --anchor-key <file>",
    "                    check the transparency-service receipts in",
    "                    checkpoint-anchors.jsonl under this service key. A",
    "                    receipt names no key of its own, so without this flag",
    "                    the receipts are counted and not checked.",
    "  --operator-credentials <file>",
    "                    verify HTTP approval signatures against this operator",
    "                    credential file, instead of operator-credentials.json",
    "                    in the state directory. A CLI approval is unsigned and",
    "                    is counted as such. Same distinction as --key.",
    "  --json            machine-readable result on stdout",
    "",
    "Exit code is 0 when the ledger verifies and 1 when it does not.",
  ].join("\n");
}

/** Lines a person reads. The trust line is never omitted. */
const APPROVAL_NOT_CHECKED: ApprovalSignatureReport = {
  ok: true,
  signedVerified: 0,
  signedFailed: 0,
  unsignedHttp: 0,
  cli: 0,
  line: "approval signatures  not checked",
  trustSource: "none",
  trustNote: "approval signatures were not checked",
};

const CONTROL_NOT_CHECKED: ControlSignatureReport = {
  ok: true,
  signedVerified: 0,
  signedFailed: 0,
  unsignedHttp: 0,
  cli: 0,
  file: 0,
  line: "control signatures   not checked",
  trustSource: "none",
  trustNote: "control signatures were not checked",
};

export function renderVerify(
  r: VerifyResult,
  approval: ApprovalSignatureReport = APPROVAL_NOT_CHECKED,
  control: ControlSignatureReport = CONTROL_NOT_CHECKED,
  starts?: StartSummary,
): string {
  const lines: string[] = [];
  lines.push(`ledger        ${r.directory}`);
  lines.push(`decisions     ${r.decisions}`);
  lines.push(`effects       ${r.effects} (${r.effectsBound} bound to a decision, ${r.effectsOrphaned} with none)`);
  if (r.effectsDeferred.length > 0) {
    lines.push(
      `deferred      ${r.effectsDeferred.length} allow(s) with no effect row yet, within the boundary allowance of the newest record (boundary-deferred, a warning): ${r.effectsDeferred.join(", ")}`,
    );
  }
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
  const witnessTrust = r.witnessTrust ?? {
    source: "none" as const,
    publicKeyPem: null,
    note: "no same-org effects, so no witness key was used",
  };
  lines.push(
    `same-org with ${
      witnessTrust.source === "pinned"
        ? "a key you supplied"
        : witnessTrust.source === "in-ledger"
          ? "the key carried in these files"
          : "no key"
    }`,
  );
  lines.push(`              ${witnessTrust.note}`);
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
  lines.push(r.effectCompleteness);
  lines.push(r.inputs.line);
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
  lines.push(r.control.line);
  for (const warning of r.control.warnings) lines.push(`warning       ${warning}`);
  lines.push(r.anchors.line);
  lines.push(approval.line);
  lines.push(`              ${approval.trustNote}`);
  // Halt and resume signatures are checked under the same operator key.
  lines.push(control.line);
  if (starts) lines.push(renderStarts(starts));
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
  let witnessPublicKeyPem: string | undefined;
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
      if (pem.trim() === "") {
        out(`verify-key-empty: ${flag}`);
        return { ok: false };
      }
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
  const witnessKey = readKeyFlag("--witness-key");
  if (!witnessKey.ok) return EX_VERIFY_FAILED;
  witnessPublicKeyPem = witnessKey.pem;
  const thirdPartyPublicKeyPems: string[] = [];
  while (args.includes("--third-party-key")) {
    const key = readKeyFlag("--third-party-key");
    if (!key.ok) return EX_VERIFY_FAILED;
    if (key.pem) thirdPartyPublicKeyPems.push(key.pem);
  }
  const checkpointKey = readKeyFlag("--checkpoint-key");
  if (!checkpointKey.ok) return EX_VERIFY_FAILED;
  checkpointPublicKeyPem = checkpointKey.pem;
  const anchorKey = readKeyFlag("--anchor-key");
  if (!anchorKey.ok) return EX_VERIFY_FAILED;
  const anchorPublicKeyPem = anchorKey.pem;
  let credentialsFile: string | undefined;
  const credentialsAt = args.indexOf("--operator-credentials");
  if (credentialsAt !== -1) {
    const path = args[credentialsAt + 1];
    if (!path || path.startsWith("-")) {
      out("verify: --operator-credentials needs a file path");
      return EX_VERIFY_FAILED;
    }
    try {
      const text = readFileSync(path, "utf8");
      if (text.trim() === "") {
        out("verify: operator credentials file is empty");
        return EX_VERIFY_FAILED;
      }
    } catch {
      out(`verify: cannot read operator credentials file ${path}`);
      return EX_VERIFY_FAILED;
    }
    args.splice(credentialsAt, 2);
    credentialsFile = path;
  }
  const dir = args.find((a) => !a.startsWith("-"));
  if (!dir) {
    out(usage());
    return EX_VERIFY_FAILED;
  }
  if (directoryAccess(dir) === "unreadable") {
    out(unreadableSentence(dir, "verify"));
    return 77;
  }

  let result: VerifyResult;
  try {
    result = await verifyLedger(dir, {
      thirdPartyPublicKeyPems,
      ...(publicKeyPem ? { publicKeyPem } : {}),
      ...(effectPublicKeyPem ? { effectPublicKeyPem } : {}),
      ...(witnessPublicKeyPem ? { witnessPublicKeyPem } : {}),
      ...(checkpointPublicKeyPem ? { checkpointPublicKeyPem } : {}),
      ...(anchorPublicKeyPem ? { anchorPublicKeyPem } : {}),
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
      effectsDeferred: [],
      trust: { source: "none", publicKeyPem: null, note: problem },
      effectTrust: { source: "none", publicKeyPem: null, note: problem },
      witnessTrust: { source: "none", publicKeyPem: null, note: problem },
      checkpointTrust: { source: "none", publicKeyPem: null, note: problem },
      index: { present: false, missing: 0, line: "index: none (cannot check for removed records)" },
      effectCompleteness: "effect completeness was not checked",
      tail: {
        line: "tail: no checkpoint; removing the newest records with their effects is not detectable from these files",
        checkpoint: null,
      },
      control: { line: "control: not checked", windows: 0, warnings: [] },
      inputs: { line: "inputs: not checked", matched: 0, missing: 0, mismatched: 0 },
      anchors: { line: "anchors: not checked", receipts: 0, verified: 0, checked: false },
      problems: [problem],
    };
    const starts = readStartSummary(dir);
    const failedReport = { ...failed, approvalSignatures: APPROVAL_NOT_CHECKED, controlSignatures: CONTROL_NOT_CHECKED, starts };
    out(json ? JSON.stringify(failedReport, null, 2) : renderVerify(failed, APPROVAL_NOT_CHECKED, CONTROL_NOT_CHECKED, starts));
    return EX_VERIFY_FAILED;
  }
  let approval: ApprovalSignatureReport;
  try {
    approval = await verifyApprovalSignatures(dir, credentialsFile ? { credentialsFile } : {});
  } catch (err) {
    const problem = err instanceof Error ? err.message : "approval signatures could not be read";
    approval = { ...APPROVAL_NOT_CHECKED, ok: false, trustNote: problem };
    result = { ...result, ok: false, problems: [...result.problems, problem] };
  }
  if (approval.signedFailed > 0) {
    result = {
      ...result,
      ok: false,
      problems: [...result.problems, `approval signatures: ${approval.signedFailed} did not verify`],
    };
  }
  let control: ControlSignatureReport;
  try {
    control = await verifyControlSignatures(dir, credentialsFile ? { credentialsFile } : {});
  } catch (err) {
    const problem = err instanceof Error ? err.message : "control signatures could not be read";
    control = { ...CONTROL_NOT_CHECKED, ok: false, trustNote: problem };
    result = { ...result, ok: false, problems: [...result.problems, problem] };
  }
  if (control.signedFailed > 0) {
    result = {
      ...result,
      ok: false,
      problems: [...result.problems, `control signatures: ${control.signedFailed} did not verify`],
    };
  }
  const reported = { ...result, approvalSignatures: approval, controlSignatures: control, starts: readStartSummary(dir) };
  out(json ? JSON.stringify(reported, null, 2) : renderVerify(reported, approval, control, reported.starts));
  return reported.ok ? 0 : EX_VERIFY_FAILED;
}
