import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { describe, it } from "node:test";

import {
  buildCheckpointClaims,
  checkpointHash,
  signCheckpoint,
  totalsFromDecisionRecords,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { canonical, decisionRecordHash, signDecisionRecord, type SignedDecisionRecord } from "@cedulon/core";
import { approvePending, approvalsLogFor, createProxy, FileLedger, loadPolicy, verifyLedger } from "@verax-ai/proxy";

import { runCli } from "../packages/body/src/cli.ts";
import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { persistPolicySnapshot } from "../packages/body/src/policy-store.ts";
import { directoryAccess } from "../packages/body/src/install.ts";
import {
  checkpointInWindow,
  countApprovalsFromSigned,
  EX_USAGE,
  parseReportDate,
  problemClass,
  readDecisionRecords,
  reportDigest,
  runReport,
  serializePeriodReport,
  subjectToolKey,
  writeOutExclusive,
  type PeriodReport,
} from "../packages/body/src/report-cli.ts";
import { EX_VERIFY_FAILED } from "../packages/body/src/verify-cli.ts";

const FROM = "2026-03-01";
const TO = "2026-03-31";
const FROM_MS = Date.UTC(2026, 2, 1);
const TO_EXCLUSIVE = Date.UTC(2026, 3, 1);
const SECRET_ARG = "SECRET_PAYEE_NEVER_IN_REPORT";
const ESCAPED_TOOL = `<script>x</script>."quoted"`;
const ESCAPED_TOOL_HTML = `&lt;script&gt;x&lt;/script&gt;.&quot;quoted&quot;`;
const IMG_TOOL = `<img src=x onerror=alert(1)`;
const IMG_TOOL_HTML = `&lt;img src=x onerror=alert(1)`;
const AMP_TOOL = `a'b&c`;
const AMP_TOOL_HTML = `a&#39;b&amp;c`;

const POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "memory-get-allow",
      tool: "memory.get",
      requires: ["verax:memory"],
      mode: "allow",
      text: "Reads are allowed.",
    },
    {
      id: "memory-put-approve",
      tool: "memory.put",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Writes need operator approval.",
    },
    {
      id: "escaped-tool-allow",
      tool: ESCAPED_TOOL,
      requires: ["verax:memory"],
      mode: "allow",
      text: "A tool name that needs escaping.",
    },
    {
      id: "img-tool-allow",
      tool: IMG_TOOL,
      requires: ["verax:memory"],
      mode: "allow",
      text: "A tool name with an img tag shape.",
    },
    {
      id: "amp-tool-allow",
      tool: AMP_TOOL,
      requires: ["verax:memory"],
      mode: "allow",
      text: "A tool name with apostrophe and ampersand.",
    },
    {
      id: "proto-tool-allow",
      tool: "__proto__",
      requires: ["verax:memory"],
      mode: "allow",
      text: "A tool name that collides with Object.prototype.",
    },
    {
      id: "constructor-tool-allow",
      tool: "constructor",
      requires: ["verax:memory"],
      mode: "allow",
      text: "A tool name equal to constructor.",
    },
    {
      id: "tostring-tool-allow",
      tool: "toString",
      requires: ["verax:memory"],
      mode: "allow",
      text: "A tool name equal to toString.",
    },
  ],
};

function capture(): { out: (s: string) => void; text: () => string } {
  const parts: string[] = [];
  return {
    out: (s) => parts.push(s),
    text: () => parts.join("\n"),
  };
}

/** A fresh directory that is NOT a state directory: where --out files go. */
function outDir(): string {
  return mkdtempSync(join(tmpdir(), "verax-report-out-"));
}

async function reportJson(
  dir: string,
  extra: readonly string[] = [],
): Promise<{ code: number; report: PeriodReport; text: string }> {
  const c = capture();
  const code = await runReport([dir, "--from", FROM, "--to", TO, "--json", ...extra], c.out);
  return { code, report: JSON.parse(c.text()) as PeriodReport, text: c.text() };
}

async function reportText(dir: string): Promise<{ code: number; text: string }> {
  const c = capture();
  const code = await runReport([dir, "--from", FROM, "--to", TO], c.out);
  return { code, text: c.text() };
}

/** Writes the HTML report outside the state directory and returns it. */
async function reportHtml(dir: string): Promise<{ code: number; html: string; stdout: string; path: string }> {
  const path = join(outDir(), "period.html");
  const c = capture();
  const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", path], c.out);
  return { code, html: existsSync(path) ? readFileSync(path, "utf8") : "", stdout: c.text(), path };
}

/** The report CLI through the real dispatcher: stdout and stderr both captured. */
async function throughDispatcher(argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  const code = await runCli(["report", ...argv], {
    elevated: () => false,
    stdout: { write: (s: string) => (stdout += s) },
    stderr: { write: (s: string) => (stderr += s) },
  });
  return { code, stdout, stderr };
}

function hasStackFrames(text: string): boolean {
  return /\n\s+at [^\n]*(\(|:\d+)/.test(`\n${text}`) || /\bat [\w.<>]+ \(/.test(text);
}

function writeCheckpoint(dir: string): SignedCheckpoint {
  const lines = readFileSync(join(dir, "decisions.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "");
  const rows = lines.map((line) => JSON.parse(line) as SignedDecisionRecord);
  const endMs = Math.max(...rows.map((r) => r.claims.timestampMs)) + 1;
  const startMs = Math.min(...rows.map((r) => r.claims.timestampMs));
  const claims = buildCheckpointClaims(
    0,
    rows,
    startMs,
    endMs,
    null,
    totalsFromDecisionRecords,
    (row: SignedDecisionRecord) => decisionRecordHash(row),
  );
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const signed = signCheckpoint(
    claims,
    privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey.export({ type: "spki", format: "pem" }).toString(),
  );
  writeFileSync(join(dir, "checkpoints.jsonl"), `${JSON.stringify(signed)}\n`, "utf8");
  return signed;
}

async function buildLedger(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "verax-report-"));
  const signers = loadOrCreateSigners(dir);
  const policy = loadPolicy(POLICY);
  persistPolicySnapshot(dir, policy.hash, POLICY);

  let clock = FROM_MS - 1;
  const now = () => clock;
  const refs = ["before", "at-from", "allow-1", "deny-1", "escape-tool", "img-tool", "amp-tool", "after"];
  let r = 0;
  const nonce = () => {
    const n = refs[r];
    if (n === undefined) throw new Error(`nonce-exhausted at ${r}`);
    r += 1;
    return n;
  };

  const ledger = new FileLedger(dir);
  const proxy = createProxy({
    policy,
    recordSigner: signers.recordSigner,
    effectSigner: signers.effectSigner,
    ledger,
    now,
    nonce,
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  const principal = { brain: "brain-1", scopes: new Set(["verax:memory"]) };

  // before window
  clock = FROM_MS - 1;
  await proxy.call({ name: "memory.get", arguments: { id: "before" } }, principal);
  // at from (included)
  clock = FROM_MS;
  await proxy.call({ name: "memory.get", arguments: { id: "at-from" } }, principal);
  // allow in window
  clock = Date.UTC(2026, 2, 10, 12);
  await proxy.call({ name: "memory.get", arguments: { id: "in-window" } }, principal);
  // deny in window (missing scope)
  clock = Date.UTC(2026, 2, 12, 12);
  await proxy.call({ name: "memory.get", arguments: { id: "denied" } }, { brain: "brain-1", scopes: new Set() });
  // defer in window (will approve); args carry a value that must not appear in the report
  const heldArgs = {
    id: "n1",
    body: SECRET_ARG,
    source: { kind: "t" },
    validUntilMs: 9_999,
    payee: SECRET_ARG,
    _ref: "defer-approved",
  };
  clock = Date.UTC(2026, 2, 15, 12);
  await proxy.call({ name: "memory.put", arguments: heldArgs }, principal);
  // Approve the held call while its TTL still covers the controlled clock, then retry so an effect lands.
  clock = Date.UTC(2026, 2, 15, 12) + 1_000;
  const approved = await approvePending({
    ledger,
    recordSigner: signers.recordSigner,
    now,
    nonce: () => "allow-approved",
    ref: "defer-approved",
    approverId: "test-operator",
    via: "cli-script",
    policyHash: policy.hash,
    approvals: approvalsLogFor(ledger),
    inputsLog: proxy.inputsLog,
  });
  assert.equal(approved.ok, true, "approve of held call");
  clock = Date.UTC(2026, 2, 15, 12) + 2_000;
  await proxy.call({ name: "memory.put", arguments: heldArgs }, principal);
  // escaped tool names in window
  clock = Date.UTC(2026, 2, 20, 12);
  await proxy.call({ name: ESCAPED_TOOL, arguments: { x: 1 } }, principal);
  clock = Date.UTC(2026, 2, 20, 13);
  await proxy.call({ name: IMG_TOOL, arguments: { x: 1 } }, principal);
  clock = Date.UTC(2026, 2, 20, 14);
  await proxy.call({ name: AMP_TOOL, arguments: { x: 1 } }, principal);

  // after window (to+1 day)
  clock = TO_EXCLUSIVE;
  await proxy.call({ name: "memory.get", arguments: { id: "after" } }, principal);

  ledger.close();

  // Leave a second hold still pending inside the window.
  const holdClock = Date.UTC(2026, 2, 22, 12);
  const ledger2 = new FileLedger(dir);
  const proxy2 = createProxy({
    policy,
    recordSigner: signers.recordSigner,
    effectSigner: signers.effectSigner,
    ledger: ledger2,
    now: () => holdClock,
    nonce: () => "still-held",
    inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
  });
  await proxy2.call(
    {
      name: "memory.put",
      arguments: { id: "n2", body: "y", source: { kind: "t" }, validUntilMs: 9_999 },
    },
    principal,
  );
  ledger2.close();

  writeCheckpoint(dir);
  return dir;
}

// ---------------------------------------------------------------------------
// Hand-built ledgers: records are really signed and chained, and each record
// has its inputs row, so the ledger verifies unless a case needs it not to.
// This is how adversarial approval matching is set up without a proxy.
// ---------------------------------------------------------------------------

const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const REQ_A = sha("request-a");
const REQ_B = sha("request-b");

type Spec = {
  decision: "allow" | "deny" | "defer";
  /** Signed ref. null: the record carries no ref (and gets no inputs row). */
  ref: string | null;
  ts: number;
  subject?: string;
  requestHash?: string;
  /** approver.resolves in the hash-bound inputs row. */
  resolves?: string;
  /** approver.signature field in the hash-bound inputs row. */
  signature?: unknown;
};

const DAY = Date.UTC(2026, 2, 10, 12);

const defer = (ref: string | null, ts: number, extra: Partial<Spec> = {}): Spec => ({
  decision: "defer",
  ref,
  ts,
  ...extra,
});
const answer = (decision: "allow" | "deny", ref: string, resolves: string, ts: number, extra: Partial<Spec> = {}): Spec => ({
  decision,
  ref,
  ts,
  resolves,
  ...extra,
});

async function handLedger(specs: readonly Spec[]): Promise<{ dir: string; records: SignedDecisionRecord[] }> {
  const dir = mkdtempSync(join(tmpdir(), "verax-report-hand-"));
  const signers = loadOrCreateSigners(dir);
  const ledger = new FileLedger(dir);
  try {
    for (const [i, s] of specs.entries()) {
      const subject = s.subject ?? "memory.put";
      const inputs = {
        principal: { brain: "brain-1", scopes: [] as string[] },
        inputs: [] as unknown[],
        n: i,
        ...(s.resolves !== undefined
          ? {
              approver: {
                id: "test-operator",
                via: "cli-script",
                resolves: s.resolves,
                ...(s.signature !== undefined ? { signature: s.signature } : {}),
              },
            }
          : {}),
      };
      if (s.ref !== null) {
        appendFileSync(join(dir, "inputs.jsonl"), `${JSON.stringify({ ref: s.ref, inputs })}\n`, "utf8");
      }
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: s.decision === "defer" ? "verax-proxy" : "verax-operator",
            subject,
            requestHash: s.requestHash ?? REQ_A,
            policyHash: sha("policy"),
            inputsHash: sha(canonical(inputs)),
            decision: s.decision,
            reasonCode: s.decision === "allow" ? "approved-by-operator" : s.decision === "deny" ? "expired" : "needs-approval",
            ref: s.ref,
            effectHash: s.decision === "allow" ? sha(`effect-${i}`) : null,
            effectClass: subject,
            timestampMs: s.ts,
            nonce: `hand-${i}`,
            prevRecordHash: prev,
          } as never,
          signers.recordSigner.privateKeyPem,
          signers.recordSigner.publicKeyPem,
        ),
      );
    }
  } finally {
    ledger.close();
  }
  return { dir, records: readDecisionRecords(dir) };
}

function approvalCounts(dir: string, records: readonly SignedDecisionRecord[]): ReturnType<typeof countApprovalsFromSigned> {
  return countApprovalsFromSigned(dir, records, FROM_MS, TO_EXCLUSIVE);
}

function sumOf(a: {
  approved: number;
  closedWithoutAllow: number;
  heldWithoutBoundAnswer: number;
  unmatched: number;
}): number {
  return a.approved + a.closedWithoutAllow + a.heldWithoutBoundAnswer + a.unmatched;
}

function deferCount(records: readonly SignedDecisionRecord[]): number {
  return records.filter(
    (r) => r.claims.decision === "defer" && r.claims.timestampMs >= FROM_MS && r.claims.timestampMs < TO_EXCLUSIVE,
  ).length;
}

describe("verax report", () => {
  it("parseReportDate accepts calendar dates and refuses bad ones", () => {
    assert.equal(parseReportDate("2026-03-01"), Date.UTC(2026, 2, 1));
    assert.equal(parseReportDate("2026-02-30"), null);
    assert.equal(parseReportDate("2026-3-1"), null);
    assert.equal(parseReportDate("not-a-date"), null);
  });

  it("problemClass keeps known classes and refuses free text, paths and URLs", () => {
    assert.equal(problemClass("ledger-manifest-corrupt: Expected property name"), "ledger-manifest-corrupt");
    assert.equal(problemClass("approvals-malformed"), "approvals-malformed");
    assert.equal(problemClass("signature does not verify: record 2 (ref allow-1)"), "signature does not verify");
    assert.equal(problemClass("symbolic link: C:\\Users\\x\\ledger"), "symbolic link");
    assert.equal(problemClass("missing piece: decisions.jsonl"), "missing piece");
    assert.equal(problemClass("C:\\Users\\x\\ledger: torn line in decisions.jsonl"), "unclassified");
    assert.equal(problemClass("https://evil.example/x: planted detail"), "unclassified");
    assert.equal(problemClass("SOME UPPER CASE ERROR WITHOUT A COLON"), "unclassified");
    assert.equal(problemClass(`${"a".repeat(200)}: detail after a long label`), "unclassified");
  });

  it("j1. problemClass takes only a known class; ledger refs never appear in the report", async () => {
    const refColon = "private-payee:123";
    const refKnownClass = "signature does not verify";
    const refSixty = "a".repeat(60);
    assert.equal(problemClass(`decision-without-effect ${refColon}`), "decision-without-effect");
    assert.equal(problemClass(`decision-without-effect ${refKnownClass}`), "decision-without-effect");
    assert.equal(problemClass(`decision-without-effect ${refSixty}`), "decision-without-effect");
    // A phrase that looks like a class but is not on the verifier's list.
    assert.equal(problemClass("invented-class-with-space detail: more"), "unclassified");

    const dir = mkdtempSync(join(tmpdir(), "verax-report-j1-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    const refs = [refColon, refKnownClass, refSixty];
    try {
      for (const [i, ref] of refs.entries()) {
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.get",
              requestHash: sha(`req-j1-${i}`),
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "allow",
              reasonCode: "ok",
              ref,
              effectHash: sha(`effect-j1-${i}`),
              effectClass: "memory.get",
              // Older than the default boundary allowance of the trailing deny.
              timestampMs: DAY + i,
              nonce: `j1-${i}`,
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
      }
      // Newest record: pulls the three allows outside the in-flight allowance
      // so default verifyLedger names decision-without-effect for each.
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "memory.get",
            requestHash: sha("req-j1-tail"),
            policyHash: sha("policy"),
            inputsHash: null,
            decision: "deny",
            reasonCode: "denied",
            ref: "j1-tail",
            effectHash: null,
            effectClass: "memory.get",
            timestampMs: DAY + 600_000,
            nonce: "j1-tail",
            prevRecordHash: prev,
          } as never,
          signers.recordSigner.privateKeyPem,
          signers.recordSigner.publicKeyPem,
        ),
      );
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, false);
    for (const ref of refs) {
      assert.ok(verified.problems.includes(`decision-without-effect ${ref}`), ref);
    }

    const json = await reportJson(dir);
    const text = await reportText(dir);
    const html = await reportHtml(dir);
    const via = await throughDispatcher([dir, "--from", FROM, "--to", TO, "--json"]);
    const surfaces = [json.text, text.text, html.html, via.stdout, via.stderr];
    for (const ref of refs) {
      for (const surface of surfaces) {
        assert.equal(surface.includes(ref), false, `ref leaked: ${ref}`);
      }
    }
    assert.ok(json.report.verification.problems.includes("decision-without-effect"));
    assert.equal(json.report.verification.problems.includes(`decision-without-effect ${refColon}`), false);
    assert.equal(json.report.verification.problems.some((p) => p.includes(refColon)), false);
  });

  it("j4. empty or missing subject counts under one fixed byTool key that sums to total", async () => {
    // A non-string subject cannot appear on a verifying ledger (signature fails).
    // subjectToolKey still maps empty and missing to the same reserved key.
    const missingKey = "\u001f";
    assert.equal(subjectToolKey(""), missingKey);
    assert.equal(subjectToolKey(undefined), missingKey);
    assert.equal(subjectToolKey(null), missingKey);
    assert.equal(subjectToolKey("memory.put"), "memory.put");

    const dir = mkdtempSync(join(tmpdir(), "verax-report-j4-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    try {
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "",
            requestHash: REQ_A,
            policyHash: sha("policy"),
            inputsHash: null,
            decision: "defer",
            reasonCode: "needs-approval",
            ref: "empty-subj",
            effectHash: null,
            effectClass: "memory.put",
            timestampMs: DAY,
            nonce: "j4-empty",
            prevRecordHash: prev,
          } as never,
          signers.recordSigner.privateKeyPem,
          signers.recordSigner.publicKeyPem,
        ),
      );
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "memory.put",
            requestHash: REQ_A,
            policyHash: sha("policy"),
            inputsHash: null,
            decision: "defer",
            reasonCode: "needs-approval",
            ref: "ordinary",
            effectHash: null,
            effectClass: "memory.put",
            timestampMs: DAY + 2,
            nonce: "j4-ord",
            prevRecordHash: prev,
          } as never,
          signers.recordSigner.privateKeyPem,
          signers.recordSigner.publicKeyPem,
        ),
      );
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "memory.get",
            requestHash: REQ_A,
            policyHash: sha("policy"),
            inputsHash: null,
            decision: "deny",
            reasonCode: "denied",
            ref: "ordinary-deny",
            effectHash: null,
            effectClass: "memory.get",
            timestampMs: DAY + 3,
            nonce: "j4-deny",
            prevRecordHash: prev,
          } as never,
          signers.recordSigner.privateKeyPem,
          signers.recordSigner.publicKeyPem,
        ),
      );
    } finally {
      ledger.close();
    }
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, JSON.stringify(verified.problems));

    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    const total = report.decisions.total!;
    const byTool = report.decisions.byTool!;
    assert.equal(byTool[missingKey]?.defer, 1);
    assert.equal(byTool["memory.put"]?.defer, 1);
    assert.equal(byTool["memory.get"]?.deny, 1);
    for (const kind of ["allow", "deny", "defer"] as const) {
      const sum = Object.values(byTool).reduce((n, c) => n + c[kind], 0);
      assert.equal(sum, total[kind], kind);
    }
  });

  it("j3. report verifies with default options only; pinned verify differs on valid-anchored", async () => {
    const root = join("test-vectors", "v1", "valid-anchored");
    const ledger = join(root, "ledger");
    const pins = join(root, "pins");
    let verifyOut = "";
    const verifyCode = await runCli(
      [
        "verify",
        ledger,
        "--key",
        join(pins, "record-key.pem"),
        "--witness-key",
        join(pins, "witness-key.pem"),
        "--checkpoint-key",
        join(pins, "witness-key.pem"),
        "--operator-credentials",
        join(pins, "operator-credentials.json"),
        "--anchor-key",
        join(pins, "anchor-key.pem"),
      ],
      {
        elevated: () => false,
        stdout: { write: (s: string) => (verifyOut += s) },
        stderr: { write: () => {} },
      },
    );
    assert.equal(verifyCode, 0, verifyOut);
    assert.match(verifyOut, /VERIFIED/);

    const report = await throughDispatcher([ledger, "--from", "2026-10-01", "--to", "2026-10-02"]);
    assert.equal(report.code, EX_VERIFY_FAILED, report.stdout);
    assert.match(report.stdout, /NOT VERIFIED/);

    const refused = await throughDispatcher([
      ledger,
      "--from",
      "2026-10-01",
      "--to",
      "2026-10-02",
      "--anchor-key",
      join(pins, "anchor-key.pem"),
    ]);
    assert.equal(refused.code, EX_USAGE);
    assert.match(refused.stdout, /unknown option --anchor-key/);

    const help = capture();
    assert.equal(await runReport(["--help"], help.out), 0);
    assert.match(help.text(), /default options only/);
    assert.match(help.text(), /does not (accept|take|check).*key|key pins|anchor-key|operator-credentials|require-signed-starts/i);
    const { report: body } = await reportJson(await buildLedger());
    assert.equal(body.whatThisReportDoesNotShow.includes("when the anchor key was supplied"), false);
    assert.ok(body.whatThisReportDoesNotShow.includes("default options only"));
  });

  it("j2. unbound terminals do not present stillHeld as established", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-report-j2-"));
    const signers = loadOrCreateSigners(dir);
    const ledger = new FileLedger(dir);
    try {
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-proxy",
            subject: "memory.put",
            requestHash: REQ_A,
            policyHash: sha("policy"),
            inputsHash: null,
            decision: "defer",
            reasonCode: "needs-approval",
            ref: "d-unbound",
            effectHash: null,
            effectClass: "memory.put",
            timestampMs: DAY,
            nonce: "j2-defer",
            prevRecordHash: prev,
          } as never,
          signers.recordSigner.privateKeyPem,
          signers.recordSigner.publicKeyPem,
        ),
      );
      await ledger.appendDecisionChained((prev) =>
        signDecisionRecord(
          {
            decider: "verax-operator",
            subject: "memory.put",
            requestHash: REQ_A,
            policyHash: sha("policy"),
            inputsHash: null,
            decision: "deny",
            reasonCode: "expired",
            ref: "a-unbound",
            effectHash: null,
            effectClass: "memory.put",
            timestampMs: DAY + 100,
            nonce: "j2-deny",
            prevRecordHash: prev,
          } as never,
          signers.recordSigner.privateKeyPem,
          signers.recordSigner.publicKeyPem,
        ),
      );
    } finally {
      ledger.close();
    }
    writeFileSync(
      join(dir, "inputs.jsonl"),
      `${JSON.stringify({ ref: "a-unbound", inputs: { approver: { resolves: "d-unbound" } } })}\n`,
      "utf8",
    );
    const verified = await verifyLedger(dir);
    assert.equal(verified.ok, true, JSON.stringify(verified.problems));

    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    assert.equal(report.approvals.terminalsWithoutBoundInputs, 1);
    assert.equal(report.approvals.stillHeld, null, "unbound answer makes stillHeld unestablished");
    assert.equal(report.approvals.heldWithoutBoundAnswer, 1);
    assert.equal(report.approvals.heldPossiblyAnsweredByUnbound, 1);
    assert.equal(report.approvals.unmatched, 0);
    assert.equal(report.approvals.unavailableReason, null);

    const plain = await reportText(dir);
    assert.match(plain.text, /could have been answered by an unbound record/);
    assert.match(plain.text, /still held not available|still held: not available|Still held: not available/i);

    // Identity over ledgers (comment in countApprovalsFromSigned):
    // approved + closedWithoutAllow + unmatched + heldWithoutBoundAnswer = window defer count.
    // stillHeld is null whenever a held defer could be answered by an unbound record after it.
    const ledgers: { dir: string; records: SignedDecisionRecord[] }[] = [
      await handLedger([defer("d1", DAY)]),
      await handLedger([defer("d1", DAY), answer("allow", "a1", "d1", DAY + 100)]),
      await handLedger([defer("d1", DAY), answer("deny", "a1", "d1", DAY + 100)]),
      await handLedger([defer("d1", DAY), defer("d2", DAY + 50)]),
      await handLedger([defer(null, DAY), answer("allow", "a1", "nope", DAY + 100)]),
      await handLedger([
        defer("dup", DAY),
        defer("dup", DAY + 50),
        answer("allow", "a1", "dup", DAY + 100),
      ]),
    ];
    for (const { dir: d, records } of ledgers) {
      const c = approvalCounts(d, records);
      const windowDefers = deferCount(records);
      assert.equal(
        c.approved + c.closedWithoutAllow + c.unmatched + c.heldWithoutBoundAnswer,
        windowDefers,
        `identity for ${d}`,
      );
      assert.equal(
        c.stillHeld,
        c.heldPossiblyAnsweredByUnbound === 0 ? c.heldWithoutBoundAnswer : null,
      );
      assert.ok(c.heldPossiblyAnsweredByUnbound <= c.heldWithoutBoundAnswer);
    }
  });

  it("k1. an unbound answer outside the window makes stillHeld unestablished", async () => {
    // March defer, April 1 unbound deny that names it: same request hash and tool.
    const april = Date.UTC(2026, 3, 1);
    async function ledgerWithUnboundAt(unboundTs: number): Promise<string> {
      const dir = mkdtempSync(join(tmpdir(), "verax-report-k1-"));
      const signers = loadOrCreateSigners(dir);
      const ledger = new FileLedger(dir);
      try {
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "defer",
              reasonCode: "needs-approval",
              ref: "d",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: DAY,
              nonce: "k1-defer",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-operator",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "deny",
              reasonCode: "expired",
              ref: "u",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: unboundTs,
              nonce: "k1-deny",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
      } finally {
        ledger.close();
      }
      writeFileSync(
        join(dir, "inputs.jsonl"),
        `${JSON.stringify({ ref: "u", inputs: { approver: { resolves: "d" } } })}\n`,
        "utf8",
      );
      const verified = await verifyLedger(dir);
      assert.equal(verified.ok, true, JSON.stringify(verified.problems));
      return dir;
    }

    const outside = await ledgerWithUnboundAt(april);
    const outReport = await reportJson(outside);
    assert.equal(outReport.code, 0, outReport.text);
    assert.equal(outReport.report.approvals.terminalsWithoutBoundInputs, 0);
    assert.equal(outReport.report.approvals.heldWithoutBoundAnswer, 1);
    assert.equal(outReport.report.approvals.heldPossiblyAnsweredByUnbound, 1);
    assert.equal(outReport.report.approvals.stillHeld, null);

    const inside = await ledgerWithUnboundAt(DAY + 100);
    const inReport = await reportJson(inside);
    assert.equal(inReport.code, 0, inReport.text);
    assert.equal(inReport.report.approvals.terminalsWithoutBoundInputs, 1);
    assert.equal(inReport.report.approvals.heldPossiblyAnsweredByUnbound, 1);
    assert.equal(inReport.report.approvals.stillHeld, null);

    // Identity: out-of-window unbound after defer, and unbound before defer (must not count).
    const afterOutside = await (async () => {
      const dir = mkdtempSync(join(tmpdir(), "verax-report-k1-id-"));
      const signers = loadOrCreateSigners(dir);
      const ledger = new FileLedger(dir);
      try {
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "defer",
              reasonCode: "needs-approval",
              ref: "d-id",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: DAY,
              nonce: "k1-id-d",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-operator",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "deny",
              reasonCode: "expired",
              ref: "u-after",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: april,
              nonce: "k1-id-u",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
      } finally {
        ledger.close();
      }
      writeFileSync(
        join(dir, "inputs.jsonl"),
        `${JSON.stringify({ ref: "u-after", inputs: { approver: { resolves: "d-id" } } })}\n`,
        "utf8",
      );
      return { dir, records: readDecisionRecords(dir) };
    })();
    const beforeUnbound = await (async () => {
      const dir = mkdtempSync(join(tmpdir(), "verax-report-k1-before-"));
      const signers = loadOrCreateSigners(dir);
      const ledger = new FileLedger(dir);
      try {
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-operator",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "deny",
              reasonCode: "expired",
              ref: "u-before",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: DAY - 50,
              nonce: "k1-before-u",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "defer",
              reasonCode: "needs-approval",
              ref: "d-before",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: DAY,
              nonce: "k1-before-d",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
      } finally {
        ledger.close();
      }
      writeFileSync(
        join(dir, "inputs.jsonl"),
        `${JSON.stringify({ ref: "u-before", inputs: { approver: { resolves: "d-before" } } })}\n`,
        "utf8",
      );
      return { dir, records: readDecisionRecords(dir) };
    })();

    for (const { dir: d, records } of [afterOutside, beforeUnbound]) {
      const c = approvalCounts(d, records);
      assert.equal(
        c.approved + c.closedWithoutAllow + c.unmatched + c.heldWithoutBoundAnswer,
        deferCount(records),
        `identity for ${d}`,
      );
      assert.equal(
        c.stillHeld,
        c.heldPossiblyAnsweredByUnbound === 0 ? c.heldWithoutBoundAnswer : null,
      );
      assert.ok(c.heldPossiblyAnsweredByUnbound <= c.heldWithoutBoundAnswer);
    }
    const beforeCounts = approvalCounts(beforeUnbound.dir, beforeUnbound.records);
    assert.equal(beforeCounts.heldPossiblyAnsweredByUnbound, 0);
    assert.equal(beforeCounts.stillHeld, 1);
    const afterCounts = approvalCounts(afterOutside.dir, afterOutside.records);
    assert.equal(afterCounts.heldPossiblyAnsweredByUnbound, 1);
    assert.equal(afterCounts.stillHeld, null);
  });

  it("k2. heldPossiblyAnsweredByUnbound is the same for every inputs-row order", async () => {
    async function unboundWithInputOrder(
      resolvesOrder: readonly string[],
    ): Promise<{ dir: string; records: SignedDecisionRecord[] }> {
      const dir = mkdtempSync(join(tmpdir(), "verax-report-k2-"));
      const signers = loadOrCreateSigners(dir);
      const ledger = new FileLedger(dir);
      try {
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "defer",
              reasonCode: "needs-approval",
              ref: "d1",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: DAY,
              nonce: "k2-d1",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-proxy",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "defer",
              reasonCode: "needs-approval",
              ref: "d2",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: DAY + 50,
              nonce: "k2-d2",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-operator",
              subject: "memory.put",
              requestHash: REQ_A,
              policyHash: sha("policy"),
              inputsHash: null,
              decision: "deny",
              reasonCode: "expired",
              ref: "u-multi",
              effectHash: null,
              effectClass: "memory.put",
              timestampMs: DAY + 100,
              nonce: "k2-u",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
      } finally {
        ledger.close();
      }
      const lines = resolvesOrder.map((resolves) =>
        JSON.stringify({ ref: "u-multi", inputs: { approver: { resolves } } }),
      );
      writeFileSync(join(dir, "inputs.jsonl"), `${lines.join("\n")}\n`, "utf8");
      const verified = await verifyLedger(dir);
      assert.equal(verified.ok, true, JSON.stringify(verified.problems));
      return { dir, records: readDecisionRecords(dir) };
    }

    const orderD1First = await unboundWithInputOrder(["d1", "unrelated", "d2"]);
    const orderUnrelatedFirst = await unboundWithInputOrder(["unrelated", "d1", "d2"]);
    const a = approvalCounts(orderD1First.dir, orderD1First.records);
    const b = approvalCounts(orderUnrelatedFirst.dir, orderUnrelatedFirst.records);
    assert.equal(a.heldWithoutBoundAnswer, 2);
    assert.equal(a.heldPossiblyAnsweredByUnbound, 2);
    assert.equal(a.stillHeld, null);
    assert.equal(b.heldWithoutBoundAnswer, a.heldWithoutBoundAnswer);
    assert.equal(b.heldPossiblyAnsweredByUnbound, a.heldPossiblyAnsweredByUnbound);
    assert.equal(b.stillHeld, a.stillHeld);
    assert.equal(b.terminalsWithoutBoundInputs, a.terminalsWithoutBoundInputs);
  });

  // -------------------------------------------------------------------------
  // Happy path counts
  // -------------------------------------------------------------------------

  it("counts match the records in the window, per tool and in total", async () => {
    const dir = await buildLedger();
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    assert.equal(report.verification.ok, true);
    assert.equal(report.countsUnavailableReason, null);
    assert.equal(report.unsignedApprovalsNote, null);
    const total = report.decisions.total!;
    const byTool = report.decisions.byTool!;
    // in window: at-from allow, allow-1 allow, deny-1 deny, defer-approved defer,
    // allow-approved allow, escape-tool allow, img-tool allow, amp-tool allow, still-held defer.
    assert.equal(total.allow, 6);
    assert.equal(total.deny, 1);
    assert.equal(total.defer, 2);
    assert.equal(byTool["memory.get"]?.allow, 2);
    assert.equal(byTool["memory.get"]?.deny, 1);
    assert.equal(byTool["memory.put"]?.defer, 2);
    assert.equal(byTool["memory.put"]?.allow, 1);
    assert.equal(byTool[ESCAPED_TOOL]?.allow, 1);
    assert.equal(byTool[IMG_TOOL]?.allow, 1);
    assert.equal(byTool[AMP_TOOL]?.allow, 1);
    const a = report.approvals;
    assert.equal(a.approved, 1);
    assert.equal(a.withoutOperatorSignatureField, 1);
    assert.equal(a.withOperatorSignatureFieldPresent, 0);
    assert.equal(a.closedWithoutAllow, 0);
    assert.equal(a.stillHeld, 1);
    assert.equal(a.unmatched, 0);
    assert.equal(
      a.approved! + a.closedWithoutAllow! + a.heldWithoutBoundAnswer! + a.unmatched!,
      total.defer,
    );
    assert.equal(report.checkpoints.count, 1);
    assert.equal(report.checkpoints.withAnchorVerified, 0);
    assert.equal(report.checkpoints.anchorRowsPresentNotChecked, 0);
    assert.equal(report.recordCount, 9);
  });

  it("excludes one millisecond before from and the instant at to+1 day; includes from midnight", async () => {
    const dir = await buildLedger();
    const { report } = await reportJson(dir);
    assert.equal(report.firstRecordMs, FROM_MS);
    assert.ok(report.lastRecordMs! < TO_EXCLUSIVE);
    assert.ok(report.lastRecordMs! >= FROM_MS);
    const decisions = readFileSync(join(dir, "decisions.jsonl"), "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as { claims: { timestampMs: number; ref: string } });
    assert.ok(decisions.some((d) => d.claims.timestampMs === FROM_MS - 1));
    assert.ok(decisions.some((d) => d.claims.timestampMs === TO_EXCLUSIVE));
    assert.equal(
      decisions.filter((d) => d.claims.timestampMs >= FROM_MS && d.claims.timestampMs < TO_EXCLUSIVE).length,
      report.recordCount,
    );
  });

  it("running twice gives byte-identical JSON; the HTML digest equals SHA-256 of that JSON", async () => {
    const dir = await buildLedger();
    const a = await reportJson(dir);
    const b = await reportJson(dir);
    assert.equal(a.text, b.text);
    const digest = reportDigest(a.text);
    const { code, html } = await reportHtml(dir);
    assert.equal(code, 0);
    assert.ok(html.includes(`<code>${digest}</code>`));
    assert.equal(createHash("sha256").update(a.text, "utf8").digest("hex"), digest);
  });

  it("JSON digest matches for relative path, absolute path, and a copy of the ledger", async () => {
    const dir = await buildLedger();
    const abs = resolve(dir);
    const copyDir = mkdtempSync(join(tmpdir(), "verax-report-copy-"));
    for (const name of readdirSync(dir)) {
      const src = join(dir, name);
      const dest = join(copyDir, name);
      try {
        copyFileSync(src, dest);
      } catch {
        // skip non-files (lock dirs)
      }
    }
    const a = await reportJson(dir);
    const b = await reportJson(abs);
    const c = await reportJson(copyDir);
    assert.equal(a.code, 0, a.text);
    assert.equal(b.code, 0, b.text);
    assert.equal(c.code, 0, c.text);
    assert.equal(a.text, b.text);
    assert.equal(a.text, c.text);
    assert.equal(a.text.includes('"directory"'), false);
    assert.equal(a.text.includes(dir.replaceAll("\\", "\\\\")), false);
    const text = await reportText(dir);
    assert.equal(text.text.includes(dir), false);
    const html = await reportHtml(dir);
    assert.equal(html.html.includes(dir), false);
  });

  it("HTML escapes <script>, <img> and & in tool names and keeps them intact in JSON", async () => {
    const dir = await buildLedger();
    const { report } = await reportJson(dir);
    for (const tool of [ESCAPED_TOOL, IMG_TOOL, AMP_TOOL]) {
      assert.ok(Object.prototype.hasOwnProperty.call(report.decisions.byTool, tool), tool);
    }
    const { html } = await reportHtml(dir);
    assert.equal(/<script/i.test(html), false);
    assert.equal(html.includes("<img"), false);
    assert.ok(html.includes(ESCAPED_TOOL_HTML));
    assert.ok(html.includes(IMG_TOOL_HTML));
    assert.ok(html.includes(AMP_TOOL_HTML));
  });

  it("WHAT_NOT_SHOWN names the hold-time, answer-order, window and signature rules", async () => {
    const dir = await buildLedger();
    const { report } = await reportJson(dir);
    const w = report.whatThisReportDoesNotShow;
    assert.ok(w.includes("signed defer counted by the time it was held"));
    assert.ok(w.includes("first signed allow or deny that follows it in chain order"));
    assert.ok(w.includes("closed without an allow"));
    assert.ok(w.includes("still held when no signed bound answer"));
    assert.ok(w.includes("unmatched when the defer has no usable reference"));
    assert.ok(w.includes("is not a verified operator signature in this report"));
    assert.ok(w.includes("approvals.jsonl is not the source of a count"));
    assert.ok(w.includes("[startMs, endMs)"));
    assert.ok(w.includes("present and not checked"));
    assert.ok(w.includes("default options only"));
    assert.equal(w.includes("when the anchor key was supplied"), false);
    assert.ok(w.includes("run verax verify"));
    assert.ok(w.includes("does not name the ledger directory"));
  });

  it("an argument value in a record does not appear in JSON, HTML or text", async () => {
    const dir = await buildLedger();
    const json = await reportJson(dir);
    const text = await reportText(dir);
    const html = await reportHtml(dir);
    assert.equal(json.text.includes(SECRET_ARG), false);
    assert.equal(text.text.includes(SECRET_ARG), false);
    assert.equal(html.html.includes(SECRET_ARG), false);
  });

  it("unknown option and bad dates exit 64", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-report-usage-"));
    const unknown = capture();
    assert.equal(await runReport([dir, "--from", FROM, "--to", TO, "--wat"], unknown.out), EX_USAGE);
    assert.match(unknown.text(), /unknown option/);

    const bad = capture();
    assert.equal(await runReport([dir, "--from", "2026-13-01", "--to", TO], bad.out), EX_USAGE);
    assert.match(bad.text(), /YYYY-MM-DD/);

    const order = capture();
    assert.equal(await runReport([dir, "--from", TO, "--to", FROM], order.out), EX_USAGE);
    assert.match(order.text(), /must not be after/);
  });

  it("serializePeriodReport is stable under key insertion order and carries the new schema", () => {
    const report: PeriodReport = {
      from: FROM,
      to: TO,
      headHash: "ab",
      recordCount: 0,
      firstRecordMs: null,
      lastRecordMs: null,
      verification: { ok: true, verdict: "VERIFIED (internal consistency only)", problems: [] },
      countsUnavailableReason: null,
      unsignedApprovalsNote: null,
      decisions: {
        total: { allow: 0, deny: 0, defer: 0 },
        byTool: {
          "z.tool": { allow: 1, deny: 0, defer: 0 },
          "a.tool": { allow: 0, deny: 1, defer: 0 },
        },
      },
      approvals: {
        approved: 0,
        withOperatorSignatureFieldPresent: 0,
        withoutOperatorSignatureField: 0,
        closedWithoutAllow: 0,
        stillHeld: 0,
        unmatched: 0,
        terminalsWithoutBoundInputs: 0,
        heldWithoutBoundAnswer: 0,
        heldPossiblyAnsweredByUnbound: 0,
        unavailableReason: null,
      },
      checkpoints: { count: 0, withAnchorVerified: 0, anchorRowsPresentNotChecked: 0, anchorUnavailableReason: null },
      whatThisReportDoesNotShow: "It counts what is in the ledger.",
    };
    const once = serializePeriodReport(report);
    const again = serializePeriodReport(report);
    assert.equal(once, again);
    assert.ok(once.indexOf('"a.tool"') < once.indexOf('"z.tool"'));
    assert.equal(once.includes('"directory"'), false);
    const parsed = JSON.parse(once) as Record<string, unknown>;
    assert.ok("countsUnavailableReason" in parsed);
    assert.ok("unsignedApprovalsNote" in parsed);
    const approvals = parsed.approvals as Record<string, unknown>;
    for (const key of ["withOperatorSignatureFieldPresent", "withoutOperatorSignatureField", "unmatched"]) {
      assert.ok(key in approvals, key);
    }
    assert.equal("withOperatorSignature" in approvals, false);
    const checkpoints = parsed.checkpoints as Record<string, unknown>;
    assert.ok("withAnchorVerified" in checkpoints);
    assert.ok("anchorRowsPresentNotChecked" in checkpoints);
    assert.equal("withAnchor" in checkpoints, false);
    // Reordering the byTool keys must not change the bytes.
    const reordered: PeriodReport = {
      ...report,
      decisions: {
        total: report.decisions.total,
        byTool: {
          "a.tool": { allow: 0, deny: 1, defer: 0 },
          "z.tool": { allow: 1, deny: 0, defer: 0 },
        },
      },
    };
    assert.equal(serializePeriodReport(reordered), once);
  });

  it("tool names __proto__, constructor and toString appear in the per-tool table", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-report-proto-"));
    const signers = loadOrCreateSigners(dir);
    const policy = loadPolicy(POLICY);
    persistPolicySnapshot(dir, policy.hash, POLICY);
    let clock = Date.UTC(2026, 2, 10, 12);
    const names = ["__proto__", "constructor", "toString"] as const;
    let i = 0;
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy,
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now: () => clock,
      nonce: () => `proto-${i++}`,
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const principal = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
    for (const name of names) {
      clock += 1;
      await proxy.call({ name, arguments: { x: 1 } }, principal);
    }
    ledger.close();
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    const byTool = report.decisions.byTool!;
    assert.equal(report.decisions.total!.allow, 3);
    assert.equal(byTool["__proto__"]?.allow, 1);
    assert.equal(byTool["constructor"]?.allow, 1);
    assert.equal(byTool["toString"]?.allow, 1);
    assert.ok(Object.prototype.hasOwnProperty.call(byTool, "__proto__"));
    assert.ok(Object.prototype.hasOwnProperty.call(byTool, "constructor"));
    assert.ok(Object.prototype.hasOwnProperty.call(byTool, "toString"));
  });

  // -------------------------------------------------------------------------
  // Finding 1: approval matching (adversarial). Each case calls
  // countApprovalsFromSigned on really signed, chained records with their
  // inputs rows; the hand-built ledgers also go through runReport.
  // -------------------------------------------------------------------------

  it("1a. an allow written BEFORE the defer does not approve it", async () => {
    const { dir, records } = await handLedger([
      answer("allow", "allow-early", "d1", DAY),
      defer("d1", DAY + 1_000),
    ]);
    const c = approvalCounts(dir, records);
    assert.equal(c.approved, 0, "an allow earlier in the chain is not an answer to a later defer");
    assert.equal(c.stillHeld, 1);
    assert.equal(c.unmatched, 0);
    assert.equal(c.closedWithoutAllow, 0);

    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    assert.equal(report.approvals.approved, 0);
    assert.equal(report.approvals.stillHeld, 1);
  });

  it("1b. an allow for another request hash or another tool does not approve", async () => {
    // Different requestHash.
    const hashCase = await handLedger([
      defer("d1", DAY, { requestHash: REQ_A }),
      answer("allow", "a1", "d1", DAY + 1_000, { requestHash: REQ_B }),
    ]);
    const h = approvalCounts(hashCase.dir, hashCase.records);
    assert.equal(h.approved, 0, "a different requestHash must not approve");
    assert.equal(h.unmatched, 1);
    assert.equal(h.stillHeld, 0);

    // Different subject (tool), same request hash.
    const toolCase = await handLedger([
      defer("d1", DAY, { subject: "memory.put" }),
      answer("allow", "a1", "d1", DAY + 1_000, { subject: "memory.get" }),
    ]);
    const t = approvalCounts(toolCase.dir, toolCase.records);
    assert.equal(t.approved, 0, "a different tool must not approve");
    assert.equal(t.unmatched, 1);

    // The same answers through the full report: not approved there either.
    const hashReport = await reportJson(hashCase.dir);
    assert.equal(hashReport.code, 0, hashReport.text);
    assert.equal(hashReport.report.approvals.approved, 0);
    assert.equal(hashReport.report.approvals.unmatched, 1);
    const toolReport = await reportJson(toolCase.dir);
    assert.equal(toolReport.code, 0, toolReport.text);
    assert.equal(toolReport.report.approvals.approved, 0);
    assert.equal(toolReport.report.approvals.unmatched, 1);
  });

  it("1c. one allow does not approve two defers that share a ref (duplicate ref is unmatched)", async () => {
    const { dir, records } = await handLedger([
      defer("dup", DAY),
      defer("dup", DAY + 500),
      answer("allow", "a1", "dup", DAY + 1_000),
    ]);
    const c = approvalCounts(dir, records);
    assert.equal(c.approved, 0, "one allow cannot approve two defers");
    assert.equal(c.unmatched, 2, "both defers share a ref");
    assert.equal(c.stillHeld, 0);
    assert.equal(sumOf(c), 2);

    const full = await reportJson(dir);
    assert.equal(full.code, 0, full.text);
    assert.equal(full.report.approvals.approved, 0);
    assert.equal(full.report.approvals.unmatched, 2);
  });

  it("1d. allow and deny both present: the FIRST in chain order decides", async () => {
    const denyFirst = await handLedger([
      defer("d1", DAY),
      answer("deny", "deny-1", "d1", DAY + 1_000),
      answer("allow", "allow-1", "d1", DAY + 2_000),
    ]);
    const a = approvalCounts(denyFirst.dir, denyFirst.records);
    assert.equal(a.closedWithoutAllow, 1, "the deny came first");
    assert.equal(a.approved, 0, "a later allow does not override an earlier deny");
    assert.equal(a.stillHeld, 0);
    assert.equal(a.unmatched, 0);

    const allowFirst = await handLedger([
      defer("d1", DAY),
      answer("allow", "allow-1", "d1", DAY + 1_000),
      answer("deny", "deny-1", "d1", DAY + 2_000),
    ]);
    const b = approvalCounts(allowFirst.dir, allowFirst.records);
    assert.equal(b.approved, 1, "the allow came first");
    assert.equal(b.closedWithoutAllow, 0, "a later deny does not override an earlier allow");

    const full = await reportJson(denyFirst.dir);
    assert.equal(full.code, 0, full.text);
    assert.equal(full.report.approvals.closedWithoutAllow, 1);
    assert.equal(full.report.approvals.approved, 0);
  });

  it("1e. another defer does not count as the answer", async () => {
    const { dir, records } = await handLedger([
      defer("d1", DAY),
      // A defer whose inputs claim it resolves d1: only an allow or a deny answers.
      defer("d2", DAY + 1_000, { resolves: "d1" }),
    ]);
    const c = approvalCounts(dir, records);
    assert.equal(c.approved, 0);
    assert.equal(c.closedWithoutAllow, 0);
    assert.equal(c.unmatched, 0);
    assert.equal(c.stillHeld, 2, "neither defer was answered");
    assert.equal(sumOf(c), 2);
  });

  it("1f. a signed defer with ref null is unmatched and is inside the sum", async () => {
    const { dir, records } = await handLedger([
      defer(null, DAY),
      defer("d2", DAY + 1_000),
      answer("allow", "a2", "d2", DAY + 2_000),
    ]);
    const c = approvalCounts(dir, records);
    assert.equal(c.unmatched, 1, "a defer without a ref cannot be matched");
    assert.equal(c.approved, 1);
    assert.equal(c.stillHeld, 0);
    assert.equal(c.closedWithoutAllow, 0);
    assert.equal(sumOf(c), deferCount(records));
    assert.equal(sumOf(c), 2);
  });

  it("1g. approved + closedWithoutAllow + stillHeld + unmatched equals the defers in the window", async () => {
    const specs: Spec[] = [
      defer("d-approved", DAY),
      answer("allow", "a-ok", "d-approved", DAY + 100),
      defer("d-closed", DAY + 200),
      answer("deny", "a-deny", "d-closed", DAY + 300),
      defer("d-held", DAY + 400),
      defer("d-bad-hash", DAY + 500, { requestHash: REQ_A }),
      answer("allow", "a-bad", "d-bad-hash", DAY + 600, { requestHash: REQ_B }),
      defer("shared", DAY + 700),
      defer("shared", DAY + 800),
      defer(null, DAY + 900),
      // Outside the window: neither counted as a defer nor in any bucket.
      defer("d-before", FROM_MS - 1_000),
      defer("d-after", TO_EXCLUSIVE),
    ];
    const { dir, records } = await handLedger(specs);
    const c = approvalCounts(dir, records);
    assert.deepEqual(
      {
        approved: c.approved,
        closed: c.closedWithoutAllow,
        held: c.heldWithoutBoundAnswer,
        stillHeld: c.stillHeld,
        unmatched: c.unmatched,
      },
      { approved: 1, closed: 1, held: 1, stillHeld: 1, unmatched: 4 },
    );
    assert.equal(sumOf(c), deferCount(records));
    assert.equal(deferCount(records), 7);
  });

  it("1g. through runReport on a verified ledger the sum equals the defer total", async () => {
    const { dir } = await handLedger([
      defer("d-approved", DAY),
      answer("allow", "a-ok", "d-approved", DAY + 100),
      defer("d-closed", DAY + 200),
      answer("deny", "a-deny", "d-closed", DAY + 300),
      defer("d-held", DAY + 400),
      defer("d-bad-hash", DAY + 500, { requestHash: REQ_A }),
      answer("allow", "a-bad", "d-bad-hash", DAY + 600, { requestHash: REQ_B }),
    ]);
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    const a = report.approvals;
    assert.deepEqual(
      [a.approved, a.closedWithoutAllow, a.stillHeld, a.heldWithoutBoundAnswer, a.unmatched],
      [1, 1, 1, 1, 1],
    );
    assert.equal(
      a.approved! + a.closedWithoutAllow! + a.heldWithoutBoundAnswer! + a.unmatched!,
      report.decisions.total!.defer,
    );
    assert.equal(report.decisions.total!.defer, 4);
  });

  it("an approving record's signature field is counted as present, never as verified", async () => {
    const { dir, records } = await handLedger([
      defer("d1", DAY),
      answer("allow", "a1", "d1", DAY + 100, { signature: { alg: "fake", sig: "00" } }),
      defer("d2", DAY + 200),
      answer("allow", "a2", "d2", DAY + 300),
    ]);
    const c = approvalCounts(dir, records);
    assert.equal(c.approved, 2);
    assert.equal(c.withOperatorSignatureFieldPresent, 1);
    assert.equal(c.withoutOperatorSignatureField, 1);
  });

  it("a fabricated approvals.jsonl row is not counted; a signed allow answers a held defer", async () => {
    const dir = await buildLedger();
    const base = (await reportJson(dir)).report;
    const approvalsPath = join(dir, "approvals.jsonl");
    const fabricated = {
      ref: "fabricated-hold",
      subject: "memory.put",
      brain: "brain-1",
      requestHash: "ab".repeat(32),
      args: { id: "x" },
      expiresAtMs: Date.UTC(2026, 2, 28),
      createdAtMs: Date.UTC(2026, 2, 16, 12),
      status: "approved",
      allowRef: "no-such-allow",
    };
    writeFileSync(approvalsPath, `${readFileSync(approvalsPath, "utf8")}${JSON.stringify(fabricated)}\n`, "utf8");
    const after = await reportJson(dir);
    assert.equal(after.code, 0, after.text);
    assert.deepEqual(after.report.approvals, base.approvals);
    assert.equal(after.report.approvals.approved, 1);
    assert.equal(after.report.approvals.stillHeld, 1);
  });

  it("a signed allow with approvals.jsonl still pending counts as approved", async () => {
    const dir = await buildLedger();
    const approvalsPath = join(dir, "approvals.jsonl");
    const lines = readFileSync(approvalsPath, "utf8")
      .split("\n")
      .filter((line) => line !== "");
    const rewritten = lines.map((line) => {
      const row = JSON.parse(line) as { ref?: string; status?: string; allowRef?: string };
      if (row.ref === "defer-approved") {
        return JSON.stringify({ ...row, status: "pending", allowRef: undefined });
      }
      return line;
    });
    writeFileSync(approvalsPath, `${rewritten.join("\n")}\n`, "utf8");
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    assert.equal(report.approvals.approved, 1);
    assert.equal(report.approvals.withoutOperatorSignatureField, 1);
    assert.equal(report.approvals.stillHeld, 1);
  });

  it("an expired hold is closed without an allow; the four classes sum to signed defers", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-report-expired-"));
    const signers = loadOrCreateSigners(dir);
    const shortTtl = { ...POLICY, approvalTtlMs: 1_000 };
    const policy = loadPolicy(shortTtl);
    persistPolicySnapshot(dir, policy.hash, shortTtl);
    let clock = Date.UTC(2026, 2, 10, 12);
    const now = () => clock;
    let n = 0;
    const nonce = () => `n-${n++}`;
    const ledger = new FileLedger(dir);
    const proxy = createProxy({
      policy,
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ledger,
      now,
      nonce,
      inner: async () => ({ content: [{ type: "text", text: "ok" }], isError: false }),
    });
    const principal = { brain: "brain-1", scopes: new Set(["verax:memory"]) };
    const put = (id: string, ref: string) =>
      proxy.call(
        {
          name: "memory.put",
          arguments: { id, body: "y", source: { kind: "t" }, validUntilMs: 9_999, _ref: ref },
        },
        principal,
      );

    clock = Date.UTC(2026, 2, 10, 12);
    await put("ok", "defer-ok");
    clock = Date.UTC(2026, 2, 10, 12) + 500;
    const approved = await approvePending({
      ledger,
      recordSigner: signers.recordSigner,
      now,
      nonce: () => "allow-ok",
      ref: "defer-ok",
      approverId: "test-operator",
      via: "cli-script",
      policyHash: policy.hash,
      approvals: approvalsLogFor(ledger),
      inputsLog: proxy.inputsLog,
    });
    assert.equal(approved.ok, true, "approve of live hold");
    clock = Date.UTC(2026, 2, 10, 12) + 600;
    await put("ok", "defer-ok");

    clock = Date.UTC(2026, 2, 11, 12);
    await put("exp", "defer-expired");
    clock = Date.UTC(2026, 2, 11, 12) + 1_001;
    const expired = await approvePending({
      ledger,
      recordSigner: signers.recordSigner,
      now,
      nonce: () => "expire-1",
      ref: "defer-expired",
      approverId: "test-operator",
      via: "cli-script",
      policyHash: policy.hash,
      approvals: approvalsLogFor(ledger),
      inputsLog: proxy.inputsLog,
    });
    assert.equal(expired.ok, false);
    if (expired.ok === false) assert.equal(expired.reason, "expired");

    clock = Date.UTC(2026, 2, 12, 12);
    await put("open", "defer-open");
    ledger.close();

    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    const a = report.approvals;
    assert.equal(a.approved, 1);
    assert.equal(a.closedWithoutAllow, 1);
    assert.equal(a.stillHeld, 1);
    assert.equal(a.unmatched, 0);
    assert.equal(report.decisions.total!.defer, 3);
    assert.equal(
      a.approved! + a.closedWithoutAllow! + a.heldWithoutBoundAnswer! + a.unmatched!,
      report.decisions.total!.defer,
    );

    const textOut = await reportText(dir);
    assert.match(textOut.text, /closed without an allow 1/);
    assert.match(textOut.text, /still held 1/);
    assert.match(textOut.text, /unmatched 0/);

    const { html } = await reportHtml(dir);
    assert.match(html, /Closed without an allow: 1/);
    assert.match(html, /Still held: 1/);
    assert.match(html, /Unmatched: 0/);
  });

  // -------------------------------------------------------------------------
  // Finding 2: malformed approvals.jsonl is an unsigned candidate file.
  // -------------------------------------------------------------------------

  it("2. a malformed approvals.jsonl leaves the ledger VERIFIED, sets a note, and changes no count", async () => {
    const dir = await buildLedger();
    const base = await reportJson(dir);
    assert.equal(base.code, 0, base.text);
    assert.equal(base.report.unsignedApprovalsNote, null);

    writeFileSync(join(dir, "approvals.jsonl"), "{not-json\n", "utf8");
    const after = await reportJson(dir);
    assert.equal(after.code, 0, "exit 0: the verdict does not move");
    assert.equal(after.report.verification.ok, true);
    assert.equal(/NOT VERIFIED/.test(after.report.verification.verdict), false);
    assert.deepEqual(after.report.verification.problems, []);
    assert.equal(typeof after.report.unsignedApprovalsNote, "string");
    assert.notEqual(after.report.unsignedApprovalsNote, "");
    assert.deepEqual(after.report.approvals, base.report.approvals);
    assert.deepEqual(after.report.decisions, base.report.decisions);
    assert.equal(after.report.recordCount, base.report.recordCount);
    assert.equal(after.report.countsUnavailableReason, null);

    const text = await reportText(dir);
    assert.equal(text.code, 0);
    assert.equal(/NOT VERIFIED/.test(text.text.split("\n")[0]!), false);
    assert.ok(text.text.includes("unsigned candidate file"));
    const { html } = await reportHtml(dir);
    assert.ok(html.includes("unsigned candidate file"));
  });

  // -------------------------------------------------------------------------
  // Finding 3: tampered or broken signature, never a count of unverified rows.
  // -------------------------------------------------------------------------

  it("3. a tampered ledger: NOT VERIFIED at the top, exit non-zero, no count of unverified material", async () => {
    const dir = await buildLedger();
    const path = join(dir, "decisions.jsonl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[2]!) as { claims: Record<string, unknown> };
    rec.claims.subject = "tampered-tool";
    lines[2] = JSON.stringify(rec);
    writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
    const text = await reportText(dir);
    assert.notEqual(text.code, 0);
    assert.match(text.text.split("\n")[0]!, /NOT VERIFIED/);
  });

  it("3. a broken signature gives null counts in JSON and 'not available' in HTML and text", async () => {
    const dir = await buildLedger();
    const path = join(dir, "decisions.jsonl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[2]!) as { coseHex: string };
    const last = rec.coseHex.slice(-1);
    rec.coseHex = `${rec.coseHex.slice(0, -1)}${last === "0" ? "1" : "0"}`;
    lines[2] = JSON.stringify(rec);
    writeFileSync(path, `${lines.join("\n")}\n`, "utf8");

    const { code, report, text } = await reportJson(dir);
    assert.equal(code, EX_VERIFY_FAILED, text);
    assert.equal(report.verification.ok, false);
    assert.equal(report.recordCount, null);
    assert.equal(report.firstRecordMs, null);
    assert.equal(report.lastRecordMs, null);
    assert.equal(report.headHash, null);
    assert.equal(report.decisions.total, null);
    assert.equal(report.decisions.byTool, null);
    for (const key of [
      "approved",
      "withOperatorSignatureFieldPresent",
      "withoutOperatorSignatureField",
      "closedWithoutAllow",
      "stillHeld",
      "unmatched",
    ] as const) {
      assert.equal(report.approvals[key], null, key);
    }
    assert.equal(report.checkpoints.count, null);
    assert.equal(report.checkpoints.withAnchorVerified, null);
    assert.equal(report.checkpoints.anchorRowsPresentNotChecked, null);
    assert.equal(typeof report.countsUnavailableReason, "string");
    assert.ok(report.verification.problems.length > 0);

    const textOut = await reportText(dir);
    assert.equal(textOut.code, EX_VERIFY_FAILED);
    assert.match(textOut.text, /Counts not available/);
    assert.match(textOut.text, /records\s+not available/);
    assert.match(textOut.text, /decisions\s+not available/);
    assert.match(textOut.text, /checkpoints\s+not available in window/);
    assert.equal(/decisions\s+allow \d/.test(textOut.text), false);

    const { html } = await reportHtml(dir);
    assert.match(html, /Counts not available/);
    assert.match(html, /Records in window: not available/);
    assert.match(html, /Total: not available/);
    assert.match(html, /Approved held calls: not available/);
    assert.match(html, /Checkpoints in the window: not available/);
    assert.equal(/Total: allow \d/.test(html), false);
    assert.equal(/Records in window: \d/.test(html), false);
  });

  it("3. a symbolic link in place of decisions.jsonl is refused and counts stay null", async (t) => {
    const dir = await buildLedger();
    const real = join(outDir(), "decisions-real.jsonl");
    copyFileSync(join(dir, "decisions.jsonl"), real);
    unlinkSync(join(dir, "decisions.jsonl"));
    try {
      symlinkSync(real, join(dir, "decisions.jsonl"), "file");
    } catch (err) {
      t.skip(`symlink not permitted on this platform: ${(err as NodeJS.ErrnoException).code}`);
      return;
    }
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, EX_VERIFY_FAILED, text);
    assert.equal(report.verification.ok, false);
    assert.equal(report.decisions.total, null);
    assert.equal(report.recordCount, null);
  });

  // -------------------------------------------------------------------------
  // Finding 4: no anchor key
  // -------------------------------------------------------------------------

  it("4. without an anchor key: withAnchorVerified is 0 and present-not-checked names the rows", async () => {
    const none = await buildLedger();
    const noAnchors = (await reportJson(none)).report;
    assert.equal(noAnchors.checkpoints.withAnchorVerified, 0);
    assert.equal(noAnchors.checkpoints.anchorRowsPresentNotChecked, 0);

    const dir = await buildLedger();
    const cpLine = readFileSync(join(dir, "checkpoints.jsonl"), "utf8").trim();
    const cp = JSON.parse(cpLine) as SignedCheckpoint;
    const hash = checkpointHash(cp);
    const row = (checkpointHashHex: string) => ({
      v: 1,
      checkpointHash: checkpointHashHex,
      service: "test-log",
      route: "register",
      entryHash: sha("entry"),
      leafIndex: 0,
      treeSize: 1,
      receiptB64: "AAAA",
      atMs: FROM_MS,
    });
    writeFileSync(
      join(dir, "checkpoint-anchors.jsonl"),
      `${JSON.stringify(row(hash))}\n${JSON.stringify(row(hash))}\n${JSON.stringify(row(sha("not-a-window-checkpoint")))}\n`,
      "utf8",
    );
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, 0, text);
    assert.equal(report.checkpoints.count, 1);
    assert.equal(report.checkpoints.withAnchorVerified, 0, "no key: nothing is verified");
    assert.equal(report.checkpoints.anchorRowsPresentNotChecked, 2, "two rows name the window checkpoint");
    assert.equal(report.checkpoints.anchorUnavailableReason, null);

    const { html } = await reportHtml(dir);
    assert.match(html, /Anchor receipts verified: 0/);
    assert.match(html, /not checked \(no anchor key\): 2/);
  });

  // -------------------------------------------------------------------------
  // Finding 5: checkpointInWindow
  // -------------------------------------------------------------------------

  it("5. checkpointInWindow: zero-length, each edge, and reversed claims", () => {
    const cp = (startMs: unknown, endMs: unknown): SignedCheckpoint =>
      ({ claims: { startMs, endMs } }) as unknown as SignedCheckpoint;
    const inWin = (s: unknown, e: unknown): boolean => checkpointInWindow(cp(s, e), FROM_MS, TO_EXCLUSIVE);

    // Zero-length inside the window covers nothing.
    assert.equal(inWin(FROM_MS + 5_000, FROM_MS + 5_000), false);
    // Zero-length at each edge.
    assert.equal(inWin(FROM_MS, FROM_MS), false);
    assert.equal(inWin(TO_EXCLUSIVE, TO_EXCLUSIVE), false);
    assert.equal(inWin(TO_EXCLUSIVE - 1, TO_EXCLUSIVE - 1), false);
    // Reversed (start after end), even with both inside the window.
    assert.equal(inWin(FROM_MS + 10_000, FROM_MS + 5_000), false);
    assert.equal(inWin(TO_EXCLUSIVE + 10, FROM_MS - 10), false);

    // Lower edge: coverage [a, FROM_MS) ends where the window begins; [a, FROM_MS + 1) reaches one ms in.
    assert.equal(inWin(FROM_MS - 10, FROM_MS), false);
    assert.equal(inWin(FROM_MS - 10, FROM_MS + 1), true);
    // Starting exactly at from is inside.
    assert.equal(inWin(FROM_MS, FROM_MS + 1), true);
    // Upper edge: [TO_EXCLUSIVE - 1, x) is in; [TO_EXCLUSIVE, x) is out.
    assert.equal(inWin(TO_EXCLUSIVE - 1, TO_EXCLUSIVE + 10), true);
    assert.equal(inWin(TO_EXCLUSIVE - 10, TO_EXCLUSIVE), true);
    assert.equal(inWin(TO_EXCLUSIVE, TO_EXCLUSIVE + 10), false);
    // Fully before, fully after, and enclosing.
    assert.equal(inWin(FROM_MS - 100, FROM_MS - 50), false);
    assert.equal(inWin(TO_EXCLUSIVE + 50, TO_EXCLUSIVE + 100), false);
    assert.equal(inWin(FROM_MS - 100, TO_EXCLUSIVE + 100), true);
    // Not numbers.
    assert.equal(inWin("0", FROM_MS + 5), false);
    assert.equal(inWin(FROM_MS, undefined), false);
  });

  // -------------------------------------------------------------------------
  // Finding 6: display-unsafe tool names; one canonical byte sequence
  // -------------------------------------------------------------------------

  it("6. bidi, combining-mark and control characters in a tool name: the digest is of the printed --json bytes", async () => {
    const names = ["tool\u202Egnp.exe", "caf\u0065\u0301", "bell\u0007ring"];
    const { dir } = await handLedger(
      names.map((subject, i) => ({
        decision: "allow" as const,
        ref: `weird-${i}`,
        ts: DAY + i,
        subject,
      })),
    );
    const json = await reportJson(dir);
    assert.equal(json.code, 0, json.text);
    // The printed bytes carry none of the raw characters.
    assert.equal(/[\u202E\u0301\u0007]/.test(json.text), false, "raw display-unsafe characters in --json");
    assert.ok(json.text.includes("\\u202e"), "bidi override is escaped in the printed JSON");
    assert.ok(json.text.includes("\\u0301"), "combining mark is escaped in the printed JSON");
    assert.ok(json.text.includes("\\u0007"), "control character is escaped in the printed JSON");

    const printedDigest = createHash("sha256").update(json.text, "utf8").digest("hex");
    assert.equal(reportDigest(json.text), printedDigest);

    // HTML: the digest shown is the digest of exactly those printed bytes.
    const { code, html, stdout } = await reportHtml(dir);
    assert.equal(code, 0);
    assert.ok(html.includes(`<code>${printedDigest}</code>`), "HTML digest equals SHA-256 of --json bytes");
    assert.ok(stdout.includes(`digest ${printedDigest}`), "the digest line on stdout matches");
    // Text mode prints the same digest.
    const text = await reportText(dir);
    assert.ok(text.text.includes(printedDigest));
    // No raw characters in any rendering.
    assert.equal(/[\u202E\u0301\u0007]/.test(html), false);
    assert.equal(/[\u202E\u0301\u0007]/.test(text.text), false);
  });

  // -------------------------------------------------------------------------
  // Finding 7 and the corrupt-manifest case, separately
  // -------------------------------------------------------------------------

  it("7. unreadable anchors file: NOT VERIFIED and checkpoints.count is null (not 0)", async () => {
    const dir = await buildLedger();
    mkdirSync(join(dir, "checkpoint-anchors.jsonl"));
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, EX_VERIFY_FAILED, text);
    assert.equal(report.verification.ok, false);
    assert.match(report.verification.verdict, /NOT VERIFIED/);
    // The class is whatever verify names; it must exist and must not carry the path or the OS error text.
    assert.ok(report.verification.problems.length > 0);
    for (const p of report.verification.problems) {
      assert.equal(p.includes(dir), false, p);
      assert.equal(/EISDIR/i.test(p), false, p);
    }
    assert.equal(report.checkpoints.count, null);
    assert.notEqual(report.checkpoints.count, 0);
    assert.equal(report.checkpoints.withAnchorVerified, null);
    assert.equal(report.checkpoints.anchorRowsPresentNotChecked, null);
    assert.equal(report.decisions.total, null);
  });

  it("a corrupt ledger manifest: NOT VERIFIED, exit verify-failed, every count null", async () => {
    const dir = await buildLedger();
    writeFileSync(join(dir, "ledger-manifest.json"), "{not-json\n", "utf8");
    const { code, report, text } = await reportJson(dir);
    assert.equal(code, EX_VERIFY_FAILED, text);
    assert.equal(report.verification.ok, false);
    assert.ok(report.verification.problems.includes("ledger-manifest-corrupt"), JSON.stringify(report.verification.problems));
    assert.equal(report.recordCount, null);
    assert.equal(report.checkpoints.count, null);
    assert.equal(report.approvals.approved, null);
  });

  // -------------------------------------------------------------------------
  // Finding 8: inaccessible or empty state dir
  // -------------------------------------------------------------------------

  it("8. a state directory that does not exist still yields a report: NOT VERIFIED, null counts, no path", async () => {
    const missing = join(mkdtempSync(join(tmpdir(), "verax-report-missing-")), "does-not-exist");
    const json = await reportJson(missing);
    assert.equal(json.code, EX_VERIFY_FAILED, json.text);
    assert.equal(json.report.verification.ok, false);
    assert.equal(json.report.recordCount, null);
    assert.equal(json.report.decisions.total, null);
    assert.equal(json.report.checkpoints.count, null);
    assert.equal(json.text.includes(missing), false);
    assert.equal(json.text.includes(missing.replaceAll("\\", "\\\\")), false);
    const text = await reportText(missing);
    assert.equal(text.code, EX_VERIFY_FAILED);
    assert.equal(text.text.includes(missing), false);
    assert.match(text.text.split("\n")[0]!, /NOT VERIFIED/);
  });

  it(
    "8. an unreadable state directory: state-unreadable, same exit as verify, no path in output",
    {
      skip:
        process.platform === "win32"
          ? "directory ACLs are not reproducible with chmod on win32; the missing-directory case above covers the null-count path"
          : typeof process.getuid === "function" && process.getuid() === 0
            ? "root reads a mode-000 directory"
            : false,
    },
    async () => {
      const dir = await buildLedger();
      chmodSync(dir, 0o000);
      try {
        const verifyCode = await runCli(["verify", dir], {
          elevated: () => false,
          stdout: { write: () => {} },
          stderr: { write: () => {} },
        });
        const json = await reportJson(dir);
        assert.equal(json.code, verifyCode, json.text);
        assert.deepEqual(json.report.verification.problems, ["state-unreadable"]);
        assert.equal(json.report.recordCount, null);
        assert.equal(json.report.checkpoints.count, null);
        assert.equal(json.text.includes(dir), false);
        const text = await reportText(dir);
        assert.equal(text.code, verifyCode);
        assert.equal(text.text.includes(dir), false);
      } finally {
        chmodSync(dir, 0o700);
      }
    },
  );

  // -------------------------------------------------------------------------
  // Finding 9: --out inside the state directory
  // -------------------------------------------------------------------------

  it("9. --out inside the state directory exits 64 before anything is overwritten", async () => {
    const dir = await buildLedger();
    const checkpointsPath = join(dir, "checkpoints.jsonl");
    const decisionsPath = join(dir, "decisions.jsonl");
    const checkpointsBefore = readFileSync(checkpointsPath, "utf8");
    const decisionsBefore = readFileSync(decisionsPath, "utf8");
    const listing = readdirSync(dir).sort();

    for (const target of [
      join(dir, "report.html"),
      checkpointsPath,
      decisionsPath,
      join(dir, "sub", "nested.html"),
      join(dir, "..", basename(dir), "dotdot.html"),
    ]) {
      const c = capture();
      const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", target], c.out);
      assert.equal(code, EX_USAGE, `${target}: ${c.text()}`);
      assert.match(c.text(), /state directory/, target);
      assert.doesNotMatch(c.text(), /refusing to overwrite/, "must stop before the exclusive create");
      assert.equal(c.text().includes(dir), false, "the message must not carry the state path");
    }
    assert.equal(readFileSync(checkpointsPath, "utf8"), checkpointsBefore);
    assert.equal(readFileSync(decisionsPath, "utf8"), decisionsBefore);
    assert.deepEqual(readdirSync(dir).sort(), listing, "nothing was created in the state directory");
    assert.equal(existsSync(join(dir, "report.html")), false);
  });

  // -------------------------------------------------------------------------
  // Findings 10, 11, 13: exclusive write
  // -------------------------------------------------------------------------

  it("10. an existing --out file outside the state directory is refused, untouched, with no temp left", async () => {
    const dir = await buildLedger();
    const out = outDir();
    const target = join(out, "exists.html");
    writeFileSync(target, "already here\n", "utf8");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", target], c.out);
    assert.equal(code, EX_USAGE);
    assert.match(c.text(), /refusing to overwrite/);
    assert.equal(readFileSync(target, "utf8"), "already here\n", "content unchanged");
    assert.deepEqual(readdirSync(out), ["exists.html"], "no temp file left behind");
  });

  it("10. the temp name is not predictable: planted temp-like files are untouched and the write still succeeds", async () => {
    const dir = await buildLedger();
    const out = outDir();
    const target = join(out, "period.html");
    // A pid- or name-derived temp (the old scheme) would collide with one of these under exclusive create.
    const planted = [
      `.verax-report-${process.pid}.tmp`,
      `period.html.${process.pid}.tmp`,
      "period.html.tmp",
      ".period.html.tmp",
      `.period.html.${process.pid}`,
      `.verax-report-${process.pid}-1.tmp`,
    ];
    for (const name of planted) writeFileSync(join(out, name), `planted ${name}\n`, "utf8");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", target], c.out);
    assert.equal(code, 0, c.text());
    for (const name of planted) {
      assert.equal(readFileSync(join(out, name), "utf8"), `planted ${name}\n`, name);
    }
    assert.deepEqual(readdirSync(out).sort(), [...planted, "period.html"].sort(), "temp file removed after the link");
    assert.ok(readFileSync(target, "utf8").startsWith("<!DOCTYPE html>"));
    // Two runs leave no temp, whatever the random name was.
    const target2 = join(out, "period2.html");
    assert.equal(await runReport([dir, "--from", FROM, "--to", TO, "--out", target2], capture().out), 0);
    assert.deepEqual(
      readdirSync(out)
        .filter((n) => !planted.includes(n))
        .sort(),
      ["period.html", "period2.html"],
    );
  });

  it("10. a failure in the final step (target is a directory) is refused with no temp left", async () => {
    // The target name is taken by a directory: the hard link to the final name fails with EEXIST after the
    // temp was written. A kill at that step leaves a complete file at the final name, or nothing there,
    // never a half-written final file: the content is written to the temp first and linked in whole.
    const dir = await buildLedger();
    const out = outDir();
    mkdirSync(join(out, "taken.html"));
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", join(out, "taken.html")], c.out);
    assert.equal(code, EX_USAGE);
    assert.match(c.text(), /refusing to overwrite/);
    assert.deepEqual(readdirSync(out), ["taken.html"]);
  });

  it("10. a missing --out parent directory is a clean usage error with no stack and no path", async () => {
    const dir = await buildLedger();
    const out = outDir();
    const target = join(out, "no-such-dir", "x.html");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", target], c.out);
    assert.equal(code, EX_USAGE);
    assert.match(c.text(), /could not write x\.html/);
    assert.equal(c.text().includes(out), false);
    assert.equal(hasStackFrames(c.text()), false);
  });

  it("10. a dangling symbolic link at the target is refused, not followed", async (t) => {
    const dir = await buildLedger();
    const out = outDir();
    const elsewhere = join(out, "elsewhere.html");
    const target = join(out, "link.html");
    try {
      symlinkSync(elsewhere, target, "file");
    } catch (err) {
      t.skip(`symlink not permitted on this platform: ${(err as NodeJS.ErrnoException).code}`);
      return;
    }
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", target], c.out);
    assert.equal(code, EX_USAGE, c.text());
    assert.equal(existsSync(elsewhere), false, "the link target was not created through the link");
  });

  it("11. the success lines and the overwrite error print the basename only", async () => {
    const dir = await buildLedger();
    const out = outDir();
    const target = join(out, "named-report.html");
    const first = capture();
    assert.equal(await runReport([dir, "--from", FROM, "--to", TO, "--out", target], first.out), 0);
    assert.match(first.text(), /^wrote named-report\.html$/m);
    assert.match(first.text(), /^digest [0-9a-f]{64}$/m);
    assert.equal(first.text().includes(out), false);
    assert.equal(first.text().includes(tmpdir()), false);

    const second = capture();
    assert.equal(await runReport([dir, "--from", FROM, "--to", TO, "--out", target], second.out), EX_USAGE);
    assert.match(second.text(), /refusing to overwrite named-report\.html/);
    assert.equal(second.text().includes(out), false);
    assert.equal(second.text().includes(tmpdir()), false);
  });

  // -------------------------------------------------------------------------
  // Finding 12: HTML wording and escaping
  // -------------------------------------------------------------------------

  it("12. HTML escapes bidi in tool names, names the window rule, and never calls a signature field verified", async () => {
    const { dir } = await handLedger([
      { decision: "allow", ref: "bidi-1", ts: DAY, subject: "pay\u202Eexe.txt" },
      defer("d1", DAY + 10),
      answer("allow", "a1", "d1", DAY + 20),
    ]);
    const { code, html } = await reportHtml(dir);
    assert.equal(code, 0);
    assert.equal(html.includes("\u202E"), false, "no raw bidi override in HTML");
    assert.ok(html.includes("pay\\u202eexe.txt"), "terminalText runs before htmlEscape: visible escape");
    assert.ok(html.includes("The to day is included in full"));
    assert.ok(html.includes("half-open"));
    assert.ok(html.includes("up to, not including, 00:00:00 UTC on the day after the to day"));
    assert.ok(html.includes("signature field present is not a verified signature here"));
    assert.equal(/with (a )?verified (operator )?signature/i.test(html), false);
    assert.equal(/verified operator signature(?! in this report)/i.test(html), false);

    const text = await reportText(dir);
    assert.ok(text.text.includes("The to day is included in full"));
    assert.ok(text.text.includes("signature field present"));
    assert.equal(/with (a )?verified (operator )?signature/i.test(text.text), false);
  });

  // -------------------------------------------------------------------------
  // Finding 13: the stack-trace test goes through the real dispatcher
  // -------------------------------------------------------------------------

  it("13. broken ledgers through `verax report` print no stack and nothing on stderr", async () => {
    async function assertFailedThroughDispatcher(dir: string, expectedClass: string): Promise<void> {
      const errParts: string[] = [];
      const onUncaught = (err: Error): void => {
        errParts.push(err.stack ?? err.message);
      };
      process.on("uncaughtException", onUncaught);
      let result: { code: number; stdout: string; stderr: string };
      try {
        result = await throughDispatcher([dir, "--from", FROM, "--to", TO]);
      } finally {
        process.off("uncaughtException", onUncaught);
      }
      assert.equal(errParts.length, 0, errParts.join("\n"));
      assert.equal(result.code, EX_VERIFY_FAILED, result.stdout + result.stderr);
      assert.equal(result.stderr, "", "nothing on stderr");
      assert.match(result.stdout.split("\n")[0]!, /NOT VERIFIED/);
      assert.match(result.stdout, new RegExp(expectedClass));
      assert.equal(hasStackFrames(result.stdout), false, result.stdout);
      assert.equal(hasStackFrames(result.stderr), false, result.stderr);
      assert.equal(result.stdout.includes(dir), false, "no state path in the dispatcher output");
    }

    const corrupt = await buildLedger();
    writeFileSync(join(corrupt, "ledger-manifest.json"), "{not-json\n", "utf8");
    await assertFailedThroughDispatcher(corrupt, "ledger-manifest-corrupt");

    const badAnchors = await buildLedger();
    mkdirSync(join(badAnchors, "checkpoint-anchors.jsonl"));
    await assertFailedThroughDispatcher(badAnchors, "problems\\s+\\d+ class");

    const tampered = await buildLedger();
    const path = join(tampered, "decisions.jsonl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[2]!) as { claims: Record<string, unknown> };
    rec.claims.subject = "tampered-tool";
    lines[2] = JSON.stringify(rec);
    writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
    const result = await throughDispatcher([tampered, "--from", FROM, "--to", TO]);
    assert.equal(result.code, EX_VERIFY_FAILED);
    assert.equal(result.stderr, "");
    assert.equal(hasStackFrames(result.stdout), false);
  });

  it("13. the dispatcher exits 64 for --out inside the state directory and for bad usage, without a stack", async () => {
    const dir = await buildLedger();
    const inside = await throughDispatcher([dir, "--from", FROM, "--to", TO, "--out", join(dir, "report.html")]);
    assert.equal(inside.code, EX_USAGE);
    assert.match(inside.stdout, /state directory/);
    assert.equal(inside.stderr, "");
    assert.equal(hasStackFrames(inside.stdout), false);

    const bad = await throughDispatcher([dir, "--from", "nope", "--to", TO]);
    assert.equal(bad.code, EX_USAGE);
    assert.equal(hasStackFrames(bad.stdout + bad.stderr), false);

    const ok = await throughDispatcher([dir, "--from", FROM, "--to", TO, "--json"]);
    assert.equal(ok.code, 0, ok.stdout + ok.stderr);
    assert.equal(ok.stderr, "");
    assert.equal(JSON.parse(ok.stdout).verification.ok, true);
  });

  // -------------------------------------------------------------------------
  // Round f: verdict parity with verax verify (shared completeVerify)
  // -------------------------------------------------------------------------

  async function verifyThroughDispatcher(dir: string): Promise<{ code: number; stdout: string; stderr: string }> {
    let stdout = "";
    let stderr = "";
    const code = await runCli(["verify", dir], {
      elevated: () => false,
      stdout: { write: (s: string) => (stdout += s) },
      stderr: { write: (s: string) => (stderr += s) },
    });
    return { code, stdout, stderr };
  }

  async function assertReportMatchesVerify(dir: string): Promise<void> {
    const verify = await verifyThroughDispatcher(dir);
    const report = await throughDispatcher([dir, "--from", FROM, "--to", TO, "--json"]);
    const body = JSON.parse(report.stdout) as PeriodReport;
    const verifyLines = verify.stdout.split("\n").filter((l) => l !== "");
    const verifyVerdict = verifyLines[verifyLines.length - 1] ?? "";
    assert.equal(body.verification.ok, verify.code === 0, `ok vs exit for ${dir}`);
    assert.equal(body.verification.verdict, verifyVerdict, `verdict for ${dir}`);
    assert.equal(report.code === 0, verify.code === 0, `exit codes for ${dir}`);
  }

  it("f1. report verification.ok and verdict match verax verify through the dispatcher", async () => {
    const clean = await buildLedger();
    await assertReportMatchesVerify(clean);

    const brokenSig = await buildLedger();
    {
      const path = join(brokenSig, "decisions.jsonl");
      const lines = readFileSync(path, "utf8").trim().split("\n");
      const rec = JSON.parse(lines[2]!) as { claims: Record<string, unknown> };
      rec.claims.subject = "tampered-tool";
      lines[2] = JSON.stringify(rec);
      writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
    }
    await assertReportMatchesVerify(brokenSig);

    const brokenChain = await buildLedger();
    {
      const path = join(brokenChain, "decisions.jsonl");
      const lines = readFileSync(path, "utf8").trim().split("\n");
      const rec = JSON.parse(lines[1]!) as { claims: Record<string, unknown> };
      rec.claims.prevRecordHash = "ab".repeat(32);
      lines[1] = JSON.stringify(rec);
      writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
    }
    await assertReportMatchesVerify(brokenChain);

    const removedWithIndex = await buildLedger();
    {
      const path = join(removedWithIndex, "decisions.jsonl");
      const lines = readFileSync(path, "utf8").trim().split("\n");
      const kept = lines.slice(0, -1);
      const dropped = JSON.parse(lines[lines.length - 1]!) as { claims: { ref?: string } };
      writeFileSync(path, `${kept.join("\n")}\n`, "utf8");
      const refs = kept
        .map((line) => (JSON.parse(line) as { claims: { ref?: string } }).claims.ref)
        .filter((r): r is string => typeof r === "string");
      if (typeof dropped.claims.ref === "string") refs.push(dropped.claims.ref);
      writeFileSync(
        join(removedWithIndex, "index.jsonl"),
        refs.map((ref) => JSON.stringify({ ref })).join("\n") + "\n",
        "utf8",
      );
    }
    await assertReportMatchesVerify(removedWithIndex);

    const badCheckpoint = await buildLedger();
    {
      const path = join(badCheckpoint, "checkpoints.jsonl");
      const row = JSON.parse(readFileSync(path, "utf8").trim()) as { signature: string };
      row.signature = "00".repeat(64);
      writeFileSync(path, `${JSON.stringify(row)}\n`, "utf8");
    }
    await assertReportMatchesVerify(badCheckpoint);

    const startProblem = await buildLedger();
    writeFileSync(join(startProblem, "starts.jsonl"), "not-json\n", "utf8");
    await assertReportMatchesVerify(startProblem);

    const missing = join(mkdtempSync(join(tmpdir(), "verax-report-parity-miss-")), "gone");
    await assertReportMatchesVerify(missing);

    // A signed control record whose bound inputs carry a signature that does
    // not verify: both commands read decisions + bound inputs, not halt-history.
    const badControl = await buildLedger();
    {
      const signers = loadOrCreateSigners(badControl);
      const controlInputs = {
        control: {
          action: "halt",
          via: "http",
          by: "operator-1",
          line: 0,
          lineHash: "ab".repeat(32),
          signature: {
            credentialId: "forged-cred",
            sub: "operator-1",
            authenticatorData: "aa",
            clientDataJSON: "bb",
            signature: "cc",
            rpId: "localhost",
            prev: null,
          },
        },
      };
      const inputsHash = sha(canonical(controlInputs));
      appendFileSync(
        join(badControl, "inputs.jsonl"),
        `${JSON.stringify({ ref: "halt-forged", inputs: controlInputs })}\n`,
        "utf8",
      );
      const ledger = new FileLedger(badControl);
      try {
        await ledger.appendDecisionChained((prev) =>
          signDecisionRecord(
            {
              decider: "verax-operator",
              subject: "verax.halt",
              requestHash: sha("halt-req"),
              policyHash: sha("policy"),
              inputsHash,
              decision: "allow",
              reasonCode: "halted",
              ref: "halt-forged",
              effectHash: sha("halt-effect"),
              effectClass: "verax.control",
              // Newest enough to sit inside the in-flight effect allowance so
              // verifyLedger stays ok; completeVerify still fails the signature.
              timestampMs: Date.now(),
              nonce: "halt-forged",
              prevRecordHash: prev,
            } as never,
            signers.recordSigner.privateKeyPem,
            signers.recordSigner.publicKeyPem,
          ),
        );
      } finally {
        ledger.close();
      }
    }
    {
      const verify = await verifyThroughDispatcher(badControl);
      const report = await throughDispatcher([badControl, "--from", FROM, "--to", TO, "--json"]);
      const body = JSON.parse(report.stdout) as PeriodReport;
      const verifyLines = verify.stdout.split("\n").filter((l) => l !== "");
      const verifyVerdict = verifyLines[verifyLines.length - 1] ?? "";
      assert.notEqual(verify.code, 0);
      assert.equal(report.code === 0, false);
      assert.equal(body.verification.verdict, verifyVerdict);
      assert.match(verifyVerdict, /NOT VERIFIED/);
      assert.ok(
        body.verification.problems.includes("control signatures"),
        JSON.stringify(body.verification.problems),
      );
    }

    // Forged halt-history.jsonl alone is not read by offline control-signature
    // verification: both commands stay VERIFIED.
    const historyNoiseOnly = await buildLedger();
    writeFileSync(
      join(historyNoiseOnly, "halt-history.jsonl"),
      `${JSON.stringify({
        action: "halt",
        atMs: Date.UTC(2026, 2, 10),
        by: "test",
        reason: "test",
        signature: { alg: "ed25519", publicKey: "aa", sig: "bb" },
      })}\n`,
      "utf8",
    );
    await assertReportMatchesVerify(historyNoiseOnly);
    {
      const verify = await verifyThroughDispatcher(historyNoiseOnly);
      assert.equal(verify.code, 0, "forged halt-history alone must not fail verify");
    }
  });

  // -------------------------------------------------------------------------
  // Round f: inputsHash binds approver.resolves to the signed record
  // -------------------------------------------------------------------------

  it("f2. a mismatched inputs row that names a defer does not approve it", async () => {
    const { dir, records } = await handLedger([
      defer("d1", DAY),
      // Matching inputs for the allow have no resolves.
      { decision: "allow", ref: "a1", ts: DAY + 100 },
    ]);
    const deferRec = records.find((r) => r.claims.decision === "defer")!;
    const allow = records.find((r) => r.claims.decision === "allow")!;
    const allowRef = allow.claims.ref as string;
    const deferInputs = {
      principal: { brain: "brain-1", scopes: [] as string[] },
      inputs: [] as unknown[],
      n: 0,
    };
    const matchingInputs = {
      principal: { brain: "brain-1", scopes: [] as string[] },
      inputs: [] as unknown[],
      n: 1,
    };
    assert.equal(sha(canonical(deferInputs)), deferRec.claims.inputsHash);
    assert.equal(sha(canonical(matchingInputs)), allow.claims.inputsHash);

    const wrongInputs = {
      principal: { brain: "brain-1", scopes: [] as string[] },
      inputs: [] as unknown[],
      n: 1,
      planted: true,
      approver: { id: "test-operator", via: "cli-script", resolves: "d1" },
    };
    assert.notEqual(sha(canonical(wrongInputs)), allow.claims.inputsHash);

    const inputsPath = join(dir, "inputs.jsonl");
    const writeAllowOrder = (first: unknown, second: unknown): void => {
      writeFileSync(
        inputsPath,
        [
          JSON.stringify({ ref: deferRec.claims.ref, inputs: deferInputs }),
          JSON.stringify({ ref: allowRef, inputs: first }),
          JSON.stringify({ ref: allowRef, inputs: second }),
        ].join("\n") + "\n",
        "utf8",
      );
    };

    // Wrong row first: without the hash check the defer would be approved.
    writeAllowOrder(wrongInputs, matchingInputs);
    const wrongFirst = approvalCounts(dir, records);
    assert.equal(wrongFirst.approved, 0, "wrong-hash resolves must not approve");
    assert.equal(wrongFirst.stillHeld, 1);

    writeAllowOrder(matchingInputs, wrongInputs);
    const matchFirst = approvalCounts(dir, records);
    assert.equal(matchFirst.approved, 0);
    assert.equal(matchFirst.stillHeld, 1);

    const full = await reportJson(dir);
    assert.equal(full.code, 0, full.text);
    assert.equal(full.report.approvals.stillHeld, 1);
    assert.equal(full.report.approvals.approved, 0);

    // Missing or mismatched inputs alone: verifyLedger fails and ok is false,
    // so the report never presents stillHeld as a fact about those records.
    const onlyWrong = await handLedger([
      defer("d2", DAY),
      { decision: "allow", ref: "a2", ts: DAY + 100 },
    ]);
    const onlyAllow = onlyWrong.records.find((r) => r.claims.decision === "allow")!;
    writeFileSync(
      join(onlyWrong.dir, "inputs.jsonl"),
      `${JSON.stringify({
        ref: onlyAllow.claims.ref,
        inputs: { planted: true, approver: { resolves: "d2" } },
      })}\n`,
      "utf8",
    );
    const mismatched = await verifyLedger(onlyWrong.dir);
    assert.equal(mismatched.ok, false);
    assert.ok(mismatched.problems.some((p) => /inputs row/.test(p)));

    const noInputs = await handLedger([defer("d3", DAY), { decision: "allow", ref: "a3", ts: DAY + 100 }]);
    unlinkSync(join(noInputs.dir, "inputs.jsonl"));
    const missingInputs = await verifyLedger(noInputs.dir);
    assert.equal(missingInputs.ok, false);
    assert.ok(missingInputs.problems.some((p) => /inputs row missing/.test(p)));
  });

  // -------------------------------------------------------------------------
  // Round f: unreadable state directory on every platform
  // -------------------------------------------------------------------------

  it("f3. an unreadable state directory: state-unreadable, null counts, no path", async (t) => {
    let dir: string;
    let restore: (() => void) | null = null;
    if (process.platform === "win32") {
      // Parent-as-file is "missing" (ENOTDIR) here. SAM is EPERM → unreadable.
      dir = "C:\\Windows\\System32\\config\\SAM";
      if (directoryAccess(dir) !== "unreadable") {
        t.skip(`expected ${dir} to be unreadable, got ${directoryAccess(dir)}`);
        return;
      }
    } else if (typeof process.getuid === "function" && process.getuid() === 0) {
      t.skip("root reads a mode-000 directory");
      return;
    } else {
      dir = await buildLedger();
      chmodSync(dir, 0o000);
      restore = () => chmodSync(dir, 0o700);
    }
    try {
      let verifyCode = -1;
      {
        const code = await runCli(["verify", dir], {
          elevated: () => false,
          stdout: { write: () => {} },
          stderr: { write: () => {} },
        });
        verifyCode = code;
      }
      const json = await reportJson(dir);
      assert.equal(json.code, verifyCode, `report ${json.code} vs verify ${verifyCode}`);
      assert.deepEqual(json.report.verification.problems, ["state-unreadable"]);
      assert.equal(json.report.verification.ok, false);
      assert.equal(json.report.recordCount, null);
      assert.equal(json.report.decisions.total, null);
      assert.equal(json.report.checkpoints.count, null);
      assert.equal(json.text.includes(dir), false);
      assert.equal(json.text.includes("System32"), false);

      const text = await reportText(dir);
      assert.equal(text.code, verifyCode);
      assert.equal(text.text.includes(dir), false);
      assert.match(text.text.split("\n")[0]!, /NOT VERIFIED/);

      const via = await throughDispatcher([dir, "--from", FROM, "--to", TO, "--json"]);
      assert.equal(via.code, verifyCode);
      assert.equal(via.stderr, "");
      assert.equal(via.stdout.includes(dir), false);
      assert.deepEqual(JSON.parse(via.stdout).verification.problems, ["state-unreadable"]);
    } finally {
      restore?.();
    }
  });

  // -------------------------------------------------------------------------
  // Round f: exclusive temp create (wx)
  // -------------------------------------------------------------------------

  it("f4. a file already at the injectable temp name is not truncated and the write refuses", async () => {
    const dir = await buildLedger();
    const out = outDir();
    const target = join(out, "period.html");
    const tempPath = join(out, ".verax-report-planted.tmp");
    writeFileSync(tempPath, "planted-temp-content\n", "utf8");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", target], c.out, {
      writeTempPath: tempPath,
    });
    assert.equal(code, EX_USAGE, c.text());
    assert.match(c.text(), /refusing to overwrite period\.html/);
    assert.equal(readFileSync(tempPath, "utf8"), "planted-temp-content\n");
    assert.equal(existsSync(target), false);

    // Direct call: wx must throw EEXIST without changing the planted bytes.
    assert.throws(
      () => writeOutExclusive(join(out, "other.html"), "<html></html>\n", tempPath),
      (err: NodeJS.ErrnoException) => err.code === "EEXIST",
    );
    assert.equal(readFileSync(tempPath, "utf8"), "planted-temp-content\n");
  });

  it("f4. a symlink at the injectable temp name is not followed or truncated", async (t) => {
    const dir = await buildLedger();
    const out = outDir();
    const target = join(out, "period.html");
    const real = join(out, "real-target.txt");
    const tempPath = join(out, ".verax-report-link.tmp");
    writeFileSync(real, "symlink-target-bytes\n", "utf8");
    try {
      symlinkSync(real, tempPath, "file");
    } catch (err) {
      t.skip(`symlink not permitted on this platform: ${(err as NodeJS.ErrnoException).code}`);
      return;
    }
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", target], c.out, {
      writeTempPath: tempPath,
    });
    assert.equal(code, EX_USAGE, c.text());
    assert.match(c.text(), /refusing to overwrite/);
    assert.equal(readFileSync(real, "utf8"), "symlink-target-bytes\n");
  });
});