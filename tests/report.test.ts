import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";

import {
  buildCheckpointClaims,
  signCheckpoint,
  totalsFromDecisionRecords,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { approvePending, approvalsLogFor, createProxy, FileLedger, loadPolicy } from "@verax-ai/proxy";

import { loadOrCreateSigners } from "../packages/body/src/keys.ts";
import { persistPolicySnapshot } from "../packages/body/src/policy-store.ts";
import {
  parseReportDate,
  reportDigest,
  runReport,
  serializePeriodReport,
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
  await proxy.call(
    { name: "memory.get", arguments: { id: "denied" } },
    { brain: "brain-1", scopes: new Set() },
  );
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

describe("verax report", () => {
  it("parseReportDate accepts calendar dates and refuses bad ones", () => {
    assert.equal(parseReportDate("2026-03-01"), Date.UTC(2026, 2, 1));
    assert.equal(parseReportDate("2026-02-30"), null);
    assert.equal(parseReportDate("2026-3-1"), null);
    assert.equal(parseReportDate("not-a-date"), null);
  });

  it("counts match the records in the window, per tool and in total", async () => {
    const dir = await buildLedger();
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--json"], c.out);
    assert.equal(code, 0, c.text());
    const report = JSON.parse(c.text()) as {
      decisions: {
        total: { allow: number; deny: number; defer: number };
        byTool: Record<string, { allow: number; deny: number; defer: number }>;
      };
      approvals: {
        approved: number;
        withOperatorSignature: number;
        withoutOperatorSignature: number;
        stillHeld: number;
      };
      checkpoints: { count: number; withAnchor: number };
      recordCount: number;
    };
    // in window: at-from allow, allow-1 allow, deny-1 deny, defer-approved defer,
    // allow-approved allow, escape-tool allow, img-tool allow, amp-tool allow, still-held defer.
    assert.equal(report.decisions.total.allow, 6);
    assert.equal(report.decisions.total.deny, 1);
    assert.equal(report.decisions.total.defer, 2);
    assert.equal(report.decisions.byTool["memory.get"]?.allow, 2);
    assert.equal(report.decisions.byTool["memory.get"]?.deny, 1);
    assert.equal(report.decisions.byTool["memory.put"]?.defer, 2);
    assert.equal(report.decisions.byTool["memory.put"]?.allow, 1);
    assert.equal(report.decisions.byTool[ESCAPED_TOOL]?.allow, 1);
    assert.equal(report.decisions.byTool[IMG_TOOL]?.allow, 1);
    assert.equal(report.decisions.byTool[AMP_TOOL]?.allow, 1);
    assert.equal(report.approvals.approved, 1);
    assert.equal(report.approvals.withoutOperatorSignature, 1);
    assert.equal(report.approvals.withOperatorSignature, 0);
    assert.equal(report.approvals.stillHeld, 1);
    assert.equal(report.checkpoints.count, 1);
    assert.equal(report.checkpoints.withAnchor, 0);
    assert.equal(report.recordCount, 9);
  });

  it("excludes one millisecond before from and the instant at to+1 day; includes from midnight", async () => {
    const dir = await buildLedger();
    const c = capture();
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], c.out);
    const report = JSON.parse(c.text()) as { firstRecordMs: number; lastRecordMs: number; recordCount: number };
    assert.equal(report.firstRecordMs, FROM_MS);
    assert.ok(report.lastRecordMs < TO_EXCLUSIVE);
    assert.ok(report.lastRecordMs >= FROM_MS);
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
    const a = capture();
    const b = capture();
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], a.out);
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], b.out);
    assert.equal(a.text(), b.text());
    const digest = reportDigest(a.text());
    const outPath = join(dir, "period.html");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", outPath], c.out);
    assert.equal(code, 0, c.text());
    const html = readFileSync(outPath, "utf8");
    assert.match(html, new RegExp(digest));
    assert.equal(createHash("sha256").update(a.text(), "utf8").digest("hex"), digest);
  });

  it("escapes a tool name with <script> and quotes in HTML and keeps it intact in JSON", async () => {
    const dir = await buildLedger();
    const jsonCap = capture();
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], jsonCap.out);
    const report = JSON.parse(jsonCap.text()) as { decisions: { byTool: Record<string, unknown> } };
    assert.ok(Object.prototype.hasOwnProperty.call(report.decisions.byTool, ESCAPED_TOOL));
    assert.ok(Object.prototype.hasOwnProperty.call(report.decisions.byTool, IMG_TOOL));
    assert.ok(Object.prototype.hasOwnProperty.call(report.decisions.byTool, AMP_TOOL));
    const outPath = join(dir, "escape.html");
    await runReport([dir, "--from", FROM, "--to", TO, "--out", outPath], capture().out);
    const html = readFileSync(outPath, "utf8");
    assert.equal(/<script/i.test(html), false);
    assert.equal(html.includes("<img"), false);
    assert.ok(html.includes(ESCAPED_TOOL_HTML));
    assert.ok(html.includes(IMG_TOOL_HTML));
    assert.ok(html.includes(AMP_TOOL_HTML));
  });

  it("names the hold-time and checkpoint-overlap window rules", async () => {
    const dir = await buildLedger();
    const jsonCap = capture();
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], jsonCap.out);
    const report = JSON.parse(jsonCap.text()) as { whatThisReportDoesNotShow: string };
    assert.ok(report.whatThisReportDoesNotShow.includes("signed defer counted by the time it was held"));
    assert.ok(report.whatThisReportDoesNotShow.includes("approvals.jsonl is not the source of a count"));
    assert.ok(report.whatThisReportDoesNotShow.includes("[startMs, endMs)"));
    assert.ok(report.whatThisReportDoesNotShow.includes("run verax verify"));
    assert.ok(report.whatThisReportDoesNotShow.includes("does not name the ledger directory"));
  });

  it("an argument value in a record does not appear in JSON, HTML or text", async () => {
    const dir = await buildLedger();
    const jsonCap = capture();
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], jsonCap.out);
    const textCap = capture();
    await runReport([dir, "--from", FROM, "--to", TO], textCap.out);
    const outPath = join(dir, "no-secret.html");
    await runReport([dir, "--from", FROM, "--to", TO, "--out", outPath], capture().out);
    const html = readFileSync(outPath, "utf8");
    assert.equal(jsonCap.text().includes(SECRET_ARG), false);
    assert.equal(textCap.text().includes(SECRET_ARG), false);
    assert.equal(html.includes(SECRET_ARG), false);
  });

  it("a tampered ledger: the report says it does not verify at the top, and exits non-zero", async () => {
    const dir = await buildLedger();
    const path = join(dir, "decisions.jsonl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[2]!) as { claims: Record<string, unknown> };
    rec.claims.subject = "tampered-tool";
    lines[2] = JSON.stringify(rec);
    writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO], c.out);
    assert.notEqual(code, 0);
    assert.match(c.text().split("\n")[0]!, /NOT VERIFIED/);
  });

  it("refuses to overwrite an existing --out file", async () => {
    const dir = await buildLedger();
    const outPath = join(dir, "exists.html");
    writeFileSync(outPath, "already here\n", "utf8");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", outPath], c.out);
    assert.equal(code, 64);
    assert.match(c.text(), /refusing to overwrite/);
    assert.equal(readFileSync(outPath, "utf8"), "already here\n");
    assert.equal(existsSync(outPath), true);
  });

  it("unknown option and bad dates exit 64", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-report-usage-"));
    const unknown = capture();
    assert.equal(await runReport([dir, "--from", FROM, "--to", TO, "--wat"], unknown.out), 64);
    assert.match(unknown.text(), /unknown option/);

    const bad = capture();
    assert.equal(await runReport([dir, "--from", "2026-13-01", "--to", TO], bad.out), 64);
    assert.match(bad.text(), /YYYY-MM-DD/);

    const order = capture();
    assert.equal(await runReport([dir, "--from", TO, "--to", FROM], order.out), 64);
    assert.match(order.text(), /must not be after/);
  });

  it("serializePeriodReport is stable under key insertion order", () => {
    const report = {
      from: FROM,
      to: TO,
      headHash: "ab",
      recordCount: 0,
      firstRecordMs: null,
      lastRecordMs: null,
      verification: { ok: true, verdict: "VERIFIED (internal consistency only)", problems: [] as string[] },
      decisions: {
        total: { allow: 0, deny: 0, defer: 0 },
        byTool: {
          "z.tool": { allow: 1, deny: 0, defer: 0 },
          "a.tool": { allow: 0, deny: 1, defer: 0 },
        },
      },
      approvals: {
        approved: 0,
        withOperatorSignature: 0,
        withoutOperatorSignature: 0,
        stillHeld: 0,
      },
      checkpoints: { count: 0, withAnchor: 0 },
      whatThisReportDoesNotShow:
        "It counts what is in the ledger. A call that never passed through the gate is not in it. A count is not a judgement that a decision was right.",
    };
    const once = serializePeriodReport(report);
    const again = serializePeriodReport(report);
    assert.equal(once, again);
    assert.ok(once.indexOf('"a.tool"') < once.indexOf('"z.tool"'));
    assert.equal(once.includes('"directory"'), false);
  });

  it("a fabricated approvals.jsonl row is not counted; signed allow answers a held defer", async () => {
    const dir = await buildLedger();
    const before = capture();
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], before.out);
    const base = JSON.parse(before.text()) as {
      approvals: { approved: number; stillHeld: number; withoutOperatorSignature: number };
    };
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
    const after = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--json"], after.out);
    assert.equal(code, 0, after.text());
    const report = JSON.parse(after.text()) as {
      approvals: { approved: number; stillHeld: number; withoutOperatorSignature: number };
    };
    assert.equal(report.approvals.approved, base.approvals.approved);
    assert.equal(report.approvals.stillHeld, base.approvals.stillHeld);
    assert.equal(report.approvals.approved, 1);
    assert.equal(report.approvals.stillHeld, 1);
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
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--json"], c.out);
    assert.equal(code, 0, c.text());
    const report = JSON.parse(c.text()) as {
      approvals: { approved: number; stillHeld: number; withoutOperatorSignature: number };
    };
    assert.equal(report.approvals.approved, 1);
    assert.equal(report.approvals.withoutOperatorSignature, 1);
    assert.equal(report.approvals.stillHeld, 1);
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
    const a = capture();
    const b = capture();
    const c = capture();
    assert.equal(await runReport([dir, "--from", FROM, "--to", TO, "--json"], a.out), 0, a.text());
    assert.equal(await runReport([abs, "--from", FROM, "--to", TO, "--json"], b.out), 0, b.text());
    assert.equal(await runReport([copyDir, "--from", FROM, "--to", TO, "--json"], c.out), 0, c.text());
    assert.equal(a.text(), b.text());
    assert.equal(a.text(), c.text());
    assert.equal(a.text().includes('"directory"'), false);
    assert.equal(a.text().includes(dir.replaceAll("\\", "\\\\")), false);
    const textCap = capture();
    await runReport([dir, "--from", FROM, "--to", TO], textCap.out);
    assert.equal(textCap.text().includes(dir), false);
    const outPath = join(dir, "no-path.html");
    await runReport([dir, "--from", FROM, "--to", TO, "--out", outPath], capture().out);
    assert.equal(readFileSync(outPath, "utf8").includes(dir), false);
  });

  it("verification problems are reported by class only, and the text points to verax verify", async () => {
    const dir = await buildLedger();
    const path = join(dir, "decisions.jsonl");
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const rec = JSON.parse(lines[2]!) as { claims: Record<string, unknown> };
    rec.claims.subject = "tampered-tool";
    lines[2] = JSON.stringify(rec);
    writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
    const jsonCap = capture();
    await runReport([dir, "--from", FROM, "--to", TO, "--json"], jsonCap.out);
    const report = JSON.parse(jsonCap.text()) as { verification: { problems: string[]; ok: boolean } };
    assert.equal(report.verification.ok, false);
    assert.ok(report.verification.problems.length > 0);
    for (const p of report.verification.problems) {
      assert.equal(p.includes(dir), false, p);
      assert.equal(/ref\s/.test(p), false, p);
      assert.equal(p.includes("_ref"), false, p);
    }
    const textCap = capture();
    await runReport([dir, "--from", FROM, "--to", TO], textCap.out);
    assert.match(textCap.text(), /verax verify/);
    for (const p of report.verification.problems) {
      assert.ok(textCap.text().includes(p), p);
    }
  });

  it("a checkpoint whose exclusive end equals from is outside; touching cases match [startMs, endMs)", async () => {
    const dir = await buildLedger();
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const priv = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
    const signWindow = (startMs: number, endMs: number, epoch: number): SignedCheckpoint =>
      signCheckpoint(
        buildCheckpointClaims(epoch, [], startMs, endMs, null, () => ({ allow: "0", deny: "0", defer: "0" }), () => ""),
        priv,
        pub,
      );
    // Coverage ends exactly at from: [from-10, from) does not overlap [from, to+1day).
    // Coverage starts exactly at from: overlaps.
    // Coverage ends exactly at to+1day: overlaps.
    // Coverage starts exactly at to+1day: does not overlap.
    const rows = [
      signWindow(FROM_MS - 10, FROM_MS, 0),
      signWindow(FROM_MS, FROM_MS + 10, 1),
      signWindow(TO_EXCLUSIVE - 10, TO_EXCLUSIVE, 2),
      signWindow(TO_EXCLUSIVE, TO_EXCLUSIVE + 10, 3),
    ];
    writeFileSync(join(dir, "checkpoints.jsonl"), `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`, "utf8");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--json"], c.out);
    assert.equal(code === 0 || code === EX_VERIFY_FAILED, true, c.text());
    const report = JSON.parse(c.text()) as { checkpoints: { count: number } };
    assert.equal(report.checkpoints.count, 2);
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
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--json"], c.out);
    assert.equal(code, 0, c.text());
    const report = JSON.parse(c.text()) as {
      decisions: { total: { allow: number }; byTool: Record<string, { allow: number }> };
    };
    assert.equal(report.decisions.total.allow, 3);
    assert.equal(report.decisions.byTool["__proto__"]?.allow, 1);
    assert.equal(report.decisions.byTool["constructor"]?.allow, 1);
    assert.equal(report.decisions.byTool["toString"]?.allow, 1);
    assert.ok(Object.prototype.hasOwnProperty.call(report.decisions.byTool, "__proto__"));
    assert.ok(Object.prototype.hasOwnProperty.call(report.decisions.byTool, "constructor"));
    assert.ok(Object.prototype.hasOwnProperty.call(report.decisions.byTool, "toString"));
  });

  it("corrupt manifest, malformed approvals, or unreadable anchors still yield NOT VERIFIED and exit verify-failed", async () => {
    async function assertFailedReport(dir: string, expectedClass: string): Promise<void> {
      const c = capture();
      const errParts: string[] = [];
      const prior = process.listeners("uncaughtException");
      const onUncaught = (err: Error): void => {
        errParts.push(err.stack ?? err.message);
      };
      process.on("uncaughtException", onUncaught);
      let code: number;
      try {
        code = await runReport([dir, "--from", FROM, "--to", TO], c.out);
      } finally {
        process.off("uncaughtException", onUncaught);
      }
      assert.equal(errParts.length, 0, errParts.join("\n"));
      assert.equal(code, EX_VERIFY_FAILED, c.text());
      assert.match(c.text().split("\n")[0]!, /NOT VERIFIED/);
      assert.match(c.text(), new RegExp(expectedClass));
      assert.equal(/\bat [\w.]+\s*\(/.test(c.text()), false, c.text());
    }

    const corrupt = await buildLedger();
    writeFileSync(join(corrupt, "ledger-manifest.json"), "{not-json\n", "utf8");
    await assertFailedReport(corrupt, "ledger-manifest-corrupt");

    const badApprovals = await buildLedger();
    writeFileSync(join(badApprovals, "approvals.jsonl"), "{not-json\n", "utf8");
    await assertFailedReport(badApprovals, "approvals-malformed");

    const badAnchors = await buildLedger();
    mkdirSync(join(badAnchors, "checkpoint-anchors.jsonl"));
    await assertFailedReport(badAnchors, "anchors-unreadable");
  });

  it("exclusive --out create refuses a racing existing file and leaves no partial on failure", async () => {
    const dir = await buildLedger();
    const outPath = join(dir, "race.html");
    writeFileSync(outPath, "already here\n", "utf8");
    const c = capture();
    const code = await runReport([dir, "--from", FROM, "--to", TO, "--out", outPath], c.out);
    assert.equal(code, 64);
    assert.match(c.text(), /refusing to overwrite/);
    assert.equal(readFileSync(outPath, "utf8"), "already here\n");
    const leftovers = readdirSync(dir).filter((n) => n.includes(".tmp") || n.startsWith(".verax-report-"));
    assert.deepEqual(leftovers, []);
  });
});
