import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { FileLedger, MemoryLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const SEND_POLICY = {
  version: 1,
  default: "deny",
  egress: ["mail.example"],
  rules: [
    {
      id: "message-send",
      tool: "message.send",
      requires: ["verax:act"],
      text: "Sending a message needs the act scope.",
      egress: true,
    },
    {
      id: "message-read",
      tool: "message.read",
      requires: ["verax:read"],
      text: "Reading the inbox needs the read scope.",
    },
    {
      id: "get-marked",
      tool: "memory.get",
      requires: ["verax:read"],
      text: "A marked tool without a named extractor must fail closed.",
      egress: true,
    },
  ],
} as const;

const sender = { brain: "brain-1", scopes: new Set(["verax:act", "verax:read"]) };

describe("S3 egress allow-list", () => {
  it("egress-blocked: a host not on the list is a signed deny and does not call inner", async () => {
    const ledger = new MemoryLedger();
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy(SEND_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["eg-blocked"]),
      inner: async () => {
        inner += 1;
        return { content: [{ type: "text", text: "sent" }], isError: false };
      },
    });
    const out = await proxy.call(
      { name: "message.send", arguments: { to: "alice@evil.example", text: "hi" } },
      sender,
    );
    assert.match(out.content[0]?.text ?? "", /denied:egress-blocked:eg-blocked/);
    assert.equal(inner, 0);
    const rec = (await ledger.decisions())[0]!;
    assert.equal(rec.claims.decision, "deny");
    assert.equal(rec.claims.reasonCode, "egress-blocked");
    assert.equal(typeof rec.coseHex, "string");
  });

  it("egress-host-missing: a marked tool whose extractor returns no host fails closed", async () => {
    const ledger = new MemoryLedger();
    const proxy = createProxy({
      policy: loadPolicy(SEND_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(),
      nonce: queuedNonce(["eg-missing", "eg-no-extractor"]),
      inner: async () => ({ content: [{ type: "text", text: "no" }], isError: false }),
    });
    const noTo = await proxy.call({ name: "message.send", arguments: { text: "hi", host: "mail.example" } }, sender);
    assert.match(noTo.content[0]?.text ?? "", /denied:egress-host-missing:eg-missing/);
    const noExtractor = await proxy.call({ name: "memory.get", arguments: { id: "n1", url: "https://evil.example" } }, sender);
    assert.match(noExtractor.content[0]?.text ?? "", /denied:egress-host-missing:eg-no-extractor/);
  });

  it("allowed host: message.send writes the outbox and does not open a network", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-outbox-"));
    const ledger = new FileLedger(dir);
    let inner = 0;
    const proxy = createProxy({
      policy: loadPolicy(SEND_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger,
      now: tickingNow(1_000, 10),
      nonce: queuedNonce(["eg-ok"]),
      inner: async (call) => {
        inner += 1;
        const { appendFileSync } = await import("node:fs");
        appendFileSync(
          join(dir, "outbox.jsonl"),
          `${JSON.stringify({ to: call.arguments.to, text: call.arguments.text, ref: "eg-ok" })}\n`,
          { encoding: "utf8" },
        );
        return { content: [{ type: "text", text: "queued" }], isError: false };
      },
    });
    try {
      const out = await proxy.call(
        { name: "message.send", arguments: { to: "alice@mail.example", text: "hi" } },
        sender,
      );
      assert.equal(out.isError, false);
      assert.equal(inner, 1);
      const rec = (await ledger.decisions())[0]!;
      assert.equal(rec.claims.decision, "allow");
      const box = readFileSync(join(dir, "outbox.jsonl"), "utf8");
      assert.match(box, /alice@mail\.example/);
      assert.doesNotMatch(box, /https?:\/\//);
    } finally {
      ledger.close();
    }
  });

  it("message.read is not egress even when args name host or url", async () => {
    const got = loadPolicy(SEND_POLICY).evaluate(
      { name: "message.read", arguments: { host: "evil.example", url: "https://evil.example" } },
      { brain: "brain-1", scopes: new Set(["verax:read"]) },
    );
    assert.deepEqual(got, { decision: "allow", reasonCode: "allow", rule: "message-read" });
  });
});
