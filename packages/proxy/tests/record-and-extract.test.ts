import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  findDecisionRecordChainBreak,
  verifyDecisionRecord,
} from "@cedulon/core";
import { effectExtractShapeRefusal, verifyEffectExtract } from "@cedulon/effect-extract";

import { explain } from "../src/explain.ts";
import { FileLedger, MemoryLedger } from "../src/ledger.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "./helpers.ts";
import { runGoldenScenario } from "./golden-scenario.ts";

describe("signed records and extract", () => {
  it("wrong key fails verify; a deleted row breaks the chain", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-chain-"));
    const ledger = await runGoldenScenario(dir);
    const decisions = await ledger.decisions();
    assert.equal(verifyDecisionRecord(decisions[0], RECORD_SIGNER.publicKeyPem), true);
    assert.equal(verifyDecisionRecord(decisions[0], EFFECT_SIGNER.publicKeyPem), false);
    assert.equal(findDecisionRecordChainBreak(decisions, [RECORD_SIGNER.publicKeyPem]), null);
    const broken = [decisions[0], ...decisions.slice(2)];
    const hit = findDecisionRecordChainBreak(broken, [RECORD_SIGNER.publicKeyPem]);
    assert.ok(hit);
    assert.equal(hit.reason, "broken-link");
  });

  it("exportExtract verifies and has no shape refusal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-extract-"));
    const ledger = await runGoldenScenario(dir);
    const signed = await ledger.exportExtract({ startMs: 10, endMs: 200 }, EFFECT_SIGNER);
    assert.equal(verifyEffectExtract(signed, EFFECT_SIGNER.publicKeyPem), true);
    assert.equal(effectExtractShapeRefusal(signed.body), null);
    assert.equal(signed.body.deciderId, "verax-proxy");
    assert.equal(signed.body.channelId, "verax-body");
  });

  it("explain labels a self witness as conditional", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-explain-"));
    const ledger = await runGoldenScenario(dir);
    const result = await explain(ledger, "n1");
    assert.equal(result.record.claims.ref, "n1");
    assert.equal(result.witnessClass, "self");
    assert.equal(result.finding.label, "conditional");
    assert.ok(result.effect);
  });

  it("duplicate effect is refused and recorded", async () => {
    const ledger = new MemoryLedger();
    await ledger.appendEffect(
      {
        ref: "dup-1",
        effectHash: "a".repeat(64),
        effectClass: "memory.get",
        timestampMs: 10,
        actor: "brain-1",
      },
      "self",
    );
    await assert.rejects(
      () =>
        ledger.appendEffect(
          {
            ref: "dup-1",
            effectHash: "b".repeat(64),
            effectClass: "memory.get",
            timestampMs: 20,
            actor: "brain-1",
          },
          "self",
        ),
      /duplicate-effect:dup-1/,
    );
    const effects = await ledger.effects();
    assert.equal(effects.length, 2);
    assert.equal(effects[1].row.effectClass, "duplicate-effect");
  });

  it("FileLedger states the Windows permission gap", () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-perm-"));
    const ledger = new FileLedger(dir);
    if (process.platform === "win32") {
      assert.equal(ledger.permissionCheck, "not checked on this platform");
    } else {
      assert.equal(ledger.permissionCheck, "owner-only");
    }
  });
});
