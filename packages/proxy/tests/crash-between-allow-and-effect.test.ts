import { strict as assert } from "node:assert";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { approvePending } from "../src/approvals.ts";
import { FileLedger } from "../src/ledger.ts";
import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { EFFECT_SIGNER, RECORD_SIGNER } from "./helpers.ts";

/**
 * STATUS names this as an open risk and says it is unproven: "Survive a crash
 * between the allow and the effect: a retry after that gap can run a second
 * time." The in-flight registry that stops a second run lives in a Map, so a
 * restarted body has an empty one — the allow is on disk, the effect is not,
 * and nothing left says a run was ever started.
 *
 * The approved path is the one that matters. On it an `allow` does not mean
 * "the tool ran"; it means "the operator said yes", so the run that follows is
 * the first one. That is why it cannot simply answer `outcome-unknown` the way
 * the un-approved path does — it would mean nothing an operator approves ever
 * runs. The body has to record that it started, not only that it was allowed.
 */

const writer = { brain: "brain-1", scopes: new Set(["verax:memory"]) };

const APPROVE_POLICY = {
  version: 1,
  default: "deny",
  approvalTtlMs: 86_400_000,
  rules: [
    {
      id: "send-approve",
      tool: "message.send",
      requires: ["verax:memory"],
      mode: "approve",
      text: "Sending needs operator approval.",
    },
  ],
} as const;

type Kurulum = {
  stateDir: string;
  calls: string[];
  /** Her `inner` çağrısı bu kuyruğa bir çözücü bırakır. */
  bekleyen: (() => void)[];
};

function proxyKur(k: Kurulum, opts: { asili?: boolean } = {}) {
  const ledger = new FileLedger(k.stateDir);
  let n = 0;
  const proxy = createProxy({
    policy: loadPolicy(APPROVE_POLICY),
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: () => Date.now(),
    nonce: () => `n-${Date.now()}-${++n}`,
    inner: async (call) => {
      k.calls.push(String(call.arguments.to ?? ""));
      if (opts.asili === true) {
        // Çökmeyi taklit eder: iş başladı, hiç bitmedi, etki yazılmadı.
        await new Promise<void>(resolve => k.bekleyen.push(resolve));
      }
      return { content: [{ type: "text", text: "gonderildi" }], isError: false }
    },
  });
  return { proxy, ledger };
}

const CAGRI = { name: "message.send", arguments: { to: "biri@ornek.com", body: "tek kez", _ref: "r-1" } };

async function deferVeOnayla(k: Kurulum): Promise<void> {
  const { proxy, ledger } = proxyKur(k);
  const ilk = await proxy.call(CAGRI, writer);
  assert.match(ilk.content.map(c => c.text).join(""), /^deferred:approval-required:/);
  const defer = (await ledger.decisions()).find(d => d.claims.decision === "defer");
  assert.ok(defer, "defer kaydı yazılmadı");
  const onay = await approvePending({
    ledger,
    recordSigner: RECORD_SIGNER,
    now: () => Date.now(),
    nonce: () => `n-approve-${Date.now()}`,
    ref: defer.claims.ref!,
    approverId: "op-1",
    via: "cli",
    policyHash: defer.claims.policyHash,
    approvals: proxy.approvals,
    inputsLog: proxy.inputsLog,
  });
  assert.equal(onay.ok, true, `onay reddedildi: ${JSON.stringify(onay)}`);
  ledger.close();
}

describe("allow ile etki arasındaki çökme", () => {
  it("onay sonrası ilk retry aracı ÇALIŞTIRIR (normal akış bozulmaz)", async () => {
    const k: Kurulum = { stateDir: mkdtempSync(join(tmpdir(), "verax-crash-a-")), calls: [], bekleyen: [] };
    await deferVeOnayla(k);
    const { proxy, ledger } = proxyKur(k);
    const sonuc = await proxy.call(CAGRI, writer);
    assert.equal(sonuc.isError, false, sonuc.content.map(c => c.text).join(""));
    assert.equal(k.calls.length, 1, "onaylanan iş hiç koşmadı");
    ledger.close();
  });

  it("koşu başlamış ama etki yazılmamışken yeniden başlayan gövde aracı İKİNCİ KEZ ÇALIŞTIRMAZ", async () => {
    const k: Kurulum = { stateDir: mkdtempSync(join(tmpdir(), "verax-crash-b-")), calls: [], bekleyen: [] };
    await deferVeOnayla(k);

    // Gövde 1: onaylı işi başlatır, etkiyi yazamadan ölür.
    const govde1 = proxyKur(k, { asili: true });
    void govde1.proxy.call(CAGRI, writer);
    for (let i = 0; i < 200 && k.calls.length === 0; i += 1) {
      await new Promise(r => setTimeout(r, 5));
    }
    assert.equal(k.calls.length, 1, "ilk gövde işi hiç başlatmadı");
    govde1.ledger.close(); // süreç öldü: bellekteki in-flight kaydı gitti

    // Gövde 2: yeni süreç, boş bellek, aynı defter.
    const govde2 = proxyKur(k);
    const sonuc = await govde2.proxy.call(CAGRI, writer);
    const metin = sonuc.content.map(c => c.text).join("");

    assert.equal(k.calls.length, 1, `araç ikinci kez koştu: ${JSON.stringify(k.calls)}`);
    assert.equal(sonuc.isError, true, metin);
    assert.match(metin, /^denied:outcome-unknown:/, metin);

    const kararlar = await govde2.ledger.decisions();
    assert.ok(
      kararlar.some(d => d.claims.reasonCode === "outcome-unknown"),
      "bilinmeyen sonuç deftere yazılmadı",
    );
    govde2.ledger.close();
    // Asılı iş bilerek çözülmez: o gövde "öldü". Çözmek, kapanmış deftere
    // yazmaya kalkar ve testten sonra `ledger-lost-lock` üretir.
  });

  it("iş bitince işaret silinir — biriken dosya bırakmaz", async () => {
    const k: Kurulum = { stateDir: mkdtempSync(join(tmpdir(), "verax-crash-c-")), calls: [], bekleyen: [] };
    await deferVeOnayla(k);
    const { proxy, ledger } = proxyKur(k);
    await proxy.call(CAGRI, writer);
    const klasor = join(k.stateDir, "in-flight");
    const kalan = existsSync(klasor) ? readdirSync(klasor) : [];
    assert.deepEqual(kalan, [], `bitmiş işin işareti duruyor: ${JSON.stringify(kalan)}`);
    ledger.close();
  });

  it("araç hata fırlatsa bile ikinci kez koşmaz — etki :threw olarak yazıldı", async () => {
    const k: Kurulum = { stateDir: mkdtempSync(join(tmpdir(), "verax-crash-d-")), calls: [], bekleyen: [] };
    await deferVeOnayla(k);

    const ledger1 = new FileLedger(k.stateDir);
    let n = 0;
    const patlayan = createProxy({
      policy: loadPolicy(APPROVE_POLICY),
      recordSigner: RECORD_SIGNER,
      effectSigner: EFFECT_SIGNER,
      ledger: ledger1,
      now: () => Date.now(),
      nonce: () => `n-t-${Date.now()}-${++n}`,
      inner: async (call) => {
        k.calls.push(String(call.arguments.to ?? ""));
        throw new Error("alici reddetti");
      },
    });
    await assert.rejects(() => patlayan.call(CAGRI, writer));
    assert.equal(k.calls.length, 1);
    ledger1.close();

    // Yeniden başlayan gövde: etki satırı (:threw) defterde, iş tekrarlanmamalı.
    const govde2 = proxyKur(k);
    await govde2.proxy.call(CAGRI, writer).catch(() => undefined);
    assert.equal(k.calls.length, 1, `hata fırlatan araç ikinci kez koştu: ${JSON.stringify(k.calls)}`);
    govde2.ledger.close();
  });
});
