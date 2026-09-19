import { strict as assert } from "node:assert";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLedger } from "../src/verify-ledger.ts";

/**
 * What this product sells is evidence. Evidence a customer can only read
 * while they are still paying for the reader is a weak kind: the honest
 * question is "if we stopped using Verax tomorrow, would the file still mean
 * anything?"
 *
 * `verifyLedger` answers that over a directory, with no body running and no
 * network. It states three separate things, because they fail separately:
 * every signature, the chain between records, and whether each effect is
 * bound to a decision.
 *
 * The fourth thing it states is the one that matters most and is easiest to
 * fudge: WHICH KEY verified the signatures. A ledger checked against the key
 * sitting next to it is internally consistent and nothing more — anything
 * that could write the file could also write that key. Saying "valid" without
 * saying "against its own key" would be the same self-confirmation the
 * downstream audit found (a stdio child runs as the same user and can read
 * `keys/*.pem`). So the trust source is part of the answer, not a footnote.
 */

const golden = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "ledger-golden",
);

function altinDefteriKopyala(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-verify-"));
  for (const ad of ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]) {
    copyFileSync(join(golden, ad), join(dir, ad));
  }
  return dir;
}

describe("verifyLedger — kanıt Verax olmadan okunur", () => {
  it("sağlam bir defter: her imza geçerli, zincir kopuk değil, etkiler bağlı", async () => {
    const sonuc = await verifyLedger(altinDefteriKopyala());
    assert.equal(sonuc.ok, true, JSON.stringify(sonuc.problems));
    assert.ok(sonuc.decisions > 0, "karar okunamadı");
    assert.equal(sonuc.signaturesInvalid, 0);
    assert.equal(sonuc.chainBreakAt, null);
    assert.deepEqual(sonuc.problems, []);
  });

  it("KİMİN anahtarıyla doğrulandığını söyler — kendi anahtarı bir uyarıdır", async () => {
    const sonuc = await verifyLedger(altinDefteriKopyala());
    // Doğrulama defterin yanındaki anahtarla yapıldıysa bu kendi kendini
    // onaylamadır; cevap bunu saklamaz.
    assert.equal(sonuc.trust.source, "in-ledger");
    assert.match(sonuc.trust.note, /internally consistent|kendi/i);
  });

  it("kurcalanmış bir karar imzayı düşürür ve ok=false yapar", async () => {
    const dir = altinDefteriKopyala();
    const yol = join(dir, "decisions.jsonl");
    const satirlar = readFileSync(yol, "utf8").trim().split("\n");
    const ilk = JSON.parse(satirlar[0]!) as { claims: Record<string, unknown> };
    ilk.claims.subject = "memory.put"; // imza bunu kapsıyor
    satirlar[0] = JSON.stringify(ilk);
    writeFileSync(yol, `${satirlar.join("\n")}\n`, "utf8");

    const sonuc = await verifyLedger(dir);
    assert.equal(sonuc.ok, false);
    assert.ok(sonuc.signaturesInvalid >= 1, "kurcalama imzayı düşürmedi");
    assert.ok(
      sonuc.problems.some((p) => /signature/i.test(p)),
      JSON.stringify(sonuc.problems),
    );
  });

  it("silinen bir satır zinciri kırar ve nerede kırıldığını söyler", async () => {
    const dir = altinDefteriKopyala();
    const yol = join(dir, "decisions.jsonl");
    const satirlar = readFileSync(yol, "utf8").trim().split("\n");
    assert.ok(satirlar.length >= 3, "altın defter bu test için kısa");
    satirlar.splice(1, 1); // ortadan bir karar sil
    writeFileSync(yol, `${satirlar.join("\n")}\n`, "utf8");

    const sonuc = await verifyLedger(dir);
    assert.equal(sonuc.ok, false);
    assert.notEqual(sonuc.chainBreakAt, null, "zincir kopukluğu görülmedi");
    assert.ok(
      sonuc.problems.some((p) => /chain/i.test(p)),
      JSON.stringify(sonuc.problems),
    );
  });

  it("dışarıdan verilen anahtar kullanılır ve kaynağı 'pinned' olur", async () => {
    const dir = altinDefteriKopyala();
    const kendi = await verifyLedger(dir);
    const pem = kendi.trust.publicKeyPem;
    assert.ok(pem && pem.includes("BEGIN PUBLIC KEY"), "defterden anahtar okunamadı");

    const sonuc = await verifyLedger(dir, { publicKeyPem: pem });
    assert.equal(sonuc.trust.source, "pinned");
    assert.equal(sonuc.ok, true, JSON.stringify(sonuc.problems));
    // Elde tutulan bir anahtarla doğrulama artık kendi kendini onaylama değil.
    assert.doesNotMatch(sonuc.trust.note, /internally consistent only/i);
  });

  it("yabancı bir anahtarla hiçbir imza geçmez", async () => {
    const dir = altinDefteriKopyala();
    const { generateKeyPairSync } = await import("node:crypto");
    const { publicKey } = generateKeyPairSync("ed25519");
    const yabanci = publicKey.export({ type: "spki", format: "pem" }).toString();

    const sonuc = await verifyLedger(dir, { publicKeyPem: yabanci });
    assert.equal(sonuc.ok, false);
    assert.equal(sonuc.signaturesValid, 0, "yabancı anahtarla imza geçti");
  });

  it("boş ya da olmayan dizin sessizce 'geçerli' demez", async () => {
    const bos = mkdtempSync(join(tmpdir(), "verax-verify-bos-"));
    const sonuc = await verifyLedger(bos);
    assert.equal(sonuc.ok, false, "boş dizin geçerli sayıldı");
    assert.equal(sonuc.decisions, 0);
    assert.ok(
      sonuc.problems.some((p) => /no decisions|not found|okunamadı/i.test(p)),
      JSON.stringify(sonuc.problems),
    );
  });
});
