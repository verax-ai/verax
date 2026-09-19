import { strict as assert } from "node:assert";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { runVerify } from "../packages/body/src/verify-cli.ts";

/**
 * The exit code is the part a pipeline reads, so it is measured here rather
 * than inferred from the text: 0 when the ledger verifies, 1 when it does
 * not, and 1 for a directory that holds no ledger at all — a missing ledger
 * must never be quiet success.
 */

const golden = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "packages",
  "proxy",
  "tests",
  "fixtures",
  "ledger-golden",
);

function kopyala(): string {
  const dir = mkdtempSync(join(tmpdir(), "verax-verify-cli-"));
  for (const ad of ["decisions.jsonl", "effects.jsonl", "inputs.jsonl"]) {
    copyFileSync(join(golden, ad), join(dir, ad));
  }
  return dir;
}

function yakala(): { out: (s: string) => void; metin: () => string } {
  const parcalar: string[] = [];
  return { out: (s) => parcalar.push(s), metin: () => parcalar.join("\n") };
}

describe("verax verify", () => {
  it("sağlam defter: 0 döner ve VERIFIED yazar", async () => {
    const y = yakala();
    const kod = await runVerify([kopyala()], y.out);
    assert.equal(kod, 0, y.metin());
    assert.match(y.metin(), /VERIFIED/);
    assert.doesNotMatch(y.metin(), /NOT VERIFIED/);
  });

  it("hangi anahtarla doğrulandığını HER ZAMAN yazar", async () => {
    const y = yakala();
    await runVerify([kopyala()], y.out);
    // Bu satır bayrakla açılıp kapanmaz: kendi anahtarıyla doğrulama,
    // "dosyalar birbiriyle tutarlı" demektir, "bu anahtara güvenilir" değil.
    assert.match(y.metin(), /verified with/i);
    assert.match(y.metin(), /internally consistent/i);
  });

  it("kurcalanmış defter: 1 döner, NOT VERIFIED yazar, sorunu adlandırır", async () => {
    const dir = kopyala();
    const yol = join(dir, "decisions.jsonl");
    const satirlar = readFileSync(yol, "utf8").trim().split("\n");
    const rec = JSON.parse(satirlar[2]!) as { claims: Record<string, unknown> };
    rec.claims.subject = "spend";
    satirlar[2] = JSON.stringify(rec);
    writeFileSync(yol, `${satirlar.join("\n")}\n`, "utf8");

    const y = yakala();
    const kod = await runVerify([dir], y.out);
    assert.equal(kod, 1, y.metin());
    assert.match(y.metin(), /NOT VERIFIED/);
    assert.match(y.metin(), /signature does not verify/);
  });

  it("defteri olmayan dizin sessiz başarı değildir", async () => {
    const y = yakala();
    const kod = await runVerify([mkdtempSync(join(tmpdir(), "verax-verify-bos-"))], y.out);
    assert.equal(kod, 1);
    assert.match(y.metin(), /NOT VERIFIED/);
  });

  it("--json makine okunur çıktı verir ve aynı kararı taşır", async () => {
    const y = yakala();
    const kod = await runVerify([kopyala(), "--json"], y.out);
    const j = JSON.parse(y.metin()) as { ok: boolean; decisions: number; trust: { source: string } };
    assert.equal(kod, 0);
    assert.equal(j.ok, true);
    assert.ok(j.decisions > 0);
    assert.equal(j.trust.source, "in-ledger");
  });

  it("--key okunamazsa sessizce kendi anahtarına düşmez", async () => {
    const y = yakala();
    const kod = await runVerify([kopyala(), "--key", join(tmpdir(), "boyle-bir-dosya-yok.pem")], y.out);
    assert.equal(kod, 1, "okunamayan anahtar başarı sayıldı");
    assert.match(y.metin(), /cannot read key file/i);
    assert.doesNotMatch(y.metin(), /\bVERIFIED\b/);
  });
});
