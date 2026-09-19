import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { Observatory, type Healthz } from "../src/observatory/Observatory.tsx";
import { setLang } from "./with-lang.ts";

/**
 * A body can now stand in front of other products. Until this screen said so,
 * an operator could read rows named `conarium.list_tables` with nothing on any
 * tab telling them a Conarium was attached, or which of its tools this body
 * would even accept.
 *
 * The address is deliberately absent: the body does not publish it, because a
 * child's URL can carry its token (`tests/downstream-visible`). The screen
 * cannot show what it is never given.
 */

afterEach(cleanup);

function health(downstream: NonNullable<Healthz>["downstream"]): Healthz {
  return {
    ok: true,
    decisions: 12,
    effects: 8,
    lastDecisionMs: 1_700_000_000_000,
    lock: "held",
    heartbeat: null,
    witness: null,
    downstream,
  };
}

function durumEkrani(h: Healthz) {
  render(<Observatory actions={[]} status="ok" demo={false} health={h} />);
  fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
}

describe("durum ekranı bağlı ürünleri söyler", () => {
  it("bağlı çocuğun önekini, taşımasını ve araç sayısını gösterir", () => {
    setLang("tr");
    durumEkrani(
      health([{ prefix: "conarium", transport: "http", tools: ["conarium.list_tables", "conarium.query"] }]),
    );
    const metin = document.body.textContent ?? "";
    expect(metin).toMatch(/conarium/i);
    expect(metin).toMatch(/HTTP/i);
    expect(metin).toMatch(/2/);
  });

  it("çocuğun adresini ekrana yazmaz", () => {
    setLang("tr");
    durumEkrani(health([{ prefix: "kb", transport: "http", tools: ["kb.lookup"] }]));
    expect(document.body.textContent ?? "").not.toMatch(/https?:\/\//);
  });

  it("hiç bağlı ürün yoksa bölümü gizlemez, yokluğu söyler", () => {
    setLang("tr");
    durumEkrani(health([]));
    expect(document.body.textContent ?? "").toMatch(/bağlı ürün yok/i);
  });

  it("gövde hiç söylemiyorsa (eski sürüm) bölüm hiç çizilmez", () => {
    setLang("tr");
    durumEkrani({ ok: true, decisions: 1, effects: 0, lastDecisionMs: null, lock: "held" });
    expect(document.body.textContent ?? "").not.toMatch(/bağlı ürün/i);
  });
});
