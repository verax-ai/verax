import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseInventory, type Inventory } from "@verax-ai/galaxy";
import { panelCopy } from "../src/copy.ts";
import { Observatory } from "../src/observatory/Observatory.tsx";
import { loadDemoActions } from "../src/observatory/demo.ts";
import { parseLedger } from "../src/rail/parse.ts";
import type { PolicyBundle, RailAction } from "../src/rail/types.ts";
import { setLang } from "./with-lang.ts";

vi.mock("@verax-ai/galaxy/react", () => ({
  Galaxy: () => <div data-testid="galaxy-stage" />,
}));

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const golden = join(root, "packages", "proxy", "tests", "fixtures", "ledger-golden");
const policy = JSON.parse(
  readFileSync(join(root, "packages", "proxy", "policy", "default.json"), "utf8"),
) as PolicyBundle["document"];

const sampleParsed = parseInventory(
  JSON.parse(readFileSync(join(root, "packages", "galaxy", "tests", "fixtures", "inventory-sample.json"), "utf8")),
);
if (!sampleParsed.ok) throw new Error(sampleParsed.reason);
const sampleInventory: Inventory = sampleParsed.value;

const actions = parseLedger(
  readFileSync(join(golden, "decisions.jsonl"), "utf8"),
  readFileSync(join(golden, "effects.jsonl"), "utf8"),
  { hash: "fixture", document: policy },
);

function withContest(list: RailAction[]): RailAction[] {
  return list.map((a, i) =>
    i === 0
      ? {
          ...a,
          guarantee: "conditional",
          finding: {
            code: null,
            label: "conditional",
            summary: "audit: balanced (conditional: self witness; extract unpinned)",
          },
          trustRoot: { pinned: false, issuerMatches: null, source: null },
          witnessClass: "self",
        }
      : a,
  );
}

afterEach(() => {
  cleanup();
});

beforeEach(() => {
  setLang("tr");
});

describe("observatory", () => {
  it("renders three tabs and defaults to records", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Kayıtlar", "Galaksi", "Genel durum"]);
    expect(screen.getByRole("tab", { name: "Kayıtlar" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("records-summary")).toBeTruthy();
    expect(screen.queryByTestId("galaxy-stage")).toBeNull();
    expect(screen.queryByTestId("stage")).toBeNull();
  });

  it("says the ledger is empty instead of showing an unexplained black stage", () => {
    render(<Observatory actions={[]} status="ok" demo={false} />);
    fireEvent.click(screen.getByRole("tab", { name: "Galaksi" }));
    expect(screen.getByTestId("galaxy-empty").textContent).toMatch(/kayıt yok/i);
    expect(screen.getByTestId("galaxy-coverage").textContent).toBe("envanter bağlı değil");
    expect(screen.getByTestId("galaxy-coverage").textContent).not.toMatch(/\d+\s*\/\s*\d+/);
  });

  it("passes the hidden-names line from copy into the sky", () => {
    const src = readFileSync(join(root, "apps", "panel", "src", "observatory", "Observatory.tsx"), "utf8");
    expect(src).toMatch(/hiddenLabelsText=\{copy\["galaxy\.labels\.hidden"\]\}/);
    expect(src).toMatch(/crowdedLabelsText=\{copy\["galaxy\.labels\.hidden\.crowd"\]\}/);
    const en = JSON.parse(readFileSync(join(root, "apps", "panel", "src", "copy", "en.json"), "utf8")) as Record<string, string>;
    const tr = JSON.parse(readFileSync(join(root, "apps", "panel", "src", "copy", "tr.json"), "utf8")) as Record<string, string>;
    expect(en["galaxy.labels.hidden"]).toMatch(/\{n\}/);
    expect(en["galaxy.labels.hidden"]).toMatch(/hidden at this distance/i);
    expect(en["galaxy.labels.hidden.crowd"]).toMatch(/\{n\}/);
    expect(en["galaxy.labels.hidden.crowd"]).toMatch(/crowded/i);
    expect(tr["galaxy.labels.hidden.crowd"]).toMatch(/\{n\}/);
    expect(tr["galaxy.labels.hidden.crowd"]).toMatch(/yığın/);
  });

  it("passes the focus line from copy into the sky and names how to leave", () => {
    const src = readFileSync(join(root, "apps", "panel", "src", "observatory", "Observatory.tsx"), "utf8");
    expect(src).toMatch(/focusText=\{copy\["galaxy\.focus"\]\}/);
    expect(src).toMatch(/leaveFocusText=\{copy\["galaxy\.focus\.leave"\]\}/);
    const en = JSON.parse(readFileSync(join(root, "apps", "panel", "src", "copy", "en.json"), "utf8")) as Record<string, string>;
    const tr = JSON.parse(readFileSync(join(root, "apps", "panel", "src", "copy", "tr.json"), "utf8")) as Record<string, string>;
    expect(en["galaxy.focus"]).toMatch(/\{name\}/);
    expect(en["galaxy.focus.leave"]).toMatch(/leave/i);
    expect(tr["galaxy.focus"]).toMatch(/\{name\}/);
    expect(tr["galaxy.focus.leave"].length).toBeGreaterThan(0);
  });

  it("reads ?focus= so a group seat can open from the address", () => {
    const src = readFileSync(join(root, "apps", "panel", "src", "observatory", "Observatory.tsx"), "utf8");
    expect(src).toMatch(/window\.location\.search\)\.get\("focus"\)/);
  });

  it("lets the inventory rail pick a group without calling it measured", () => {
    render(
      <Observatory
        actions={[]}
        status="ok"
        demo={false}
        inventory={sampleInventory}
        nowMs={sampleInventory.takenAtMs + 5_000}
      />,
    );
    const groups = screen.getByTestId("rail-inventory-groups");
    const button = groups.querySelector("button");
    expect(button?.textContent).toMatch(/Team A/);
    expect(screen.getByText("Gruplar (envanter, ölçülemedi)")).toBeTruthy();
    fireEvent.click(button!);
    expect(screen.getByRole("tab", { name: "Galaksi" }).getAttribute("aria-selected")).toBe("true");
  });

  it("keeps inventory names off the ledger rail and does not say not-bound for them", () => {
    render(
      <Observatory
        actions={[]}
        status="ok"
        demo={false}
        inventory={sampleInventory}
        nowMs={sampleInventory.takenAtMs + 5_000}
      />,
    );
    expect(screen.getByText("Projeler (defter)")).toBeTruthy();
    expect(screen.getByText("Ajanlar (defter)")).toBeTruthy();
    expect(screen.getByText("Gruplar (envanter, ölçülemedi)")).toBeTruthy();
    expect(screen.getByText("Ajanlar (envanter, ölçülemedi)")).toBeTruthy();
    expect(screen.getByTestId("rail-inventory-groups").textContent).toMatch(/Team A/);
    expect(screen.getByTestId("rail-inventory-groups").textContent).toMatch(/Team B/);
    expect(screen.getByTestId("rail-inventory-agents").textContent).toMatch(/Agent 1/);
    expect(screen.queryByTestId("rail-ledger-agents")).toBeNull();
    const inventoryBlock = screen.getByTestId("rail-inventory-agents");
    expect(inventoryBlock.className).toMatch(/rail-inventory/);
    expect(inventoryBlock.className).not.toMatch(/rail-ledger/);
    const disconnected = [...document.querySelectorAll(".obs-left .muted")].map((n) => n.textContent);
    expect(disconnected.length).toBeGreaterThan(0);
    expect(inventoryBlock.textContent).not.toMatch(/bağlı değil/);
  });

  it("omits the inventory rail when the roster is not bound", () => {
    render(<Observatory actions={[]} status="ok" demo={false} />);
    expect(screen.queryByTestId("rail-inventory-groups")).toBeNull();
    expect(screen.queryByTestId("rail-inventory-agents")).toBeNull();
    expect(screen.getByText("Projeler (defter)")).toBeTruthy();
    expect(screen.getAllByText("bağlı değil").length).toBeGreaterThan(0);
  });

  it("fills the sky from inventory and names coverage without a percentage", () => {
    render(
      <Observatory
        actions={[]}
        status="ok"
        demo={false}
        inventory={sampleInventory}
        nowMs={sampleInventory.takenAtMs + 5_000}
      />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Galaksi" }));
    expect(screen.queryByTestId("galaxy-empty")).toBeNull();
    expect(screen.getByTestId("galaxy-coverage").textContent).toMatch(/0 \/ 3 ajan hesap veriyor/);
    expect(screen.getByTestId("galaxy-coverage").textContent).toMatch(/fixture-source/);
    expect(screen.getByTestId("galaxy-coverage").textContent).not.toMatch(/%/);
  });

  it("says the inventory snapshot is stale instead of hiding it", () => {
    render(
      <Observatory
        actions={[]}
        status="ok"
        demo={false}
        inventory={sampleInventory}
        nowMs={sampleInventory.takenAtMs + 25 * 60 * 60 * 1000}
      />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Galaksi" }));
    expect(screen.getByTestId("galaxy-coverage").textContent).toMatch(/bayat/);
  });

  it("says nothing about emptiness once there are records", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    expect(screen.queryByTestId("galaxy-empty")).toBeNull();
  });

  it("does not repeat the record list in the rail on the records tab", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    expect(screen.queryByTestId("rail-records")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Galaksi" }));
    // From the other tabs the rail is the only way back into a record, so it
    // has to still be there.
    expect(screen.getByTestId("rail-records").textContent ?? "").toMatch(/memory\.|spend|audit\./);
  });

  it("opens in English and hands the reader the other language", () => {
    setLang("en");
    render(<Observatory actions={withContest(actions)} status="ok" demo={false} />);
    expect(screen.getByRole("tab", { name: "Records" })).toBeTruthy();
    const tr = screen.getByRole("button", { name: "TR" });
    expect(tr.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(tr);
    expect(screen.getByRole("tab", { name: "Kayıtlar" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "TR" }).getAttribute("aria-pressed")).toBe("true");
    // The choice is in the address, so the screen can be handed on as it reads.
    expect(window.location.search).toMatch(/lang=tr/);
  });

  it("asks all five questions on the record, including the one it cannot answer", () => {
    // The questions are the product. A screen that drops the one it has no
    // answer for is back to reporting only what flatters it, so the empty
    // question stays on the page and says it is not connected.
    render(<Observatory actions={withContest(actions)} status="ok" demo={false} />);
    const copy = panelCopy();
    const heads = [...document.querySelectorAll(".detail-pane h3")].map((n) => n.textContent);
    expect(heads).toEqual([
      copy["question.did"],
      copy["question.counterpart"],
      copy["question.current"],
      copy["question.impact"],
      copy["question.rules"],
    ]);
    expect(screen.getByTestId("question-impact").textContent).toBe(copy["question.impact.empty"]);
  });

  it("offers the inspect button on a record that has a ref", () => {
    render(<Observatory actions={withContest(actions)} status="ok" demo={false} />);
    expect(screen.getByRole("button", { name: panelCopy().inspect })).toBeTruthy();
  });

  it("says the historical policy is unreadable in red, in the reader's language", () => {
    const noPolicy: RailAction[] = [
      { ...actions[0]!, rule: { text: null, missing: "historical policy unavailable" } },
    ];
    render(<Observatory actions={noPolicy} status="ok" demo={false} />);
    const line = screen.getByTestId("detail-policy");
    expect(line.textContent).toBe(panelCopy()["line.rule.missing"]);
    expect(line.className).toMatch(/rule-missing/);
  });

  it("names the warning codes next to the guarantee", () => {
    const warned: RailAction[] = [
      {
        ...actions[0]!,
        guarantee: "conditional",
        warnings: [{ id: "w1", code: "issuer-unpinned" }],
        trustRoot: { pinned: true, issuerMatches: null, source: "own-key" },
      },
    ];
    render(<Observatory actions={warned} status="ok" demo={false} />);
    const scope = screen.getByTestId("evidence-scope").textContent ?? "";
    expect(scope).toMatch(/issuer-unpinned/);
    expect(scope).toMatch(/pin: own key/);
  });

  it("says so when an inspect does not complete, instead of going quiet", async () => {
    // The dead rail reported a failed re-audit; the live screen stored the
    // result only when there was no error and printed nothing otherwise, so a
    // 401 looked exactly like a click that did nothing.
    const onContest = vi.fn(async () => ({ error: "re-audit failed (401)" }));
    render(
      <Observatory actions={withContest(actions)} status="ok" demo={false} onContest={onContest} />,
    );
    fireEvent.click(screen.getByRole("button", { name: panelCopy().inspect }));
    await waitFor(() => {
      expect(onContest).toHaveBeenCalled();
      expect(screen.getByTestId("inspect-failed").textContent).toMatch(/401/);
    });
  });

  it("shows evidence scope with guarantee and pin:", () => {
    render(<Observatory actions={withContest(actions)} status="ok" demo={false} />);
    expect(screen.getByTestId("evidence-scope").textContent).toMatch(/guarantee/);
    expect(screen.getByTestId("evidence-scope").textContent).toMatch(/pin:/);
  });

  it("shows a red identity line when the inputs document is missing", () => {
    const missing: RailAction[] = [
      {
        ...actions[0]!,
        inputs: undefined,
        inputsBound: false,
        record: {
          ...actions[0]!.record,
          claims: { ...actions[0]!.record.claims, inputsHash: "aa".repeat(32) },
        },
      },
    ];
    render(<Observatory actions={missing} status="ok" demo={false} />);
    const line = screen.getByTestId("detail-identity");
    expect(line.textContent).toBe(panelCopy()["detail.identityMissing"]);
    expect(line.className).toMatch(/rule-missing/);
  });

  it("says receipt yok when an effect has no receipt", () => {
    const bare: RailAction[] = [
      {
        ...actions[0]!,
        effect: actions[0]!.effect
          ? { ...actions[0]!.effect, receipt: undefined, attestation: undefined }
          : {
              row: {
                ref: actions[0]!.record.claims.ref ?? "n1",
                effectClass: "memory.get",
                effectHash: "aa".repeat(32),
                timestampMs: 10,
              },
            },
      },
    ];
    render(<Observatory actions={bare} status="ok" demo={false} />);
    expect(document.body.textContent).toMatch(/receipt yok/);
    expect(document.body.textContent).not.toMatch(/receipt var/);
  });

  it("keeps anatomy copy on the status document, not as a presence stage", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    const doc = screen.getByTestId("anatomy-document");
    expect(doc.textContent).toMatch(/Anatomi/);
    expect(doc.textContent).toMatch(/head\.part|Kafa|Head/i);
    expect(screen.queryByTestId("stage")).toBeNull();
  });

  it("demo data has no rule-missing rows", () => {
    render(<Observatory actions={loadDemoActions()} status="ok" demo={true} />);
    expect(document.querySelectorAll(".rule-missing").length).toBe(0);
  });

  it("shows ÖRNEK SENARYO on demo data and hides it on live data", () => {
    const { rerender } = render(<Observatory actions={actions} status="ok" demo={true} />);
    expect(screen.getByText("ÖRNEK SENARYO")).toBeTruthy();
    rerender(<Observatory actions={actions} status="ok" demo={false} />);
    expect(screen.queryByText("ÖRNEK SENARYO")).toBeNull();
  });

  it("moves tabs with arrow keys", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    const list = screen.getByRole("tablist");
    fireEvent.keyDown(list, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Galaksi" }).getAttribute("aria-selected")).toBe("true");
  });

  it("does not add an animation class when reduced motion is set", () => {
    vi.stubGlobal(
      "matchMedia",
      (q: string) => ({
        matches: q.includes("prefers-reduced-motion"),
        media: q,
        addEventListener() {},
        removeEventListener() {},
        addListener() {},
        removeListener() {},
        dispatchEvent() {
          return false;
        },
      }),
    );
    render(<Observatory actions={actions} status="ok" demo={false} />);
    expect(document.querySelector(".is-animating")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("opens with a measured sentence and a readable list, not naked refs", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    const sentence = screen.getByTestId("records-summary").textContent ?? "";
    expect(sentence).toMatch(/6 karar/);
    expect(sentence).toMatch(/ekstre bağlı değil/);
    const labels = [...document.querySelectorAll(".record-asked")].map((n) => n.textContent ?? "");
    expect(labels.length).toBe(6);
    expect(labels.every((t) => t !== "" && !/^n\d+$/.test(t))).toBe(true);
    fireEvent.click(screen.getByRole("tab", { name: "Galaksi" }));
    const rail = screen.getByTestId("rail-records").textContent ?? "";
    expect(rail).not.toMatch(/^n1$/);
    expect(rail).toMatch(/memory\.|spend|audit\./);
  });

  it("writes what an empty ledger is, instead of looking broken", () => {
    render(<Observatory actions={[]} status="empty" demo={false} />);
    expect(screen.getByTestId("records-summary").textContent).toBe("Henüz karar üretilmedi.");
    expect(screen.getByTestId("records-empty").textContent).toMatch(/bozuk bir ekran değil/);
    expect(screen.queryByTestId("record-list")).toBeNull();
  });

  it("splits evidence scope into signature, witness and external lines", () => {
    render(<Observatory actions={withContest(actions)} status="ok" demo={false} />);
    expect(screen.getByTestId("scope-signature").textContent).toMatch(/ölçülemedi|not measured|doğrulandı|verified/i);
    expect(screen.getByTestId("scope-witness").textContent).toMatch(/self/);
    expect(screen.getByTestId("scope-external").textContent).toMatch(/bağlı değil|not bound/);
    expect(screen.getByTestId("evidence-scope").textContent).toMatch(/guarantee/);
    expect(screen.getByTestId("evidence-scope").textContent).toMatch(/pin:/);
  });

  it("does not draw unbound product names", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    const body = document.body.textContent ?? "";
    expect(body).not.toMatch(/Conarium/);
    expect(body).not.toMatch(/Tuğra|Tugra/);
    expect(body).not.toMatch(/Cedulon/);
  });
});
