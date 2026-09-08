import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseInventory, type Inventory } from "@verax-ai/galaxy";
import { Observatory } from "../src/observatory/Observatory.tsx";
import { loadDemoActions } from "../src/observatory/demo.ts";
import { parseLedger } from "../src/rail/parse.ts";
import type { PolicyBundle, RailAction } from "../src/rail/types.ts";

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

describe("observatory", () => {
  it("renders three tabs and defaults to galaxy", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Genel durum", "Galaksi", "Geçmiş"]);
    expect(screen.getByRole("tab", { name: "Galaksi" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByTestId("galaxy-stage")).toBeTruthy();
    expect(screen.queryByTestId("stage")).toBeNull();
  });

  it("says the ledger is empty instead of showing an unexplained black stage", () => {
    render(<Observatory actions={[]} status="ok" demo={false} />);
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
    expect(screen.getByTestId("galaxy-coverage").textContent).toMatch(/bayat/);
  });

  it("says nothing about emptiness once there are records", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    expect(screen.queryByTestId("galaxy-empty")).toBeNull();
  });

  it("shows evidence scope with guarantee and pin:", () => {
    render(<Observatory actions={withContest(actions)} status="ok" demo={false} />);
    fireEvent.click(screen.getByRole("tab", { name: "Geçmiş" }));
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
    fireEvent.click(screen.getByRole("tab", { name: "Geçmiş" }));
    const line = document.querySelector(".detail-pane .rule-missing");
    expect(line?.textContent).toBe("identity hash on the record; inputs document unavailable");
    expect(line?.className).toMatch(/rule-missing/);
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
    fireEvent.click(screen.getByRole("tab", { name: "Geçmiş" }));
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
    expect(screen.getByRole("tab", { name: "Geçmiş" }).getAttribute("aria-selected")).toBe("true");
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
});
