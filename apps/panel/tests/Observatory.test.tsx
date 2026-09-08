import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
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
