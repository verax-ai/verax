import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Observatory } from "../src/observatory/Observatory.tsx";
import { loadDemoActions } from "../src/observatory/demo.ts";
import { parseLedger } from "../src/rail/parse.ts";
import type { PolicyBundle, RailAction } from "../src/rail/types.ts";

vi.mock("@verax-ai/presence", () => ({
  Stage: () => <div data-testid="stage" />,
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
  it("renders four tabs", () => {
    render(<Observatory actions={actions} status="ok" demo={false} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual([
      "Genel durum",
      "Sistem haritası",
      "İşlem geçmişi",
      "Anatomi",
    ]);
  });

  it("shows evidence scope with guarantee and pin:", () => {
    render(<Observatory actions={withContest(actions)} status="ok" demo={false} />);
    fireEvent.click(screen.getByRole("tab", { name: "İşlem geçmişi" }));
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
    fireEvent.click(screen.getByRole("tab", { name: "İşlem geçmişi" }));
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

  it("draws one map edge per unique brain-subject pair", () => {
    const demo = loadDemoActions();
    const pairs = new Set(
      demo.map((a) => `${a.inputs?.principal.brain ?? "unknown"}\t${a.record.claims.subject}`),
    );
    render(<Observatory actions={demo} status="ok" demo={true} />);
    fireEvent.click(screen.getByRole("tab", { name: "Sistem haritası" }));
    const edges = [...document.querySelectorAll(".system-map line[data-edge]")];
    expect(edges.length).toBe(pairs.size);
    const bySubject = new Map<string, { x2: string | null; y2: string | null }>();
    for (const el of edges) {
      const pair = el.getAttribute("data-edge") ?? "";
      const subject = pair.split("|")[1] ?? "";
      bySubject.set(subject, { x2: el.getAttribute("x2"), y2: el.getAttribute("y2") });
    }
    const subjects = [...bySubject.keys()];
    expect(subjects.length).toBeGreaterThan(1);
    const a = bySubject.get(subjects[0]!)!;
    const b = bySubject.get(subjects[1]!)!;
    expect(`${a.x2},${a.y2}`).not.toBe(`${b.x2},${b.y2}`);
  });

  it("demo data has no rule-missing rows", () => {
    render(<Observatory actions={loadDemoActions()} status="ok" demo={true} />);
    fireEvent.click(screen.getByRole("tab", { name: "İşlem geçmişi" }));
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
    expect(screen.getByRole("tab", { name: "Sistem haritası" }).getAttribute("aria-selected")).toBe("true");
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
