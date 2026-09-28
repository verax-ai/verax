import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Observatory } from "../src/observatory/Observatory.tsx";
import { panelCopy } from "../src/copy.ts";
import { fillCopy } from "../src/fill.ts";
import { formatMinor } from "../src/records/money.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";
import { setLang } from "./with-lang.ts";

afterEach(() => {
  cleanup();
});

beforeEach(() => {
  setLang("tr");
});

const HASH = "ab".repeat(32);

const waiting: PendingApproval = {
  ref: "d-open",
  requestHash: HASH,
  subject: "spend",
  ruleText: "Sample spend needs operator approval.",
  inputsSummary: { count: 0, ids: [] },
  amount: 1000,
  currency: "TRY",
  payee: "example-payee",
  expiresAtMs: 9_999_999_999_999,
  status: "pending",
  brain: "sample-brain",
};

const deferRecord: RailAction = {
  record: {
    claims: {
      subject: "spend",
      decision: "defer",
      reasonCode: "approval-required",
      timestampMs: 1_788_800_000_000,
      decider: "verax-proxy",
      ref: "d-open",
      requestHash: HASH,
      policyHash: "aa".repeat(32),
      effectHash: null,
    },
  },
  effect: null,
  rule: { id: "spend-sample", tool: "spend", text: "Sample spend needs operator approval." },
  finding: null,
  inputs: { principal: { brain: "sample-brain", scopes: ["verax:pay"] }, inputs: [] },
  inputsBound: true,
};

const memoryRecord: RailAction = {
  ...deferRecord,
  record: { claims: { ...deferRecord.record.claims, subject: "memory.get", decision: "allow", reasonCode: "rule", ref: "m-1" } },
};

const allowRecord: RailAction = {
  ...deferRecord,
  record: {
    claims: { ...deferRecord.record.claims, decision: "allow", reasonCode: "approved-by-operator", ref: "a-open", timestampMs: 1_788_800_060_000 },
  },
  inputs: {
    principal: { brain: "sample-brain", scopes: ["verax:pay"] },
    inputs: [],
    approver: { id: "operator-1", via: "http", resolves: "d-open" },
  },
};

function openBox(extra: Record<string, unknown> = {}) {
  render(
    <Observatory actions={[deferRecord, memoryRecord]} status="ok" demo={false} pending={[waiting]} {...extra} />,
  );
  fireEvent.click(screen.getByRole("tab", { name: "Kara kutu" }));
  const host = screen.getByTestId("black-box");
  const cx = host.shadowRoot?.querySelector(".cx");
  if (!(cx instanceof HTMLElement)) throw new Error("the black box drew nothing into its shadow root");
  return { host, cx, box: within(cx) };
}

/**
 * The black box reads the ledger like a flight recorder: a tape of every
 * decision, the chain of the one picked, and what is waiting. It may not draw
 * a product the body is not connected to, a number the ledger did not give, or
 * an approval that skips the questions the rest of the panel asks.
 */
describe("the black box tab", () => {
  it("draws inside its shadow root, where the page's own text checks cannot see", () => {
    const { host, cx } = openBox();
    // The reason the checks below read the shadow root: the page does not.
    expect(host.textContent).toBe("");
    expect(cx.textContent).toContain(panelCopy()["rec.tape.title"]);
  });

  it("names no product the body is not connected to", () => {
    const { cx } = openBox();
    expect(cx.textContent).not.toMatch(/Conarium|Tugra|Tuğra|Cedulon/i);
  });

  it("counts from the ledger and puts every decision on the tape", () => {
    const { cx } = openBox();
    expect(cx.textContent).toContain("2 karar, 1 ajan. 0 ret, 1 onay bekliyor.");
    expect(cx.querySelectorAll(".mark")).toHaveLength(2);
  });

  it("stops the chain at a refusal: the tool never ran", () => {
    const denied: RailAction = {
      ...memoryRecord,
      record: { claims: { ...memoryRecord.record.claims, decision: "deny", reasonCode: "scope-missing", ref: "m-deny", timestampMs: 1_788_800_030_000 } },
    };
    const { box, cx } = openBox({ actions: [deferRecord, denied] });
    const mark = cx.querySelector(".mark.deny");
    if (!(mark instanceof HTMLElement)) throw new Error("no refused mark on the tape");
    expect(mark.getAttribute("aria-label")).toContain(panelCopy()["rec.legend.deny"]);
    fireEvent.click(mark);
    const chain = box.getByTestId("box-chain");
    expect(chain.textContent).toContain(panelCopy()["rec.say.decision.deny"]);
    expect(chain.textContent).toContain(panelCopy()["rec.say.effect.refused"]);
    expect(chain.textContent).not.toContain(panelCopy()["rec.step.receipt"]);
  });

  it("draws a long silence as a break that says how long", () => {
    const late: RailAction = {
      ...memoryRecord,
      record: { claims: { ...memoryRecord.record.claims, ref: "m-late", timestampMs: 1_788_800_000_000 + 2 * 3600_000 + 60_000 } },
    };
    const { cx } = openBox({ actions: [deferRecord, late] });
    expect(cx.textContent).toContain(fillCopy(panelCopy()["rec.tape.break"], { gap: "2 sa" }));
  });

  it("says the tape is empty instead of drawing a sample", () => {
    const { cx } = openBox({ actions: [], pending: [] });
    expect(cx.textContent).toContain(panelCopy()["rec.tape.empty"]);
  });

  it("prints the waiting sum exactly as the record list does", () => {
    const { box } = openBox();
    const listed = formatMinor(1000, "TRY", "tr");
    expect(listed).not.toBeNull();
    expect(box.getByTestId("box-amount").textContent).toBe(listed);
    expect(box.getByTestId("box-record-amount").textContent).toBe(listed);
  });

  it("draws no approve button when the session cannot approve, and says why", () => {
    // The handler is there, as it is in the app; only the scope is missing.
    const { box } = openBox({ canApprove: false, onApprove: vi.fn() });
    expect(box.queryByRole("button", { name: new RegExp(panelCopy()["approve.button"]) })).toBeNull();
    expect(box.getByTestId("box-no-scope").textContent).toBe(panelCopy()["box.request.noScope"]);
  });

  it("asks before it approves, then sends the ref and the hash on the screen", async () => {
    const onApprove = vi.fn(async () => ({ ok: true as const, allowRef: "a-1" }));
    const { box } = openBox({ canApprove: true, onApprove });
    fireEvent.click(box.getByRole("button", { name: new RegExp(panelCopy()["approve.button"]) }));
    expect(onApprove).not.toHaveBeenCalled();
    const asked = box.getByTestId("box-approve-confirm").textContent ?? "";
    expect(asked).toContain(formatMinor(1000, "TRY", "tr") ?? "missing");
    expect(asked).toContain("example-payee");
    expect(asked).toContain("Sample spend needs operator approval.");
    fireEvent.click(box.getByRole("button", { name: new RegExp(panelCopy()["approve.yes"]) }));
    await waitFor(() => {
      expect(onApprove).toHaveBeenCalledWith("d-open", HASH);
    });
    await waitFor(() => {
      expect(box.getByTestId("box-approve-outcome").textContent).toContain("a-1");
    });
  });

  it("says the sample was not sent instead of claiming it approved one", async () => {
    const onApprove = vi.fn(async () => ({ ok: false as const, error: "sample-not-sent" }));
    const { box, cx } = openBox({ canApprove: true, onApprove, demo: true });
    expect(cx.textContent).toContain(panelCopy()["box.console.sample"]);
    fireEvent.click(box.getByRole("button", { name: new RegExp(panelCopy()["approve.button"]) }));
    fireEvent.click(box.getByRole("button", { name: new RegExp(panelCopy()["approve.yes"]) }));
    await waitFor(() => {
      expect(box.getByTestId("box-approve-outcome").textContent).toBe(panelCopy()["approve.sample"]);
    });
  });

  it("shows who approved an answered request, from the record", () => {
    const answered: PendingApproval = { ...waiting, status: "approved", allowRef: "a-open" };
    const { box, cx } = openBox({ actions: [deferRecord, allowRecord], pending: [answered], canApprove: true, onApprove: vi.fn() });
    expect(box.getByTestId("box-badge").textContent).toBe(panelCopy()["box.badge.approved"]);
    expect(cx.textContent).toContain("operator-1 / http");
    expect(box.queryByRole("button", { name: new RegExp(panelCopy()["approve.button"]) })).toBeNull();
  });

  it("says the ledger holds no request instead of playing a sample", () => {
    const { box, cx } = openBox({ pending: [] });
    expect(box.getByTestId("box-badge").textContent).toBe(panelCopy()["box.badge.none"]);
    expect(box.queryByTestId("box-amount")).toBeNull();
    expect(cx.textContent).not.toMatch(/4[.,]800/);
  });

  it("opens the record it shows on the records tab", () => {
    const { box } = openBox();
    fireEvent.click(box.getByRole("button", { name: new RegExp(panelCopy()["box.record.open"]) }));
    expect(screen.getByRole("tab", { name: "Kayıtlar" }).getAttribute("aria-selected")).toBe("true");
  });

  it("gives the box the whole width: no rail, no detail pane", () => {
    openBox();
    expect(document.querySelector(".obs-left")).toBeNull();
    expect(document.querySelector(".obs-detail")).toBeNull();
  });
});
