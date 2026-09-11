import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Observatory } from "../src/observatory/Observatory.tsx";
import { panelCopy } from "../src/copy.ts";
import type { PendingApproval } from "../src/rail/types.ts";
import { setLang } from "./with-lang.ts";

vi.mock("@verax-ai/galaxy/react", () => ({
  Galaxy: () => <div data-testid="galaxy-stage" />,
}));

afterEach(() => {
  cleanup();
});

beforeEach(() => {
  setLang("tr");
});

const waiting: PendingApproval = {
  ref: "d-open",
  requestHash: "ab".repeat(32),
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

const resolved: PendingApproval = { ...waiting, ref: "d-done", status: "approved" };

function open(extra: Record<string, unknown> = {}) {
  render(<Observatory actions={[]} status="ok" demo={false} pending={[waiting, resolved]} {...extra} />);
  fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
}

/**
 * An approval is money leaving, and it cannot be taken back. That shapes what
 * the screen owes the operator: never a button that cannot work, never an
 * approval without being asked first, never a claim of success that the body
 * did not make.
 */
describe("approving from the screen", () => {
  it("draws no button when the session cannot approve", () => {
    open();
    expect(screen.queryByRole("button", { name: panelCopy()["approve.button"] })).toBeNull();
  });

  it("offers it only on what is still waiting", () => {
    open({ canApprove: true, onApprove: vi.fn() });
    const buttons = screen.getAllByRole("button", { name: panelCopy()["approve.button"] });
    // Two rows are listed; only the pending one is a decision still open.
    expect(buttons.length).toBe(1);
  });

  it("asks before it approves, and names what is being approved", () => {
    const onApprove = vi.fn();
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    // The tap opens the question. It does not approve.
    expect(onApprove).not.toHaveBeenCalled();
    const asked = screen.getByTestId("approve-confirm").textContent ?? "";
    expect(asked).toContain("10,00");
    expect(asked).toContain("example-payee");
    expect(asked).toContain("Sample spend needs operator approval.");
  });

  it("sends the ref and the hash the screen was showing", async () => {
    const onApprove = vi.fn(async () => ({ ok: true as const, allowRef: "a-1" }));
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(onApprove).toHaveBeenCalledWith("d-open", "ab".repeat(32));
    });
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("a-1");
    });
  });

  it("says the request changed instead of claiming it approved one", async () => {
    const onApprove = vi.fn(async () => ({ ok: false as const, error: "stale" }));
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      const said = screen.getByTestId("approve-outcome").textContent ?? "";
      expect(said).toBe(panelCopy()["approve.stale"]);
    });
  });

  it("repeats the body's own reason when it refuses for another cause", async () => {
    const onApprove = vi.fn(async () => ({ ok: false as const, error: "already-resolved" }));
    open({ canApprove: true, onApprove });
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("already-resolved");
    });
  });
});
