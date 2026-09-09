import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Observatory } from "../src/observatory/Observatory.tsx";
import type { PendingApproval } from "../src/rail/types.ts";

vi.mock("@verax-ai/galaxy/react", () => ({
  Galaxy: () => <div data-testid="galaxy-stage" />,
}));

afterEach(() => {
  cleanup();
});

const row: PendingApproval = {
  ref: "d1",
  requestHash: "aa".repeat(32),
  subject: "memory.put",
  ruleText: "Writes need operator approval.",
  inputsSummary: { count: 0, ids: [] },
  amount: 10,
  payee: "ads",
  expiresAtMs: 9_999,
  status: "pending",
  brain: "brain-1",
};

describe("pending approvals", () => {
  it("lists pending rows with rule text and has no approve-all control", () => {
    render(
      <Observatory
        actions={[]}
        status="empty"
        demo={false}
        pending={[row]}
      />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    const list = screen.getByTestId("pending-approvals");
    expect(list.textContent).toMatch(/d1/);
    expect(list.textContent).toMatch(/Writes need operator approval/);
    expect(list.textContent).toMatch(/ads/);
    expect(document.body.textContent).not.toMatch(/hepsini onayla/i);
    expect(document.body.textContent).not.toMatch(/approve all/i);
    expect(document.querySelector("[data-approve-all]")).toBeNull();
    expect(document.querySelector("button[data-approve]")).toBeNull();
  });

  it("formats a spend pending row as amount currency to payee", () => {
    render(
      <Observatory
        actions={[]}
        status="empty"
        demo={false}
        pending={[
          {
            ...row,
            ref: "s1",
            subject: "spend",
            ruleText: "Spends need operator approval.",
            amount: 125050,
            currency: "TRY",
            payee: "true-ads",
          },
        ]}
      />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    const list = screen.getByTestId("pending-approvals");
    // 125050 is the stored minor amount. This screen used to print it beside
    // the currency, which states a sum a hundred times too large, and this
    // test froze that. The record screen was fixed in 3fafdcb; the status tab
    // kept the fault because each file was consistent with itself.
    expect(list.textContent).toMatch(/1[.,]250[.,]50/);
    expect(/(^|[^.,\d])125050([^.,\d]|$)/.test(list.textContent ?? "")).toBe(false);
    expect(list.textContent).toMatch(/true-ads/);
    expect(list.textContent).toMatch(/Spends need operator approval/);
    expect(document.querySelector("button[data-approve]")).toBeNull();
  });
});
