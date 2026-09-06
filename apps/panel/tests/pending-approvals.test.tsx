import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Observatory } from "../src/observatory/Observatory.tsx";
import type { PendingApproval } from "../src/rail/types.ts";

vi.mock("@verax-ai/presence", () => ({
  Stage: () => <div data-testid="stage" />,
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
    const list = screen.getByTestId("pending-approvals");
    expect(list.textContent).toMatch(/d1/);
    expect(list.textContent).toMatch(/Writes need operator approval/);
    expect(list.textContent).toMatch(/ads/);
    expect(document.body.textContent).not.toMatch(/hepsini onayla/i);
    expect(document.body.textContent).not.toMatch(/approve all/i);
    expect(document.querySelector("[data-approve-all]")).toBeNull();
    expect(document.querySelector("button[data-approve]")).toBeNull();
  });
});
