import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Observatory } from "../src/observatory/Observatory.tsx";
import { panelCopy } from "../src/copy.ts";
import type { PendingApproval } from "../src/rail/types.ts";
import { setLang } from "./with-lang.ts";

afterEach(() => {
  cleanup();
});

beforeEach(() => {
  setLang("tr");
});

function row(ref: string, requestHash: string): PendingApproval {
  return {
    ref,
    requestHash,
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
}

const rowA = row("ref-a", "aa".repeat(32));
const rowB = row("ref-b", "bb".repeat(32));

function boxRoot() {
  const host = screen.getByTestId("black-box");
  const cx = host.shadowRoot?.querySelector(".cx");
  if (!(cx instanceof HTMLElement)) throw new Error("the black box drew nothing into its shadow root");
  return within(cx);
}

/**
 * The confirmation belongs to the row Approve was pressed on. When the row
 * on screen becomes a different request, the confirmation closes and Yes
 * does not approve that new row.
 */
describe("R11-2 approval confirmation stays on its row", () => {
  it("closes the black-box confirmation when the row changes from A to B and does not approve B", () => {
    const onApprove = vi.fn(async () => ({ ok: true as const, allowRef: "a-1" }));
    const view = render(
      <Observatory actions={[]} status="ok" demo={false} pending={[rowA]} canApprove onApprove={onApprove} />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Kara kutu" }));
    fireEvent.click(boxRoot().getByRole("button", { name: new RegExp(panelCopy()["approve.button"]) }));
    expect(boxRoot().getByTestId("box-approve-confirm")).toBeTruthy();
    expect(onApprove).not.toHaveBeenCalled();

    view.rerender(
      <Observatory actions={[]} status="ok" demo={false} pending={[rowB]} canApprove onApprove={onApprove} />,
    );
    const yes = boxRoot().queryByRole("button", { name: new RegExp(panelCopy()["approve.yes"]) });
    if (yes) fireEvent.click(yes);
    expect(onApprove).not.toHaveBeenCalled();
    expect(boxRoot().queryByTestId("box-approve-confirm")).toBeNull();
    expect(onApprove.mock.calls.some((call) => call[0] === "ref-b" || call[1] === rowB.requestHash)).toBe(false);
  });

  it("closes the list confirmation when the row changes from A to B and does not approve B", () => {
    const onApprove = vi.fn(async () => ({ ok: true as const, allowRef: "a-1" }));
    const view = render(
      <Observatory actions={[]} status="ok" demo={false} pending={[rowA]} canApprove onApprove={onApprove} />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    expect(screen.getByTestId("approve-confirm")).toBeTruthy();

    view.rerender(
      <Observatory actions={[]} status="ok" demo={false} pending={[rowB]} canApprove onApprove={onApprove} />,
    );
    const yes = screen.queryByRole("button", { name: panelCopy()["approve.yes"] });
    if (yes) fireEvent.click(yes);
    expect(onApprove).not.toHaveBeenCalled();
    expect(screen.queryByTestId("approve-confirm")).toBeNull();
    expect(onApprove.mock.calls.some((call) => call[0] === "ref-b")).toBe(false);
  });

  it("while Yes is in flight for A, a change to B does not send B", async () => {
    let release: (value: { ok: true; allowRef: string }) => void = () => {};
    const onApprove = vi.fn(
      () =>
        new Promise<{ ok: true; allowRef: string }>((resolve) => {
          release = resolve;
        }),
    );
    const view = render(
      <Observatory actions={[]} status="ok" demo={false} pending={[rowA]} canApprove onApprove={onApprove} />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Kara kutu" }));
    fireEvent.click(boxRoot().getByRole("button", { name: new RegExp(panelCopy()["approve.button"]) }));
    fireEvent.click(boxRoot().getByRole("button", { name: new RegExp(panelCopy()["approve.yes"]) }));
    expect(onApprove).toHaveBeenCalledTimes(1);
    expect(onApprove).toHaveBeenCalledWith("ref-a", rowA.requestHash);

    view.rerender(
      <Observatory actions={[]} status="ok" demo={false} pending={[rowB]} canApprove onApprove={onApprove} />,
    );
    const yes = boxRoot().queryByRole("button", { name: new RegExp(panelCopy()["approve.yes"]) });
    if (yes) fireEvent.click(yes);
    expect(onApprove).toHaveBeenCalledTimes(1);
    expect(onApprove.mock.calls.some((call) => call[0] === "ref-b")).toBe(false);
    release({ ok: true, allowRef: "a-1" });
  });
});
