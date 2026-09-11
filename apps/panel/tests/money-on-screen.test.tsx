import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Observatory } from "../src/observatory/Observatory.tsx";
import { loadDemoActions, loadDemoApprovals } from "../src/observatory/demo.ts";
import { formatMinor } from "../src/records/money.ts";
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

/**
 * The hundred-times fault has been found twice: once on the record screen and
 * once on the status tab, and both times the file that had it was consistent
 * with itself while three tests froze the wrong number in place.
 *
 * The guard written after that reads the sources: a panel file that touches an
 * amount has to mention formatMinor somewhere in it. That is cheap and it is
 * holed - a file can satisfy it and still print a raw number in one of its
 * three branches, and a row whose field is not called `amount` slips past it
 * entirely.
 *
 * This asks the screens instead. One approval, three places that draw its
 * amount, and the number the ledger actually stores: the ledger says 1000, the
 * operator must read 10,00, and the stored number must appear nowhere.
 */
describe("one stored amount, three screens", () => {
  const approvals = loadDemoApprovals();
  const stored = approvals[0]!;
  const minor = Number(stored.amount);
  const money = formatMinor(minor, stored.currency, "tr");

  // The sample approval is already resolved, so the status tab lists nothing.
  // A pending twin of the same row puts the same amount on that tab too.
  const withPending: PendingApproval[] = [
    ...approvals,
    { ...stored, ref: `${stored.ref}-open`, status: "pending", allowRef: undefined },
  ];

  function draw() {
    render(<Observatory actions={loadDemoActions()} pending={withPending} status="ok" demo />);
  }

  it("agrees with the ledger about what the amount is", () => {
    // Not the formatter's opinion of itself: 1000 minor units of a two-decimal
    // currency is ten lira, and the test says so in its own words.
    expect(minor).toBe(1000);
    expect(money).toMatch(/10[.,]00/);
  });

  it("draws it as money on the record line, in the detail, and on the status tab", () => {
    draw();
    const line = screen.getByTestId("record-list").textContent ?? "";
    const detail = screen.getByTestId("spend-fields").textContent ?? "";
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    const status = screen.getByTestId("pending-approvals").textContent ?? "";

    for (const [where, text] of [
      ["record line", line],
      ["detail", detail],
      ["status tab", status],
    ] as const) {
      expect(text, `${where} does not print the amount as money`).toContain(money!);
      expect(text, `${where} prints the stored minor units raw`).not.toMatch(
        new RegExp(`(^|[^\\d])${minor}([^\\d]|$)`),
      );
    }
  });
});
