import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseLedger } from "../src/rail/parse.ts";
import { Rail } from "../src/rail/Rail.tsx";
import type { PolicyBundle } from "../src/rail/types.ts";

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

afterEach(() => {
  cleanup();
});

describe("account-for rail", () => {
  it("renders six actions from the golden ledger", () => {
    render(<Rail actions={actions} />);
    expect(document.querySelectorAll(".row").length).toBe(6);
  });

  it("shows Contest on a deny row", () => {
    render(<Rail actions={actions} />);
    fireEvent.click(screen.getByRole("button", { name: /spend deny/i }));
    expect(screen.getByRole("button", { name: "Contest" })).toBeTruthy();
  });

  it("keeps questions 3 and 4 visible", () => {
    render(<Rail actions={actions} />);
    expect(screen.getByText("not tracked yet")).toBeTruthy();
    expect(screen.getByText("not connected")).toBeTruthy();
  });

  it("P2-11: a 401 contest shows re-audit failed, not re-audited at", async () => {
    const onContest = vi.fn(async () => ({ error: "re-audit failed (401)" }));
    render(<Rail actions={actions} onContest={onContest} />);
    fireEvent.click(screen.getByRole("button", { name: "Contest" }));
    await waitFor(() => {
      expect(screen.getByText("re-audit failed (401)")).toBeTruthy();
    });
    expect(screen.queryByText(/re-audited at/)).toBeNull();
  });

  it("POSTs contest with the open ref", async () => {
    const onContest = vi.fn(async () => ({ reAuditedAt: 123 }));
    render(<Rail actions={actions} onContest={onContest} />);
    fireEvent.click(screen.getByRole("button", { name: "Contest" }));
    expect(onContest).toHaveBeenCalled();
    const ref = onContest.mock.calls[0]?.[0];
    expect(typeof ref).toBe("string");
    expect((ref as string).length).toBeGreaterThan(0);
  });
});
