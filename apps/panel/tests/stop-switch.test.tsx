import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { StopSwitch, type HaltState } from "../src/StopSwitch.tsx";
import { panelCopy } from "../src/copy.ts";
import { setLang } from "./with-lang.ts";

afterEach(() => {
  cleanup();
});

beforeEach(() => {
  setLang("tr");
});

const running: HaltState = { halted: false };
const halted: HaltState = { halted: true, since: { atMs: 1_788_800_000_000, by: "operator-7", via: "http" } };

describe("stop switch", () => {
  it("draws nothing until the body has said whether it is halted", () => {
    const { container } = render(
      <StopSwitch state={null} canResume onHalt={vi.fn()} onResume={vi.fn()} />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("asks once before stopping, and a cancel sends nothing", async () => {
    const copy = panelCopy();
    const onHalt = vi.fn(async () => ({ ok: true as const, state: halted }));
    render(<StopSwitch state={running} canResume onHalt={onHalt} onResume={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: copy["stop.button"] }));
    expect(screen.getByTestId("stop-confirm").textContent).toContain(copy["stop.explain"]);
    fireEvent.click(screen.getByRole("button", { name: copy["stop.no"] }));
    expect(onHalt).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: copy["stop.button"] }));
    fireEvent.click(screen.getByRole("button", { name: copy["stop.yes"] }));
    await waitFor(() => expect(onHalt).toHaveBeenCalledTimes(1));
  });

  it("says who stopped it, and offers resume only to a session that can approve", () => {
    const copy = panelCopy();
    const { rerender } = render(
      <StopSwitch state={halted} canResume={false} onHalt={vi.fn()} onResume={vi.fn()} />,
    );
    const bar = screen.getByTestId("stop-halted");
    expect(bar.textContent).toContain(copy["stop.halted"]);
    expect(bar.textContent).toContain("operator-7");
    expect(screen.queryByRole("button", { name: copy["stop.resume"] })).toBeNull();
    expect(bar.textContent).toContain(copy["stop.resume.needApprove"]);

    rerender(<StopSwitch state={halted} canResume onHalt={vi.fn()} onResume={vi.fn()} />);
    expect(screen.getByRole("button", { name: copy["stop.resume"] })).toBeTruthy();
  });

  it("shows the body's refusal instead of assuming the press worked", async () => {
    const copy = panelCopy();
    const onResume = vi.fn(async () => ({ ok: false as const, error: "scope-missing" }));
    render(<StopSwitch state={halted} canResume onHalt={vi.fn()} onResume={onResume} />);

    fireEvent.click(screen.getByRole("button", { name: copy["stop.resume"] }));
    fireEvent.click(screen.getByRole("button", { name: copy["stop.resume.yes"] }));
    await waitFor(() => expect(screen.getByTestId("stop-halted").textContent).toContain("scope-missing"));
    expect(screen.getByTestId("stop-halted").textContent).toContain(copy["stop.halted"]);
  });
});
