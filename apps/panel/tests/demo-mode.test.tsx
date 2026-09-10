import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setLang } from "./with-lang.ts";

vi.mock("@verax-ai/galaxy/react", () => ({
  Galaxy: () => <div data-testid="galaxy-stage" />,
}));

const ledgerBody = { decisions: [], effects: [], policies: {}, inputs: {}, approvals: [] };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});

/**
 * The sample scenario used to survive only because the session was broken: an
 * unauthorised /api/ledger left the demo rows on screen. With the session
 * working, an empty real ledger overwrote the sample and demo=1 showed nothing.
 */
beforeEach(() => {
  setLang("tr");
});

describe("demo mode", () => {
  it("keeps the sample scenario when the real ledger is empty", async () => {
    vi.stubGlobal("location", {
      // The stub stands in for the whole address, so the language has to be
      // named here: setLang cannot reach a location that is not the real one.
      search: "?demo=1&lang=tr",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign: vi.fn(),
    });
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(ledgerBody), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { App } = await import("../src/App.tsx");
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("ÖRNEK SENARYO")).toBeTruthy();
    });
    await waitFor(() => {
      expect(screen.queryByTestId("galaxy-empty")).toBeNull();
    });
    const ledgerCalls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/ledger"));
    expect(ledgerCalls.length).toBe(0);
  });
});
