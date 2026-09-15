import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { panelCopy } from "../src/copy.ts";
import { rememberToken } from "../src/session.ts";
import { setLang } from "./with-lang.ts";

vi.mock("@verax-ai/galaxy/react", () => ({
  Galaxy: () => <div data-testid="galaxy-stage" />,
}));

const ledgerBody = { decisions: [], effects: [], policies: {}, inputs: {}, approvals: [] };

afterEach(() => {
  cleanup();
  rememberToken(null);
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

  it("confirms an approval in the sample scenario without talking to the body", async () => {
    vi.stubGlobal("location", {
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
      expect(document.querySelector(".record-row.defer")).toBeTruthy();
    });
    fireEvent.click(document.querySelector(".record-row.defer")!);
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome")).toBeTruthy();
    });
    const approveCalls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/approve"));
    expect(approveCalls.length).toBe(0);
    expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy()["approve.sample"]);
  });

  it("keeps an approval from the black box console off the body in the sample scenario too", async () => {
    vi.stubGlobal("location", {
      search: "?demo=1&lang=tr&tab=box",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign: vi.fn(),
    });
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(ledgerBody), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { App } = await import("../src/App.tsx");
    render(<App />);
    const console = () => screen.getByTestId("black-box").shadowRoot?.querySelector(".cx") as HTMLElement | null;
    await waitFor(() => {
      expect(console()?.querySelector(".button.blue")).toBeTruthy();
    });
    fireEvent.click(console()!.querySelector(".button.blue")!);
    fireEvent.click(console()!.querySelector(".button.blue")!);
    await waitFor(() => {
      expect(console()?.querySelector('[data-testid="box-approve-outcome"]')).toBeTruthy();
    });
    const approveCalls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/approve"));
    expect(approveCalls.length).toBe(0);
    expect(console()!.querySelector('[data-testid="box-approve-outcome"]')!.textContent).toBe(panelCopy()["approve.sample"]);
  });

  it("says the English sample sentence when the sample is in English", async () => {
    vi.stubGlobal("location", {
      search: "?demo=1&lang=en",
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
      expect(document.querySelector(".record-row.defer")).toBeTruthy();
    });
    fireEvent.click(document.querySelector(".record-row.defer")!);
    fireEvent.click(screen.getByRole("button", { name: panelCopy("en")["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy("en")["approve.yes"] }));
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome")).toBeTruthy();
    });
    expect(fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/approve")).length).toBe(0);
    expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy("en")["approve.sample"]);
  });

  it("keeps the sample opened from the error screen off the network too", async () => {
    // No demo=1 in the address: the operator reached the sample through the
    // button a failing ledger offers. Checking the address alone let this
    // confirmation post a sample ref to the real body.
    rememberToken(`x.${btoa(JSON.stringify({ scope: "verax:audit verax:approve" }))}.y`);
    const fetchMock = vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      if (url.includes("/api/ledger")) {
        return new Response(JSON.stringify({ error: "fault" }), { status: 500 });
      }
      if (url.includes("/api/approve")) {
        return new Response(JSON.stringify({ error: "unknown-ref" }), { status: 404 });
      }
      return new Response("{}", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { App } = await import("../src/App.tsx");
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: panelCopy()["showDemo"] }));
    await waitFor(() => {
      expect(document.querySelector(".record-row.defer")).toBeTruthy();
    });
    fireEvent.click(document.querySelector(".record-row.defer")!);
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).not.toBe("");
    });
    expect(fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/approve")).length).toBe(0);
    expect(screen.getByTestId("approve-outcome").textContent).toBe(panelCopy()["approve.sample"]);
  });
});
