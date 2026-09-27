// A session without verax:audit makes every audit door answer 403
// scope-missing. That used to render as "the server answered 403", which
// tells a first run nothing about the passkey. These tests fail on that screen.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import { panelCopy } from "../src/copy.ts";
import { fillCopy } from "../src/fill.ts";
import { rememberToken } from "../src/session.ts";
import { setLang } from "./with-lang.ts";

const oneDecision = {
  claims: {
    subject: "memory.put",
    decision: "allow" as const,
    reasonCode: "allow",
    timestampMs: 1,
    decider: "verax-proxy",
    ref: "hist-1",
    policyHash: "aaa",
    effectHash: null,
  },
};

function http403(): string {
  return fillCopy(panelCopy()["error.http"], { code: 403 });
}

function installFetch(decide: (url: string, init?: RequestInit) => Response): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("reconcile-report")) return new Response("missing", { status: 404 });
      return decide(url, init);
    }),
  );
}

function okJson(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200 });
}

function denied(error: string): Response {
  return new Response(JSON.stringify({ error }), { status: 403 });
}

/** Doors other than the one under test answer as an open ledger. */
function openDoors(url: string): Response | null {
  if (url.includes("/api/agents")) return okJson({ fromMs: 0, toMs: 0, agents: [], unattributed: 0 });
  if (url.includes("/api/inventory")) return okJson({ inventory: null });
  if (url.includes("/healthz")) return okJson({ ok: true });
  return null;
}

afterEach(() => {
  cleanup();
  rememberToken(null);
  vi.unstubAllGlobals();
});

beforeEach(() => {
  setLang("tr");
  rememberToken("test-session");
});

describe("passkey required before the ledger", () => {
  it("renders the passkey state, not the generic 403, and sign-in restarts the code flow", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", {
      search: "?lang=tr",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    installFetch((url) => {
      if (url.includes("/api/ledger")) return denied("scope-missing");
      return openDoors(url) ?? new Response("{}", { status: 404 });
    });
    render(<App />);
    const box = await screen.findByTestId("passkey-required");
    expect(box.textContent).toContain(panelCopy()["passkey.needed"]);
    expect(box.textContent).toContain(panelCopy()["passkey.how"]);
    expect(box.textContent).toContain("verax operator enroll");
    expect(within(box).getByRole("button", { name: panelCopy()["passkey.signIn"] })).toBeTruthy();
    const statusLine = document.querySelector("[data-status=error]")?.textContent ?? "";
    expect(statusLine).toContain(panelCopy()["passkey.needed"]);
    expect(statusLine).not.toContain(http403());
    expect(document.body.textContent ?? "").not.toContain(http403());

    fireEvent.click(within(box).getByRole("button", { name: panelCopy()["passkey.signIn"] }));
    await waitFor(() => {
      expect(assign).toHaveBeenCalledTimes(1);
    });
    const dest = new URL(String(assign.mock.calls[0]![0]));
    expect(dest.pathname).toBe("/authorize");
    expect(dest.searchParams.get("response_type")).toBe("code");
    expect(dest.searchParams.get("scope")).toContain("verax:audit");
  });

  it("still renders the generic error for 403 origin-not-allowed", async () => {
    installFetch((url) => {
      if (url.includes("/api/ledger")) return denied("origin-not-allowed");
      return openDoors(url) ?? new Response("{}", { status: 404 });
    });
    render(<App />);
    await waitFor(() => {
      const statusLine = document.querySelector("[data-status=error]")?.textContent ?? "";
      expect(statusLine).toContain(http403());
      expect(statusLine).toContain("origin-not-allowed");
    });
    expect(screen.queryByTestId("passkey-required")).toBeNull();
  });

  it("still renders the generic error for 403 local-mode-operator-scope", async () => {
    installFetch((url) => {
      if (url.includes("/api/ledger")) return denied("local-mode-operator-scope");
      return openDoors(url) ?? new Response("{}", { status: 404 });
    });
    render(<App />);
    await waitFor(() => {
      const statusLine = document.querySelector("[data-status=error]")?.textContent ?? "";
      expect(statusLine).toContain(http403());
      expect(statusLine).toContain("local-mode-operator-scope");
    });
    expect(screen.queryByTestId("passkey-required")).toBeNull();
  });

  it("leaves demo mode on the sample scenario", async () => {
    vi.stubGlobal("location", {
      search: "?demo=1&lang=tr",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign: vi.fn(),
    });
    const fetchMock = vi.fn(async () => denied("scope-missing"));
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText(panelCopy()["badge.demo"])).toBeTruthy();
    });
    expect(screen.queryByTestId("passkey-required")).toBeNull();
    expect(document.body.textContent ?? "").not.toContain(http403());
    const ledgerCalls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/ledger"));
    expect(ledgerCalls.length).toBe(0);
  });

  it("shows the passkey state when the agents read answers 403 scope-missing", async () => {
    installFetch((url) => {
      if (url.includes("/api/agents")) return denied("scope-missing");
      if (url.includes("/api/ledger")) return okJson({ decisions: [oneDecision], effects: [] });
      return openDoors(url) ?? new Response("{}", { status: 404 });
    });
    render(<App />);
    const box = await screen.findByTestId("passkey-required");
    expect(box.textContent).toContain(panelCopy()["passkey.needed"]);
    expect(document.body.textContent ?? "").not.toContain(http403());
  });

  it("shows the passkey state when the inventory read answers 403 scope-missing", async () => {
    installFetch((url) => {
      if (url.includes("/api/inventory")) return denied("scope-missing");
      if (url.includes("/api/ledger")) return okJson({ decisions: [], effects: [] });
      return openDoors(url) ?? new Response("{}", { status: 404 });
    });
    render(<App />);
    const box = await screen.findByTestId("passkey-required");
    expect(box.textContent).toContain("verax operator enroll");
    expect(document.body.textContent ?? "").not.toContain(http403());
    expect(screen.queryByText(panelCopy()["status.empty"])).toBeNull();
  });

  it("shows the passkey state when contest answers 403 scope-missing", async () => {
    installFetch((url) => {
      if (url.includes("/api/contest/")) return denied("scope-missing");
      if (url.includes("/api/ledger")) return okJson({ decisions: [oneDecision], effects: [], policies: {} });
      return openDoors(url) ?? new Response("{}", { status: 404 });
    });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: panelCopy().inspect }));
    const box = await screen.findByTestId("passkey-required");
    expect(box.textContent).toContain(panelCopy()["passkey.needed"]);
    expect(document.body.textContent ?? "").not.toContain(http403());
  });
});
