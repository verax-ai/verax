// The status tab lists the agents: one row each, what it did in the last
// day, what is waiting on an operator for it, when it last acted, and what
// the roster says. The body computes the list (/api/agents); the screen
// draws it and says so when it could not be read.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import type { RailDecision } from "../src/rail/types.ts";
import { rememberToken } from "../src/session.ts";
import { setLang } from "./with-lang.ts";

const T = 1_700_000_000_000;

const oneDecision: RailDecision = {
  claims: {
    subject: "memory.get",
    decision: "allow",
    reasonCode: "allow",
    timestampMs: T,
    decider: "verax-proxy",
    ref: "d-1",
    policyHash: "aaa",
    effectHash: null,
  },
} as RailDecision;

const agentsAnswer = {
  fromMs: T - 86_400_000,
  toMs: T,
  unattributed: 0,
  agents: [
    { brain: "agent-a", decisions: 4, allowed: 2, denied: 1, deferred: 1, pending: 1, lastMs: T - 600_000, roster: { state: "live", label: "Agent A", group: "This PC" } },
    { brain: "agent-b", decisions: 2, allowed: 2, denied: 0, deferred: 0, pending: 0, lastMs: T - 1_200_000, roster: null },
    { brain: "agent-c", decisions: 0, allowed: 0, denied: 0, deferred: 0, pending: 0, lastMs: null, roster: { state: "unmonitored", label: "Agent C", group: null } },
  ],
};

function stubFetch(agents: () => Response): string[] {
  const urls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      urls.push(url);
      if (url.includes("reconcile-report")) return new Response("missing", { status: 404 });
      if (url.includes("/api/inventory")) return new Response(JSON.stringify({ inventory: null }), { status: 200 });
      if (url.includes("/healthz")) return new Response(JSON.stringify({ ok: true, decisions: 7, effects: 0 }), { status: 200 });
      if (url.includes("/api/agents")) return agents();
      return new Response(JSON.stringify({ decisions: [oneDecision], effects: [], more: false }), { status: 200 });
    }),
  );
  return urls;
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

describe("status tab agents", () => {
  it("draws one row per agent with its day, its waiting approvals and its roster state", async () => {
    const urls = stubFetch(() => new Response(JSON.stringify(agentsAnswer), { status: 200 }));
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(1);
    });
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    const table = await screen.findByTestId("agents-table");
    expect(urls.some((u) => u.includes("/api/agents"))).toBe(true);
    const rows = [...table.querySelectorAll<HTMLElement>("tr.agent-row")];
    expect(rows.length).toBe(3);
    const cells = (row: HTMLElement) => within(row).getAllByRole("cell").map((c) => c.textContent?.trim() ?? "");
    expect(cells(rows[0]!)).toEqual(["Agent A", "This PC", "canlı", "4", "1", "1", "2023-11-14T22:03:20Z"]);
    expect(cells(rows[1]!)).toEqual(["agent-b", "", "listede yok", "2", "0", "0", "2023-11-14T21:53:20Z"]);
    expect(cells(rows[2]!)).toEqual(["Agent C", "", "izlenmiyor", "0", "0", "0", "ölçülemedi"]);
    expect(screen.getByText("Ajanlar · son 24 saat · 3 ajan")).toBeTruthy();
  });

  it("folds the rows under their roster group, and a group can be closed and opened", async () => {
    stubFetch(() => new Response(JSON.stringify(agentsAnswer), { status: 200 }));
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(1);
    });
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    const table = await screen.findByTestId("agents-table");
    const headers = [...table.querySelectorAll<HTMLElement>("tr.agents-group button")].map((b) => b.textContent?.trim());
    expect(headers).toEqual(["This PC · 1 ajan · 1 bekleyen", "listede yok · 1 ajan · 0 bekleyen", "grupsuz · 1 ajan · 0 bekleyen"]);
    const thisPc = screen.getByRole("button", { name: "This PC · 1 ajan · 1 bekleyen" });
    expect(thisPc.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(thisPc);
    expect(table.querySelectorAll("tr.agent-row").length).toBe(2);
    expect(thisPc.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(thisPc);
    expect(table.querySelectorAll("tr.agent-row").length).toBe(3);
  });

  it("says the list could not be read instead of drawing an empty table", async () => {
    stubFetch(() => new Response(JSON.stringify({ error: "fault" }), { status: 500 }));
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(1);
    });
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    await waitFor(() => {
      expect(screen.getByText("ajan listesi okunamadı")).toBeTruthy();
    });
    expect(screen.queryByTestId("agents-table")).toBeNull();
  });
});
