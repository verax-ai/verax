import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { demoAgents, loadDemoActions, loadDemoAgents } from "../src/observatory/demo.ts";
import type { PendingApproval, RailAction } from "../src/rail/types.ts";
import { rememberToken } from "../src/session.ts";
import { setLang } from "./with-lang.ts";

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
  setLang("tr");
});

function action(brain: string | null, decision: string, timestampMs: number): RailAction {
  return {
    record: { claims: { decision, timestampMs, subject: "spend", ref: `r-${timestampMs}` } },
    effect: null,
    rule: null,
    finding: null,
    inputs: brain === null ? null : { principal: { brain, scopes: [] }, inputs: [] },
  } as unknown as RailAction;
}

function approval(brain: string, status: PendingApproval["status"]): PendingApproval {
  return {
    ref: `a-${brain}-${status}`,
    requestHash: "0".repeat(64),
    subject: "spend",
    ruleText: null,
    inputsSummary: { count: 0, ids: [] },
    expiresAtMs: 0,
    status,
    brain,
  };
}

/**
 * The published sample had no agents table at all: the table reads /api/agents
 * and the sample asks no body for anything, so the screen on the site showed
 * less than the product and said nothing about why. The rows are counted off
 * the sample instead. These hold the arithmetic to the same rule the body
 * uses, so the demo cannot start stating numbers the sample does not carry.
 */
describe("agents counted off the sample", () => {
  it("counts a decision under the brain its inputs document names", () => {
    const answer = demoAgents([action("a", "allow", 10), action("a", "deny", 20)], []);
    expect(answer.agents.length).toBe(1);
    expect(answer.agents[0]).toMatchObject({ brain: "a", decisions: 2, allowed: 1, denied: 1, lastMs: 20 });
  });

  it("files a decision with no inputs document as unattributed, not under a guessed name", () => {
    const answer = demoAgents([action(null, "allow", 10), action("a", "allow", 20)], []);
    expect(answer.unattributed).toBe(1);
    expect(answer.agents.map((r) => r.brain)).toEqual(["a"]);
  });

  it("counts only approvals still pending", () => {
    const answer = demoAgents([action("a", "defer", 10)], [approval("a", "pending"), approval("a", "approved")]);
    expect(answer.agents[0]!.pending).toBe(1);
  });

  it("gives a brain a row even when its only trace is a pending approval", () => {
    const answer = demoAgents([], [approval("ghost", "pending")]);
    expect(answer.agents.map((r) => r.brain)).toEqual(["ghost"]);
    expect(answer.agents[0]).toMatchObject({ decisions: 0, pending: 1, lastMs: null });
  });

  it("puts the brain that is waiting on an operator first", () => {
    const answer = demoAgents(
      [action("quiet", "allow", 99), action("waiting", "defer", 1)],
      [approval("waiting", "pending")],
    );
    expect(answer.agents.map((r) => r.brain)).toEqual(["waiting", "quiet"]);
  });

  it("spans the window from the oldest attributed decision to the newest", () => {
    const answer = demoAgents([action("a", "allow", 500), action("a", "allow", 100)], []);
    expect(answer.fromMs).toBe(100);
    expect(answer.toMs).toBe(500);
  });

  it("leaves roster null, because the sample reads no inventory", () => {
    for (const row of loadDemoAgents().agents) expect(row.roster).toBeNull();
  });

  it("the shipped sample carries the two brains the status rail names", () => {
    const answer = loadDemoAgents();
    expect(answer.agents.map((r) => r.brain).sort()).toEqual(["brain-1", "sample-brain"]);
    expect(answer.agents.reduce((n, r) => n + r.decisions, 0)).toBeGreaterThan(0);
  });
});

describe("the sample's status tab", () => {
  it("draws the agents table without asking a body for it", async () => {
    vi.stubGlobal("location", {
      search: "?demo=1&lang=tr&tab=status",
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
      expect(screen.getByTestId("agents-table")).toBeTruthy();
    });
    const rows = document.querySelectorAll(".agent-row");
    expect(rows.length).toBe(2);
    expect(screen.getByTestId("agents-table").textContent).toContain("sample-brain");
    const agentCalls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/api/agents"));
    expect(agentCalls.length).toBe(0);
  });

  /**
   * One golden row is stamped at the epoch, so the window the sample spans is
   * fifty-six years. A body says "last 24 hours" because it was asked for a
   * window; the sample was asked for nothing, and "last 496889 hours" is a
   * number a reader can only read as a bug.
   */
  it("says it is the sample instead of measuring a window nobody asked for", async () => {
    vi.stubGlobal("location", {
      search: "?demo=1&lang=tr&tab=status",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign: vi.fn(),
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(ledgerBody), { status: 200 })));
    const { App } = await import("../src/App.tsx");
    render(<App />);
    await waitFor(() => {
      expect(screen.getByTestId("agents")).toBeTruthy();
    });
    const heading = screen.getByTestId("agents").querySelector("h3")!.textContent ?? "";
    expect(heading).toContain("örnek senaryo");
    expect(heading).not.toMatch(/saat/);
  });

  it("counts the same decisions the status sentence counts", () => {
    const answer = loadDemoAgents();
    const total = answer.agents.reduce((n, r) => n + r.decisions, 0) + answer.unattributed;
    expect(total).toBe(loadDemoActions().length);
  });
});
