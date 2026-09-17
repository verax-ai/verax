// The records list can be narrowed to one agent, one tool, one outcome, or a
// ref, over the rows the screen holds. A company's ledger has hundreds of
// agents in it; an operator looking for one should not have to read them all.
// Narrowing is on the screen, not in the body: what is on screen is the
// newest page plus the older pages asked for, and the line under the summary
// says how many of them are shown.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import { filterActions } from "../src/records/filter.ts";
import { parseLedgerRows } from "../src/rail/parse.ts";
import type { RailDecision, RailInputs } from "../src/rail/types.ts";
import { rememberToken } from "../src/session.ts";
import { setLang } from "./with-lang.ts";

const T = 1_700_000_000_000;

function decision(ref: string, subject: string, decisionKind: "allow" | "deny", offsetMs: number): RailDecision {
  return {
    claims: {
      subject,
      decision: decisionKind,
      reasonCode: decisionKind === "allow" ? "allow" : "scope-missing",
      timestampMs: T + offsetMs,
      decider: "verax-proxy",
      ref,
      policyHash: "aaa",
      effectHash: null,
    },
  } as RailDecision;
}

function inputsFor(brain: string): RailInputs {
  return { principal: { brain, scopes: ["verax:read"] }, inputs: [] } as unknown as RailInputs;
}

const decisions = [
  decision("d-1", "memory.get", "allow", 1000),
  decision("d-2", "memory.put", "allow", 2000),
  decision("d-3", "spend", "deny", 3000),
  decision("d-4", "memory.get", "deny", 4000),
];
const inputs: Record<string, RailInputs> = {
  "d-1": inputsFor("agent-a"),
  "d-2": inputsFor("agent-b"),
  "d-3": inputsFor("agent-a"),
  "d-4": inputsFor("agent-b"),
};

describe("filterActions", () => {
  const actions = parseLedgerRows(decisions, [], null, inputs);

  it("narrows by agent, tool, outcome and ref, and by all of them together", () => {
    const refs = (rows: ReturnType<typeof filterActions>) => rows.map((a) => a.record.claims.ref);
    expect(refs(filterActions(actions, [], { agent: "agent-a" }))).toEqual(["d-3", "d-1"]);
    expect(refs(filterActions(actions, [], { tool: "memory.get" }))).toEqual(["d-4", "d-1"]);
    expect(refs(filterActions(actions, [], { kind: "deny" }))).toEqual(["d-4", "d-3"]);
    expect(refs(filterActions(actions, [], { ref: "D-2" }))).toEqual(["d-2"]);
    expect(refs(filterActions(actions, [], { agent: "agent-b", tool: "memory.get", kind: "deny" }))).toEqual(["d-4"]);
    expect(refs(filterActions(actions, [], {}))).toEqual(["d-4", "d-3", "d-2", "d-1"]);
  });
});

function stubFetch(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      if (url.includes("reconcile-report")) return new Response("missing", { status: 404 });
      if (url.includes("/api/inventory")) return new Response(JSON.stringify({ inventory: null }), { status: 200 });
      if (url.includes("/healthz")) return new Response(JSON.stringify({ ok: true, decisions: 4, effects: 0 }), { status: 200 });
      if (url.includes("/api/agents")) {
        return new Response(JSON.stringify({ fromMs: 0, toMs: 0, agents: [], unattributed: 0 }), { status: 200 });
      }
      return new Response(JSON.stringify({ decisions, effects: [], inputs, more: false }), { status: 200 });
    }),
  );
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

describe("records filter bar", () => {
  it("narrows the list on screen and says how many of the loaded rows are shown", async () => {
    stubFetch();
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(4);
    });
    fireEvent.change(screen.getByLabelText("Ajan"), { target: { value: "agent-a" } });
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(2);
    });
    expect(screen.getByText("2 / 4 kayıt gösteriliyor")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Sonuç"), { target: { value: "deny" } });
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(1);
    });
    fireEvent.change(screen.getByPlaceholderText("ref ara"), { target: { value: "d-3" } });
    expect(document.querySelectorAll(".record-row").length).toBe(1);
    fireEvent.change(screen.getByPlaceholderText("ref ara"), { target: { value: "d-1" } });
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(0);
    });
    expect(screen.getByText("0 / 4 kayıt gösteriliyor")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Süzgeci temizle" }));
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(4);
    });
    expect(screen.queryByText(/kayıt gösteriliyor/)).toBeNull();
  });
});
