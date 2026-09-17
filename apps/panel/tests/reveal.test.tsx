// The records list draws the first hundred of the rows it holds and reveals
// the next hundred as the reader reaches the end, so that loading older
// pages (200 rows each) never puts thousands of rows into the document at
// once. Measured on 17 Sep 2026: ten thousand rows drawn at once cost 122k
// DOM nodes and 1.8 s before the first paint. Where the browser cannot
// watch the scroll (no IntersectionObserver, as in this test's DOM) a
// button at the end of the list does the same job.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import type { RailDecision, RailInputs } from "../src/rail/types.ts";
import { rememberToken } from "../src/session.ts";
import { setLang } from "./with-lang.ts";

const T = 1_700_000_000_000;
const N = 350;

function decision(i: number): RailDecision {
  return {
    claims: {
      subject: "memory.get",
      decision: "allow",
      reasonCode: "allow",
      timestampMs: T + i * 1000,
      decider: "verax-proxy",
      ref: `d-${i}`,
      policyHash: "aaa",
      effectHash: null,
    },
  } as RailDecision;
}

const decisions = Array.from({ length: N }, (_, i) => decision(i));
const inputs: Record<string, RailInputs> = Object.fromEntries(
  decisions.map((d, i) => [
    d.claims.ref,
    { principal: { brain: i % 10 === 0 ? "agent-ten" : "agent-rest", scopes: [] }, inputs: [] } as unknown as RailInputs,
  ]),
);

function stubFetch(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      if (url.includes("reconcile-report")) return new Response("missing", { status: 404 });
      if (url.includes("/api/inventory")) return new Response(JSON.stringify({ inventory: null }), { status: 200 });
      if (url.includes("/healthz")) return new Response(JSON.stringify({ ok: true, decisions: N, effects: 0 }), { status: 200 });
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

describe("records list reveals rows a hundred at a time", () => {
  it("draws the first hundred, reveals the rest on request, and starts over when the filter changes", async () => {
    stubFetch();
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(100);
    });
    // The summary counts what is loaded, not what is drawn.
    expect(screen.getByText("350 karar · 0 reddedildi · 0 onay bekliyor · ekstre bağlı değil")).toBeTruthy();
    const more = () => screen.getByRole("button", { name: /Daha fazla satır göster/ });
    expect(more().textContent).toBe("Daha fazla satır göster (250 satır daha)");
    fireEvent.click(more());
    expect(document.querySelectorAll(".record-row").length).toBe(200);
    fireEvent.click(more());
    fireEvent.click(more());
    expect(document.querySelectorAll(".record-row").length).toBe(350);
    expect(screen.queryByRole("button", { name: /Daha fazla satır göster/ })).toBeNull();

    // Narrowing to 35 rows needs no reveal; clearing the filter starts at a hundred again.
    fireEvent.change(screen.getByLabelText("Ajan"), { target: { value: "agent-ten" } });
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(35);
    });
    expect(screen.queryByRole("button", { name: /Daha fazla satır göster/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Süzgeci temizle" }));
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(100);
    });
    expect(more().textContent).toBe("Daha fazla satır göster (250 satır daha)");
  });
});
