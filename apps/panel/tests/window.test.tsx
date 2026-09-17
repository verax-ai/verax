// The panel used to ask the body for the whole ledger every five seconds and
// draw every row. Measured on 17 Sep 2026 with 100k decisions: 345 MB per
// poll, 26 s to first paint, the main thread busy 91% of the time. Now it
// asks for the newest page, polls for what is new since the newest row it
// holds, and offers the older pages on request.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import { mergeActions } from "../src/rail/merge.ts";
import { parseLedger, parseLedgerRows } from "../src/rail/parse.ts";
import type { PolicyBundle, RailDecision, RailEffect } from "../src/rail/types.ts";
import { rememberToken } from "../src/session.ts";
import { setLang } from "./with-lang.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const golden = join(root, "packages", "proxy", "tests", "fixtures", "ledger-golden");
const policy = JSON.parse(
  readFileSync(join(root, "packages", "proxy", "policy", "default.json"), "utf8"),
) as PolicyBundle["document"];

/** Stamps sit at a real epoch so "a minute before the newest" is not clamped to zero. */
const T = 1_700_000_000_000;

function decision(ref: string, offsetMs: number): RailDecision {
  return {
    claims: {
      subject: "memory.get",
      decision: "allow",
      reasonCode: "allow",
      timestampMs: T + offsetMs,
      decider: "verax-proxy",
      ref,
      policyHash: "aaa",
      effectHash: null,
    },
  } as RailDecision;
}

function stubFetch(ledger: (url: string) => Response): string[] {
  const ledgerUrls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      if (url.includes("reconcile-report")) return new Response("missing", { status: 404 });
      if (url.includes("/api/inventory")) return new Response(JSON.stringify({ inventory: null }), { status: 200 });
      if (url.includes("/healthz")) return new Response(JSON.stringify({ ok: true, decisions: 5, effects: 0 }), { status: 200 });
      if (url.includes("/api/agents")) {
        return new Response(JSON.stringify({ fromMs: 0, toMs: 0, agents: [], unattributed: 0 }), { status: 200 });
      }
      ledgerUrls.push(url);
      return ledger(url);
    }),
  );
  return ledgerUrls;
}

function param(url: string, name: string): string | null {
  return new URL(url, "http://panel.test").searchParams.get(name);
}

afterEach(() => {
  cleanup();
  rememberToken(null);
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

beforeEach(() => {
  setLang("tr");
  rememberToken("test-session");
});

describe("parseLedgerRows", () => {
  it("reads rows the way parseLedger reads lines", () => {
    const decisionsText = readFileSync(join(golden, "decisions.jsonl"), "utf8");
    const effectsText = readFileSync(join(golden, "effects.jsonl"), "utf8");
    const rows = (text: string) => text.split("\n").filter((l) => l !== "").map((l) => JSON.parse(l) as unknown);
    const bundle = { hash: "fixture", document: policy };
    expect(parseLedgerRows(rows(decisionsText) as RailDecision[], rows(effectsText) as RailEffect[], bundle)).toEqual(
      parseLedger(decisionsText, effectsText, bundle),
    );
  });
});

describe("mergeActions", () => {
  it("keeps one row per ref, the incoming one, newest first", () => {
    const held = parseLedgerRows([decision("a", 1000), decision("b", 2000), decision("c", 3000)], [], null);
    const incoming = parseLedgerRows([decision("c", 3000), decision("d", 4000)], [], null);
    const merged = mergeActions(held, incoming);
    expect(merged.map((x) => x.record.claims.ref)).toEqual(["d", "c", "b", "a"]);
    expect(merged[1]).toBe(incoming[1]);
  });
});

describe("panel ledger window", () => {
  it("asks for the newest page, then the page before it on request", async () => {
    const urls = stubFetch((url) => {
      if (param(url, "to") === String(T + 1000)) {
        return new Response(
          JSON.stringify({ decisions: [decision("old-1", 400), decision("old-2", 700)], effects: [], more: false }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({ decisions: [decision("n-1", 1000), decision("n-2", 2000), decision("n-3", 3000)], effects: [], more: true }),
        { status: 200 },
      );
    });
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(3);
    });
    expect(param(urls[0]!, "limit")).toBe("200");
    const older = screen.getByRole("button", { name: "Daha eskileri göster" });
    fireEvent.click(older);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(5);
    });
    const pageRequest = urls.find((u) => param(u, "to") === String(T + 1000));
    expect(pageRequest).toBeTruthy();
    expect(param(pageRequest!, "limit")).toBe("200");
    expect(screen.queryByRole("button", { name: "Daha eskileri göster" })).toBeNull();
  });

  it("polls for what is new since the newest row it holds and merges without duplicates", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let polls = 0;
    const urls = stubFetch((url) => {
      if (param(url, "from") !== "0") {
        polls += 1;
        return new Response(
          JSON.stringify({ decisions: [decision("n-3", 3000), decision("n-4", 4000)], effects: [], more: false }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({ decisions: [decision("n-1", 1000), decision("n-2", 2000), decision("n-3", 3000)], effects: [], more: false }),
        { status: 200 },
      );
    });
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBe(3);
    });
    await vi.advanceTimersByTimeAsync(5_000);
    await waitFor(() => {
      expect(polls).toBeGreaterThan(0);
      expect(document.querySelectorAll(".record-row").length).toBe(4);
    });
    const poll = urls.find((u) => param(u, "from") !== "0");
    expect(param(poll!, "from")).toBe(String(T + 3000 - 60_000));
    expect(param(poll!, "limit")).toBeNull();
  });
});
