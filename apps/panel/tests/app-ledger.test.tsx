// What the panel does with the ledger it fetches, and which policy document a
// decision is read against. The rendering assertions that used to live here
// belonged to a rail component the app never mounted; they were moved onto the
// screen the operator can actually open before that component was deleted.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import { rememberToken } from "../src/session.ts";
import { parseLedger } from "../src/rail/parse.ts";
import type { PolicyBundle } from "../src/rail/types.ts";
import { setLang } from "./with-lang.ts";
import { panelCopy } from "../src/copy.ts";

vi.mock("@verax-ai/galaxy/react", () => ({
  Galaxy: () => <div data-testid="galaxy-stage" />,
}));

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
const histDecision = {
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


beforeEach(() => {
  setLang("tr");
});

describe("historical policy sentence", () => {
  it("uses the decision policyHash document, not a later live policy", () => {
    const parsed = parseLedger(
      JSON.stringify(histDecision),
      "",
      {
        aaa: { rules: [{ id: "memory-put", tool: "memory.put", text: "Sentence A" }] },
        bbb: { rules: [{ id: "memory-put", tool: "memory.put", text: "Sentence B" }] },
      },
    );
    expect(parsed[0]?.rule && "text" in parsed[0].rule ? parsed[0].rule.text : null).toBe("Sentence A");
  });
});

function stubLedgerFetch(
  handler: (url: string, init?: RequestInit) => Response | Promise<Response>,
) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("reconcile-report")) {
        return new Response("missing", { status: 404 });
      }
      if (url.includes("/api/inventory")) {
        return new Response(JSON.stringify({ inventory: null }), { status: 200 });
      }
      return handler(url, init);
    }),
  );
}

describe("panel ledger fetch states", () => {
  afterEach(() => {
    rememberToken(null);
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  beforeEach(() => {
    rememberToken("test-session");
  });

  it("shows error and the HTTP status when the ledger returns 500", async () => {
    stubLedgerFetch(() => new Response(JSON.stringify({ error: "fault" }), { status: 500 }));
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("deftere erişilemiyor")).toBeTruthy();
      expect(screen.getByText(/500/)).toBeTruthy();
    });
    expect(screen.queryByText("defter boş")).toBeNull();
    expect(document.querySelectorAll(".row").length).toBe(0);
  });

  it("shows empty when the ledger has no decisions or effects", async () => {
    stubLedgerFetch(() => new Response(JSON.stringify({ decisions: [], effects: [] }), { status: 200 }));
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("defter boş")).toBeTruthy();
    });
    expect(screen.queryByText("deftere erişilemiyor")).toBeNull();
  });

  it("keeps the last good rail when a later poll returns 500", async () => {
    const ledgerBody = {
      decisions: [histDecision],
      effects: [],
      policies: { aaa: { rules: [{ id: "memory-put", tool: "memory.put", text: "Sentence A" }] } },
    };
    const ledgerFetch = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(ledgerBody), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: "fault" }), { status: 500 }));
    stubLedgerFetch((url) => {
      if (url.includes("/healthz")) return new Response(JSON.stringify({ ok: true }), { status: 200 });
      return ledgerFetch();
    });
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getByRole("button", { name: "Yenile" }));
    await waitFor(() => {
      expect(screen.getByText("deftere erişilemiyor")).toBeTruthy();
      expect(document.querySelectorAll(".record-row").length).toBeGreaterThan(0);
    });
  });

  it("re-reads /healthz with the ledger, so the status tab counts one moment", async () => {
    // The status tab reads its totals from /healthz and its witness split
    // from the rows. /healthz was fetched once at mount and the rows every
    // five seconds, so one screen could print an old total beside a fresh
    // split. A refresh has to move both.
    let healthReads = 0;
    const ledgerBody = { decisions: [histDecision], effects: [], policies: {} };
    stubLedgerFetch((url) => {
      if (url.includes("/healthz")) {
        healthReads += 1;
        return new Response(JSON.stringify({ decisions: healthReads, effects: 0 }), { status: 200 });
      }
      return new Response(JSON.stringify(ledgerBody), { status: 200 });
    });
    render(<App />);
    await waitFor(() => {
      expect(healthReads).toBe(1);
    });
    fireEvent.click(screen.getByRole("button", { name: "Yenile" }));
    await waitFor(() => {
      expect(healthReads).toBe(2);
    });
  });

  it("posts the ref and the hash the screen showed, and re-reads after", async () => {
    // The button is drawn from the session's scopes and the call is made by
    // App; a test on the control alone would pass with this wiring missing.
    rememberToken(
      `x.${btoa(JSON.stringify({ scope: "verax:audit verax:approve" }))}.y`,
    );
    const pending = {
      ref: "d-open",
      requestHash: "cd".repeat(32),
      subject: "spend",
      ruleText: "Sample spend needs operator approval.",
      inputsSummary: { count: 0, ids: [] },
      amount: 1000,
      currency: "TRY",
      payee: "example-payee",
      expiresAtMs: 9_999_999_999_999,
      status: "pending",
      brain: "sample-brain",
    };
    let approveBody: Record<string, unknown> | null = null;
    let ledgerReads = 0;
    stubLedgerFetch((url, init) => {
      if (url.includes("/api/approve")) {
        approveBody = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
        return new Response(JSON.stringify({ allowRef: "a-9" }), { status: 200 });
      }
      if (url.includes("/healthz")) return new Response(JSON.stringify({}), { status: 200 });
      ledgerReads += 1;
      return new Response(
        JSON.stringify({ decisions: [histDecision], effects: [], policies: {}, approvals: [pending] }),
        { status: 200 },
      );
    });
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.button"] }));
    const before = ledgerReads;
    fireEvent.click(screen.getByRole("button", { name: panelCopy()["approve.yes"] }));
    await waitFor(() => {
      expect(approveBody).toEqual({ ref: "d-open", requestHash: "cd".repeat(32) });
    });
    await waitFor(() => {
      expect(screen.getByTestId("approve-outcome").textContent).toContain("a-9");
    });
    // The ledger changed; the screen reads it again instead of assuming.
    await waitFor(() => {
      expect(ledgerReads).toBeGreaterThan(before);
    });
  });

  it("draws no approve button for a session that cannot approve", async () => {
    // Mutation caught this gap: with App hard-wiring canApprove to true, every
    // other test here still passed. A read-only operator would have been shown
    // a button that answers 403 - a promise the screen cannot keep.
    rememberToken(`x.${btoa(JSON.stringify({ scope: "verax:audit" }))}.y`);
    const pending = {
      ref: "d-open",
      requestHash: "cd".repeat(32),
      subject: "spend",
      ruleText: "Sample spend needs operator approval.",
      inputsSummary: { count: 0, ids: [] },
      amount: 1000,
      currency: "TRY",
      payee: "example-payee",
      expiresAtMs: 9_999_999_999_999,
      status: "pending",
      brain: "sample-brain",
    };
    stubLedgerFetch((url) => {
      if (url.includes("/healthz")) return new Response(JSON.stringify({}), { status: 200 });
      return new Response(
        JSON.stringify({ decisions: [histDecision], effects: [], policies: {}, approvals: [pending] }),
        { status: 200 },
      );
    });
    render(<App />);
    await waitFor(() => {
      expect(document.querySelectorAll(".record-row").length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getByRole("tab", { name: "Genel durum" }));
    expect(screen.getByTestId("pending-approvals").textContent).toContain("d-open");
    expect(screen.queryByRole("button", { name: panelCopy()["approve.button"] })).toBeNull();
  });

  it("keeps data-status=error and no rows when fetch rejects", async () => {
    stubLedgerFetch(() => Promise.reject(new Error("offline")));
    render(<App />);
    await waitFor(() => {
      expect(document.querySelector("[data-status]")?.getAttribute("data-status")).toBe("error");
    });
    expect(document.querySelectorAll(".row").length).toBe(0);
    expect(screen.getByRole("button", { name: "Örnek senaryoyu göster" })).toBeTruthy();
  });

  it("shows error when the ledger body is not JSON", async () => {
    stubLedgerFetch(() => new Response("not-json {", { status: 200 }));
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("deftere erişilemiyor")).toBeTruthy();
    });
    expect(screen.queryByText("defter boş")).toBeNull();
    expect(document.querySelectorAll(".row").length).toBe(0);
  });
});
