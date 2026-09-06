import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import { parseLedger } from "../src/rail/parse.ts";
import { Rail } from "../src/rail/Rail.tsx";
import type { PolicyBundle } from "../src/rail/types.ts";

vi.mock("@verax-ai/presence", () => ({
  Stage: () => <div data-testid="stage" />,
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

describe("account-for rail", () => {
  it("renders six actions from the golden ledger", () => {
    render(<Rail actions={actions} />);
    expect(document.querySelectorAll(".row").length).toBe(6);
  });

  it("shows Contest on a deny row", () => {
    render(<Rail actions={actions} />);
    fireEvent.click(screen.getByRole("button", { name: /spend deny/i }));
    expect(screen.getByRole("button", { name: "Contest" })).toBeTruthy();
  });

  it("keeps questions 3 and 4 visible", () => {
    render(<Rail actions={actions} />);
    expect(screen.getByText("not tracked yet")).toBeTruthy();
    expect(screen.getByText("not connected")).toBeTruthy();
  });

  it("P2-11: a 401 contest shows re-audit failed, not re-audited at", async () => {
    const onContest = vi.fn(async () => ({ error: "re-audit failed (401)" }));
    render(<Rail actions={actions} onContest={onContest} />);
    fireEvent.click(screen.getByRole("button", { name: "Contest" }));
    await waitFor(() => {
      expect(screen.getByText("re-audit failed (401)")).toBeTruthy();
    });
    expect(screen.queryByText(/re-audited at/)).toBeNull();
  });

  it("POSTs contest with the open ref", async () => {
    const onContest = vi.fn(async () => ({ reAuditedAt: 123 }));
    render(<Rail actions={actions} onContest={onContest} />);
    fireEvent.click(screen.getByRole("button", { name: "Contest" }));
    expect(onContest).toHaveBeenCalled();
    const ref = onContest.mock.calls[0]?.[0];
    expect(typeof ref).toBe("string");
    expect((ref as string).length).toBeGreaterThan(0);
  });
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

describe("guarantee strip", () => {
  it("5: shows a general issuer warning on the rail", () => {
    const parsed = parseLedger(JSON.stringify(histDecision), "", {
      aaa: { rules: [{ id: "memory-put", tool: "memory.put", text: "Sentence A" }] },
    });
    parsed[0] = {
      ...parsed[0]!,
      guarantee: "conditional",
      warnings: [{ id: "issuer", code: "unauthenticated-issuer", detail: "issuer unpinned" }],
      witnessClass: null,
    };
    render(<Rail actions={parsed} />);
    expect(screen.getByText(/unauthenticated-issuer/)).toBeTruthy();
    expect(screen.getByText(/guarantee/i)).toBeTruthy();
  });

  it("shows pin: own key on the guarantee strip", () => {
    const parsed = parseLedger(JSON.stringify(histDecision), "", {
      aaa: { rules: [{ id: "memory-put", tool: "memory.put", text: "Sentence A" }] },
    });
    parsed[0] = {
      ...parsed[0]!,
      guarantee: "conditional",
      trustRoot: { pinned: true, issuerMatches: true, source: "own-key" },
    };
    render(<Rail actions={parsed} />);
    expect(screen.getByText(/pin: own key/)).toBeTruthy();
  });
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

  it("shows historical policy unavailable in red when the snapshot is missing", () => {
    const parsed = parseLedger(JSON.stringify(histDecision), "", {});
    render(<Rail actions={parsed} />);
    const line = screen.getByText("historical policy unavailable");
    expect(line.className).toMatch(/rule-missing/);
  });

  it("shows a red identity line when the hash is on the record but the document is not", () => {
    const parsed = parseLedger(
      JSON.stringify({
        claims: { ...histDecision.claims, inputsHash: "aa".repeat(32) },
      }),
      "",
      { aaa: { rules: [{ id: "memory-put", tool: "memory.put", text: "Sentence A" }] } },
    );
    parsed[0] = { ...parsed[0]!, inputs: undefined, inputsBound: false };
    render(<Rail actions={parsed} />);
    const line = screen.getByText("identity hash on the record; inputs document unavailable");
    expect(line.className).toMatch(/rule-missing/);
  });
});

function stubLedgerFetch(handler: (url: string) => Response | Promise<Response>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      if (url.includes("reconcile-report")) {
        return new Response("missing", { status: 404 });
      }
      return handler(url);
    }),
  );
}

describe("panel ledger fetch states", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("shows error and the HTTP status when the ledger returns 500", async () => {
    stubLedgerFetch(() => new Response(JSON.stringify({ error: "fault" }), { status: 500 }));
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("error")).toBeTruthy();
      expect(screen.getByText(/500/)).toBeTruthy();
    });
    expect(screen.queryByText("empty")).toBeNull();
    expect(document.querySelectorAll(".row").length).toBe(0);
  });

  it("shows empty when the ledger has no decisions or effects", async () => {
    stubLedgerFetch(() => new Response(JSON.stringify({ decisions: [], effects: [] }), { status: 200 }));
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("empty")).toBeTruthy();
    });
    expect(screen.queryByText("error")).toBeNull();
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
    stubLedgerFetch(() => ledgerFetch());
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "İşlem geçmişi" }));
    await waitFor(() => {
      expect(document.querySelectorAll(".row").length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => {
      expect(screen.getByText("error")).toBeTruthy();
      expect(document.querySelectorAll(".row").length).toBeGreaterThan(0);
    });
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
      expect(screen.getByText("error")).toBeTruthy();
    });
    expect(screen.queryByText("empty")).toBeNull();
    expect(document.querySelectorAll(".row").length).toBe(0);
  });
});
