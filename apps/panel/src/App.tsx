import { useCallback, useEffect, useState } from "react";
import { parseInventory, type Inventory } from "@verax-ai/galaxy";
import { Observatory, type Healthz, type LedgerError } from "./observatory/Observatory.tsx";
import { loadDemoActions, loadDemoApprovals, loadDemoReconcile } from "./observatory/demo.ts";
import { parseLedger } from "./rail/parse.ts";
import type { PendingApproval, PolicyBundle, RailAction, RailFinding } from "./rail/types.ts";
import type { ReconcileCardReport } from "./ReconcileCard.tsx";
import { authorizedFetch, beginSession, sessionIssueError, sessionScopes } from "./session.ts";

type RailStatus = "loading" | "ok" | "error" | "empty";

const STALE_MS = 30_000;
const REFRESH_MS = 5_000;

function wantDemo(): boolean {
  if (typeof window === "undefined") return false;
  return new URLSearchParams(window.location.search).get("demo") === "1";
}

export function App() {
  const [status, setStatus] = useState<RailStatus>("loading");
  const [actions, setActions] = useState<RailAction[]>([]);
  const [demo, setDemo] = useState(false);
  const [error, setError] = useState<LedgerError | null>(null);
  const [lastReadMs, setLastReadMs] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [reconcileReport, setReconcileReport] = useState<ReconcileCardReport | null>(null);
  const [health, setHealth] = useState<Healthz>(null);
  const [pending, setPending] = useState<PendingApproval[]>([]);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [canApprove, setCanApprove] = useState(false);

  const loadInventory = useCallback(async () => {
    try {
      const invRes = await authorizedFetch("/api/inventory");
      if (!invRes.ok) {
        setInventory(null);
        return;
      }
      const invBody = (await invRes.json()) as { inventory?: unknown };
      const parsed = invBody.inventory == null ? null : parseInventory(invBody.inventory);
      setInventory(parsed && parsed.ok ? parsed.value : null);
    } catch {
      setInventory(null);
    }
  }, []);

  const loadHealth = useCallback(async () => {
    try {
      const r = await authorizedFetch("/healthz");
      if (!r.ok) {
        setHealth(null);
        return;
      }
      const body = (await r.json()) as Healthz;
      setHealth(body && typeof body === "object" ? body : null);
    } catch {
      setHealth(null);
    }
  }, []);

  const load = useCallback(async () => {
    if (wantDemo()) {
      // The sample scenario stands on its own flag, not on a failing request.
      // It used to survive only because an unauthorised /api/ledger took the
      // early return below; once the session worked, an empty real ledger
      // overwrote the sample and demo=1 showed nothing.
      if (actions.length === 0) {
        setActions(loadDemoActions());
        setPending(loadDemoApprovals());
        setReconcileReport(loadDemoReconcile());
        setDemo(true);
        setStatus("ok");
        setLastReadMs(Date.now());
      }
      return;
    }
    await loadInventory();
    // The status tab counts decisions out of /healthz and witnesses out of
    // the rows it has. Read once at mount, those two disagreed the moment a
    // decision landed: the sentence said eight while the list showed nine.
    // They are read together now, so the tab is one reading of one ledger.
    await loadHealth();
    try {
      const r = await authorizedFetch("/api/ledger?from=0&to=9999999999999");
      if (!r.ok) {
        let detail = "";
        try {
          const errBody = (await r.json()) as { error?: unknown };
          if (typeof errBody.error === "string") detail = errBody.error;
        } catch {
          detail = "";
        }
        if (wantDemo()) {
          return;
        }
        setStatus("error");
        setError({ code: "http", status: r.status, detail: detail || null });
        return;
      }
      let body: {
        decisions?: unknown[];
        effects?: unknown[];
        policies?: Record<string, PolicyBundle["document"]>;
        policy?: PolicyBundle;
        inputs?: Record<string, import("./rail/types.ts").RailInputs>;
        approvals?: PendingApproval[];
      };
      try {
        body = (await r.json()) as typeof body;
      } catch {
        setStatus("error");
        setError({ code: "invalid-json", detail: null });
        return;
      }
      const decisions = Array.isArray(body.decisions) ? body.decisions : [];
      const effects = Array.isArray(body.effects) ? body.effects : [];
      const parsed = parseLedger(
        decisions.map((x) => JSON.stringify(x)).join("\n"),
        effects.map((x) => JSON.stringify(x)).join("\n"),
        body.policies ?? null,
        body.inputs ?? null,
      );
      setLastReadMs(Date.now());
      setError(null);
      setDemo(false);
      if (parsed.length === 0) {
        setActions([]);
        setPending(Array.isArray(body.approvals) ? body.approvals : []);
        setStatus("empty");
        return;
      }
      setActions(parsed);
      setPending(Array.isArray(body.approvals) ? body.approvals : []);
      setStatus("ok");
    } catch {
      setStatus("error");
      setError({ code: "network", detail: null });
    }
  }, [actions.length, loadHealth, loadInventory]);

  useEffect(() => {
    let cancelled = false;
    let id: ReturnType<typeof setInterval> | undefined;
    void (async () => {
      const phase = await beginSession();
      if (cancelled || phase === "redirect") return;
      if (phase === "error") {
        setStatus("error");
        // sessionIssueError() is the machine's own words; the sentence
        // around them comes from the copy table, like every other line.
        setError({ code: "session", detail: sessionIssueError() });
        return;
      }
      setCanApprove(phase === "demo" || sessionScopes().has("verax:approve"));
      void load();
      id = setInterval(() => {
        void load();
      }, REFRESH_MS);
    })();
    return () => {
      cancelled = true;
      if (id) clearInterval(id);
    };
  }, [load]);

  useEffect(() => {
    if (wantDemo()) return;
    void (async () => {
      try {
        const r = await fetch("/reconcile-report.json");
        if (!r.ok) {
          setReconcileReport(null);
          return;
        }
        const body = (await r.json()) as ReconcileCardReport;
        if (body?.scope && typeof body.scope.channel === "string" && Array.isArray(body.ghost)) {
          setReconcileReport(body);
        } else {
          setReconcileReport(null);
        }
      } catch {
        setReconcileReport(null);
      }
    })();
  }, []);

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1_000);
    return () => clearInterval(id);
  }, []);

  const ageMs = lastReadMs === null ? null : nowMs - lastReadMs;
  const stale = ageMs !== null && ageMs > STALE_MS;

  return (
    <main className="shell observatory-shell">
      <Observatory
        actions={actions}
        status={status}
        demo={demo}
        health={health}
        reconcile={reconcileReport}
        error={error}
        canApprove={canApprove}
        onApprove={async (ref, requestHash) => {
          const res = await authorizedFetch("/api/approve", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ ref, requestHash }),
          });
          const body = (await res.json().catch(() => ({}))) as {
            allowRef?: unknown;
            error?: unknown;
          };
          if (res.ok && typeof body.allowRef === "string") {
            // The approval changed the ledger; the screen reads it again
            // rather than drawing what it assumes happened.
            void load();
            return { ok: true as const, allowRef: body.allowRef };
          }
          return {
            ok: false as const,
            error: typeof body.error === "string" ? body.error : `http-${res.status}`,
          };
        }}
        stale={stale}
        ageMs={ageMs}
        pending={pending}
        inventory={inventory}
        nowMs={nowMs}
        onRefresh={() => void load()}
        onShowDemo={() => {
          setActions(loadDemoActions());
          setPending(loadDemoApprovals());
          setReconcileReport(loadDemoReconcile());
          setDemo(true);
        }}
        onContest={async (ref) => {
          const res = await authorizedFetch(`/api/contest/${encodeURIComponent(ref)}`, { method: "POST" });
          const body = (await res.json().catch(() => ({}))) as {
            reAuditedAt?: number;
            finding?: RailFinding;
            guarantee?: "unconditional" | "conditional";
            warnings?: { id: string; code: string; detail?: string }[];
            witnessClass?: string | null;
            trustRoot?: { pinned: boolean; issuerMatches: boolean | null; source: "env" | "own-key" | null };
            pair?: { defer: { decision: string; reasonCode: string } | null; resolution: { decision: string; reasonCode: string } | null };
          };
          if (!res.ok || typeof body.reAuditedAt !== "number") {
            return { error: `re-audit failed (${res.status})` };
          }
          return body;
        }}
      />
    </main>
  );
}
