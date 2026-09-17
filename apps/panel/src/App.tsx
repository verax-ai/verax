import { useCallback, useEffect, useRef, useState } from "react";
import { parseInventory, type Inventory } from "@verax-ai/inventory";
import { Observatory, type Healthz, type LedgerError } from "./observatory/Observatory.tsx";
import { loadDemoActions, loadDemoApprovals, loadDemoReconcile } from "./observatory/demo.ts";
import { mergeActions } from "./rail/merge.ts";
import { parseLedgerRows } from "./rail/parse.ts";
import type {
  AgentsAnswer,
  PendingApproval,
  PolicyBundle,
  RailAction,
  RailDecision,
  RailEffect,
  RailFinding,
} from "./rail/types.ts";
import type { ReconcileCardReport } from "./ReconcileCard.tsx";
import { authorizedFetch, beginSession, sessionIssueError, sessionScopes } from "./session.ts";

type RailStatus = "loading" | "ok" | "error" | "empty";

const STALE_MS = 30_000;
const REFRESH_MS = 5_000;
/** Rows per page. The newest page is what opens; older pages come on request. */
const PAGE = 200;
/**
 * How far behind the newest row held a poll starts. An effect lands a moment
 * after its decision, and a clock can be set back between two rows; a
 * minute of overlap catches both, and mergeActions folds the overlap away.
 */
const POLL_OVERLAP_MS = 60_000;
const END_OF_TIME = 9_999_999_999_999;

type LedgerBody = {
  decisions?: unknown[];
  effects?: unknown[];
  policies?: Record<string, PolicyBundle["document"]>;
  policy?: PolicyBundle;
  inputs?: Record<string, import("./rail/types.ts").RailInputs>;
  approvals?: PendingApproval[];
  more?: unknown;
};

function rowsOf(body: LedgerBody): RailAction[] {
  const decisions = Array.isArray(body.decisions) ? (body.decisions as RailDecision[]) : [];
  const effects = Array.isArray(body.effects) ? (body.effects as RailEffect[]) : [];
  return parseLedgerRows(decisions, effects, body.policies ?? null, body.inputs ?? null);
}

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
  // Whether the ledger goes on past the oldest row on screen.
  const [more, setMore] = useState(false);
  const [olderBusy, setOlderBusy] = useState(false);
  const pollRef = useRef<() => Promise<void>>(async () => undefined);
  // The agents list is the body's reading of its ledger and roster; the
  // screen draws it, and says so when it could not be read.
  const [agents, setAgents] = useState<AgentsAnswer | null>(null);
  const [agentsFailed, setAgentsFailed] = useState(false);

  const loadAgents = useCallback(async () => {
    try {
      const r = await authorizedFetch("/api/agents");
      if (!r.ok) {
        setAgents(null);
        setAgentsFailed(true);
        return;
      }
      const body = (await r.json()) as AgentsAnswer;
      if (body && Array.isArray(body.agents)) {
        setAgents(body);
        setAgentsFailed(false);
      } else {
        setAgents(null);
        setAgentsFailed(true);
      }
    } catch {
      setAgents(null);
      setAgentsFailed(true);
    }
  }, []);

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

  /**
   * One read of /api/ledger. Null when the screen already said what went
   * wrong; the caller decides what a good answer replaces.
   */
  const readLedger = useCallback(async (query: string): Promise<LedgerBody | null> => {
    const r = await authorizedFetch(`/api/ledger?${query}`);
    if (!r.ok) {
      let detail = "";
      try {
        const errBody = (await r.json()) as { error?: unknown };
        if (typeof errBody.error === "string") detail = errBody.error;
      } catch {
        detail = "";
      }
      if (wantDemo()) {
        return null;
      }
      setStatus("error");
      setError({ code: "http", status: r.status, detail: detail || null });
      return null;
    }
    try {
      return (await r.json()) as LedgerBody;
    } catch {
      setStatus("error");
      setError({ code: "invalid-json", detail: null });
      return null;
    }
  }, []);

  /** The newest page, replacing whatever the screen held. */
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
    await loadAgents();
    try {
      const body = await readLedger(`from=0&to=${END_OF_TIME}&limit=${PAGE}`);
      if (!body) return;
      const parsed = rowsOf(body);
      setLastReadMs(Date.now());
      setError(null);
      setDemo(false);
      setMore(body.more === true);
      setPending(Array.isArray(body.approvals) ? body.approvals : []);
      if (parsed.length === 0) {
        setActions([]);
        setStatus("empty");
        return;
      }
      setActions(parsed);
      setStatus("ok");
    } catch {
      setStatus("error");
      setError({ code: "network", detail: null });
    }
  }, [actions.length, loadAgents, loadHealth, loadInventory, readLedger]);

  /**
   * What is new since the newest row held, folded into the rows on screen.
   * Until the screen holds a row there is nothing to fold into: the newest
   * page is read instead. The body answers a window from the end of its
   * files, so this costs a minute of rows, not the ledger.
   */
  const poll = useCallback(async () => {
    if (wantDemo() || actions.length === 0) {
      await load();
      return;
    }
    await loadInventory();
    await loadHealth();
    await loadAgents();
    try {
      const newestMs = actions[0]!.record.claims.timestampMs;
      const body = await readLedger(`from=${Math.max(0, newestMs - POLL_OVERLAP_MS)}&to=${END_OF_TIME}`);
      if (!body) return;
      setLastReadMs(Date.now());
      setError(null);
      setPending(Array.isArray(body.approvals) ? body.approvals : []);
      const fresh = rowsOf(body);
      if (fresh.length > 0) setActions((held) => mergeActions(held, fresh));
      setStatus("ok");
    } catch {
      setStatus("error");
      setError({ code: "network", detail: null });
    }
  }, [actions, load, loadAgents, loadHealth, loadInventory, readLedger]);

  /** The page before the oldest row on screen, appended below it. */
  const loadOlder = useCallback(async () => {
    if (actions.length === 0 || olderBusy) return;
    setOlderBusy(true);
    try {
      const oldestMs = actions[actions.length - 1]!.record.claims.timestampMs;
      const body = await readLedger(`from=0&to=${oldestMs}&limit=${PAGE}`);
      if (!body) return;
      setMore(body.more === true);
      const older = rowsOf(body);
      if (older.length > 0) setActions((held) => mergeActions(held, older));
    } catch {
      setStatus("error");
      setError({ code: "network", detail: null });
    } finally {
      setOlderBusy(false);
    }
  }, [actions, olderBusy, readLedger]);

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
        void pollRef.current();
      }, REFRESH_MS);
    })();
    return () => {
      cancelled = true;
      if (id) clearInterval(id);
    };
    // The interval is set once, at session start; it reads the latest poll
    // through the ref rather than restarting whenever the rows change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    pollRef.current = poll;
  }, [poll]);

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
          // The sample scenario draws the same control so the operator can
          // see the ask. Confirming it must not talk to the body: a 401 on
          // a button that looks real is how this hole came back after #39.
          // The sample can also be opened from the error screen, with no
          // demo=1 in the address, so the screen's own flag decides.
          if (demo) {
            return { ok: false as const, error: "sample-not-sent" };
          }
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
        more={more}
        onOlder={() => void loadOlder()}
        agents={agents}
        agentsFailed={agentsFailed}
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
