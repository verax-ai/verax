import { useCallback, useEffect, useRef, useState } from "react";
import { parseInventory, type Inventory } from "@verax-ai/inventory";
import { Observatory, type Healthz, type LedgerError } from "./observatory/Observatory.tsx";
import { loadDemoActions, loadDemoAgents, loadDemoApprovals, loadDemoReconcile } from "./observatory/demo.ts";
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
import { authorizedFetch, beginSession, restartCodeFlow, sessionIssueError, sessionScopes } from "./session.ts";

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

async function readErrorBody(r: Response): Promise<string | null> {
  try {
    const errBody = (await r.json()) as { error?: unknown };
    return typeof errBody.error === "string" ? errBody.error : null;
  } catch {
    return null;
  }
}

/**
 * Audit doors (/api/ledger, /api/agents, /api/inventory, /api/contest) answer
 * 403 scope-missing when the session has no verax:audit. Other 403s, including
 * origin-not-allowed and local-mode-operator-scope, are not this case.
 * /api/approve uses the same status for a missing verax:approve and is not an
 * audit door.
 */
function isAuditScopeMissing(status: number, detail: string | null): boolean {
  return status === 403 && detail === "scope-missing";
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
  // The agents list is the body's reading of its ledger and roster; the
  // screen draws it, and says so when it could not be read.
  const [agents, setAgents] = useState<AgentsAnswer | null>(null);
  const [agentsFailed, setAgentsFailed] = useState(false);
  const pollRef = useRef<() => Promise<void>>(async () => undefined);
  const passkeyHeld = useRef(false);
  const showPasskey = useCallback(() => {
    if (wantDemo()) return;
    passkeyHeld.current = true;
    setStatus("error");
    setError({ code: "passkey" });
  }, []);

  const loadAgents = useCallback(async () => {
    try {
      const r = await authorizedFetch("/api/agents");
      if (!r.ok) {
        const detail = await readErrorBody(r);
        if (isAuditScopeMissing(r.status, detail)) showPasskey();
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
  }, [showPasskey]);

  const loadInventory = useCallback(async () => {
    try {
      const invRes = await authorizedFetch("/api/inventory");
      if (!invRes.ok) {
        const detail = await readErrorBody(invRes);
        if (isAuditScopeMissing(invRes.status, detail)) showPasskey();
        setInventory(null);
        return;
      }
      const invBody = (await invRes.json()) as { inventory?: unknown };
      const parsed = invBody.inventory == null ? null : parseInventory(invBody.inventory);
      setInventory(parsed && parsed.ok ? parsed.value : null);
    } catch {
      setInventory(null);
    }
  }, [showPasskey]);

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
      const detail = await readErrorBody(r);
      if (wantDemo()) {
        return null;
      }
      if (isAuditScopeMissing(r.status, detail)) {
        showPasskey();
        return null;
      }
      if (!passkeyHeld.current) {
        setStatus("error");
        setError({ code: "http", status: r.status, detail: detail || null });
      }
      return null;
    }
    try {
      return (await r.json()) as LedgerBody;
    } catch {
      if (!passkeyHeld.current) {
        setStatus("error");
        setError({ code: "invalid-json", detail: null });
      }
      return null;
    }
  }, [showPasskey]);

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
        // The agents table is the body's reading of its ledger. The sample has
        // no body to ask, so it is counted off the sample's own rows rather
        // than left out: the published screen used to show less than the
        // product, and a visitor had no way to know why.
        setAgents(loadDemoAgents());
        setAgentsFailed(false);
        setDemo(true);
        setStatus("ok");
        setLastReadMs(Date.now());
      }
      return;
    }
    passkeyHeld.current = false;
    await loadInventory();
    // The status tab counts decisions out of /healthz and witnesses out of
    // the rows it has. Read once at mount, those two disagreed the moment a
    // decision landed: the sentence said eight while the list showed nine.
    // They are read together now, so the tab is one reading of one ledger.
    await loadHealth();
    await loadAgents();
    try {
      const body = await readLedger(`from=0&to=${END_OF_TIME}&limit=${PAGE}`);
      if (!body) {
        if (passkeyHeld.current) showPasskey();
        return;
      }
      const parsed = rowsOf(body);
      setLastReadMs(Date.now());
      setDemo(false);
      setMore(body.more === true);
      setPending(Array.isArray(body.approvals) ? body.approvals : []);
      if (passkeyHeld.current) {
        // Another audit door closed this read. Keep its explanation; a good
        // ledger page must not wipe it back to an empty or open screen.
        showPasskey();
      } else {
        setError(null);
      }
      if (parsed.length === 0) {
        setActions([]);
        if (!passkeyHeld.current) setStatus("empty");
        return;
      }
      setActions(parsed);
      if (!passkeyHeld.current) setStatus("ok");
    } catch {
      if (!passkeyHeld.current) {
        setStatus("error");
        setError({ code: "network", detail: null });
      }
    }
  }, [actions.length, loadAgents, loadHealth, loadInventory, readLedger, showPasskey]);

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
    passkeyHeld.current = false;
    await loadInventory();
    await loadHealth();
    await loadAgents();
    try {
      const newestMs = actions[0]!.record.claims.timestampMs;
      const body = await readLedger(`from=${Math.max(0, newestMs - POLL_OVERLAP_MS)}&to=${END_OF_TIME}`);
      if (!body) {
        if (passkeyHeld.current) showPasskey();
        return;
      }
      setLastReadMs(Date.now());
      setPending(Array.isArray(body.approvals) ? body.approvals : []);
      const fresh = rowsOf(body);
      if (fresh.length > 0) setActions((held) => mergeActions(held, fresh));
      if (passkeyHeld.current) showPasskey();
      else {
        setError(null);
        setStatus("ok");
      }
    } catch {
      if (!passkeyHeld.current) {
        setStatus("error");
        setError({ code: "network", detail: null });
      }
    }
  }, [actions, load, loadAgents, loadHealth, loadInventory, readLedger, showPasskey]);

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
      if (!passkeyHeld.current) {
        setStatus("error");
        setError({ code: "network", detail: null });
      }
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
          setAgents(loadDemoAgents());
          setAgentsFailed(false);
          setDemo(true);
        }}
        onSignIn={() => {
          void restartCodeFlow();
        }}
        onContest={async (ref) => {
          const res = await authorizedFetch(`/api/contest/${encodeURIComponent(ref)}`, { method: "POST" });
          const body = (await res.json().catch(() => ({}))) as {
            error?: unknown;
            reAuditedAt?: number;
            finding?: RailFinding;
            guarantee?: "unconditional" | "conditional";
            warnings?: { id: string; code: string; detail?: string }[];
            witnessClass?: string | null;
            trustRoot?: { pinned: boolean; issuerMatches: boolean | null; source: "env" | "own-key" | null };
            pair?: { defer: { decision: string; reasonCode: string } | null; resolution: { decision: string; reasonCode: string } | null };
          };
          const detail = typeof body.error === "string" ? body.error : null;
          if (isAuditScopeMissing(res.status, detail)) {
            showPasskey();
            return { error: "scope-missing" };
          }
          if (!res.ok || typeof body.reAuditedAt !== "number") {
            return { error: `re-audit failed (${res.status})` };
          }
          return {
            reAuditedAt: body.reAuditedAt,
            finding: body.finding,
            guarantee: body.guarantee,
            warnings: body.warnings,
            witnessClass: body.witnessClass,
            trustRoot: body.trustRoot,
            pair: body.pair,
          };
        }}
      />
    </main>
  );
}
