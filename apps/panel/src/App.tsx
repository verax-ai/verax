import { useCallback, useEffect, useState } from "react";
import { Observatory, type Healthz } from "./observatory/Observatory.tsx";
import { loadDemoActions } from "./observatory/demo.ts";
import { parseLedger } from "./rail/parse.ts";
import type { PolicyBundle, RailAction, RailFinding } from "./rail/types.ts";
import type { ReconcileCardReport } from "./ReconcileCard.tsx";

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
  const [errorText, setErrorText] = useState<string | null>(null);
  const [lastReadMs, setLastReadMs] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [reconcileReport, setReconcileReport] = useState<ReconcileCardReport | null>(null);
  const [health, setHealth] = useState<Healthz>(null);

  const load = useCallback(async () => {
    if (wantDemo() && actions.length === 0) {
      setActions(loadDemoActions());
      setDemo(true);
      setStatus("ok");
      setLastReadMs(Date.now());
    }
    try {
      const r = await fetch("/api/ledger?from=0&to=9999999999999");
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
        setErrorText(`ledger unreachable: ${r.status}${detail ? ` ${detail}` : ""}`);
        return;
      }
      let body: {
        decisions?: unknown[];
        effects?: unknown[];
        policies?: Record<string, PolicyBundle["document"]>;
        policy?: PolicyBundle;
        inputs?: Record<string, import("./rail/types.ts").RailInputs>;
      };
      try {
        body = (await r.json()) as typeof body;
      } catch {
        setStatus("error");
        setErrorText("ledger unreachable: invalid-json");
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
      setErrorText(null);
      setDemo(false);
      if (parsed.length === 0) {
        setActions([]);
        setStatus("empty");
        return;
      }
      setActions(parsed);
      setStatus("ok");
    } catch {
      setStatus("error");
      setErrorText("ledger unreachable: network");
      if (actions.length === 0) {
        setActions(loadDemoActions());
        setDemo(true);
        setStatus("ok");
        setLastReadMs(Date.now());
      }
    }
  }, [actions.length]);

  useEffect(() => {
    void load();
    const id = setInterval(() => {
      void load();
    }, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    void (async () => {
      try {
        const r = await fetch("/healthz");
        if (!r.ok) {
          setHealth(null);
          return;
        }
        const body = (await r.json()) as Healthz;
        setHealth(body && typeof body === "object" ? body : null);
      } catch {
        setHealth(null);
      }
    })();
  }, []);

  useEffect(() => {
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
        errorText={errorText}
        stale={stale}
        ageMs={ageMs}
        onRefresh={() => void load()}
        onContest={async (ref) => {
          const res = await fetch(`/api/contest/${encodeURIComponent(ref)}`, { method: "POST" });
          const body = (await res.json().catch(() => ({}))) as {
            reAuditedAt?: number;
            finding?: RailFinding;
            guarantee?: "unconditional" | "conditional";
            warnings?: { id: string; code: string; detail?: string }[];
            witnessClass?: string | null;
            trustRoot?: { pinned: boolean; issuerMatches: boolean | null; source: "env" | "own-key" | null };
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
