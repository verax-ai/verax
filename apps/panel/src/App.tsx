import { useCallback, useEffect, useState } from "react";
import { Stage } from "@verax-ai/presence";
import { parseLedger } from "./rail/parse.ts";
import { Rail } from "./rail/Rail.tsx";
import type { PolicyBundle, RailAction, RailFinding } from "./rail/types.ts";

type RailStatus = "loading" | "ok" | "error" | "empty";

const STALE_MS = 30_000;
const REFRESH_MS = 5_000;

function ageLabel(ageMs: number): string {
  return `last read ${Math.max(0, Math.floor(ageMs / 1000))} s ago`;
}

export function App() {
  const [status, setStatus] = useState<RailStatus>("loading");
  const [actions, setActions] = useState<RailAction[]>([]);
  const [errorText, setErrorText] = useState<string | null>(null);
  const [lastReadMs, setLastReadMs] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());

  const load = useCallback(async () => {
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
    }
  }, []);

  useEffect(() => {
    void load();
    const id = setInterval(() => {
      void load();
    }, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1_000);
    return () => clearInterval(id);
  }, []);

  const ageMs = lastReadMs === null ? null : nowMs - lastReadMs;
  const stale = ageMs !== null && ageMs > STALE_MS;

  return (
    <main className="shell">
      <Stage />
      <aside>
        <h1>Account for</h1>
        <div className="rail-head">
          <p className={`rail-status ${status}${stale ? " stale" : ""}`} data-status={status}>
            {status === "error" ? (
              <>
                <span>error</span> {errorText}
              </>
            ) : (
              status
            )}
          </p>
          {ageMs !== null ? <p className={stale ? "age stale" : "age"}>{ageLabel(ageMs)}</p> : null}
          <button type="button" className="refresh focusable" onClick={() => void load()}>
            Refresh
          </button>
        </div>
        {status === "ok" ? (
          <Rail
            actions={actions}
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
        ) : null}
      </aside>
    </main>
  );
}
