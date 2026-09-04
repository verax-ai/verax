import { useEffect, useState } from "react";
import { parseLedger } from "./rail/parse.ts";
import { Rail } from "./rail/Rail.tsx";
import type { PolicyBundle, RailAction, RailFinding } from "./rail/types.ts";

export function App() {
  const [actions, setActions] = useState<RailAction[]>([]);

  useEffect(() => {
    void fetch("/api/ledger?from=0&to=9999999999999")
      .then((r) => r.json())
      .then(
        (body: {
          decisions?: unknown[];
          effects?: unknown[];
          policy?: PolicyBundle;
        }) => {
          const d = (body.decisions ?? []).map((x) => JSON.stringify(x)).join("\n");
          const e = (body.effects ?? []).map((x) => JSON.stringify(x)).join("\n");
          setActions(parseLedger(d, e, body.policy ?? null));
        },
      )
      .catch(() => setActions([]));
  }, []);

  return (
    <main>
      <h1>Account for</h1>
      <Rail
        actions={actions}
        onContest={async (ref) => {
          const res = await fetch(`/api/contest/${encodeURIComponent(ref)}`, { method: "POST" });
          return (await res.json()) as { reAuditedAt?: number; finding?: RailFinding };
        }}
      />
    </main>
  );
}
