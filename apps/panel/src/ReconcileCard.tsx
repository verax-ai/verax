import { panelCopy } from "./copy.ts";
export type ReconcileMatch = {
  effect?: { ref?: string };
};

export type ReconcileCardReport = {
  scope: {
    channel: string;
    windowStartMs: number;
    windowEndMs: number;
    rowCount: number;
  };
  ghost: unknown[];
  matched?: ReconcileMatch[];
  authorizedUnpaid?: { ref?: string }[];
};

export function ReconcileCard({ report }: { report: ReconcileCardReport | null }) {
  const copy = panelCopy();
  if (report === null) {
    return (
      <section className="reconcile-card" data-connected="no">
        <p>{copy["reconcile.unbound"]}</p>
      </section>
    );
  }
  return (
    <section className="reconcile-card" data-connected="yes">
      <p>
        {copy["reconcile.scope"]
          .replace("{channel}", report.scope.channel)
          .replace("{from}", String(report.scope.windowStartMs))
          .replace("{to}", String(report.scope.windowEndMs))
          .replace("{ghosts}", String(report.ghost.length))}
      </p>
    </section>
  );
}
