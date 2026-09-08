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
  if (report === null) {
    return (
      <section className="reconcile-card" data-connected="no">
        <p>dış kaynak bağlı değil</p>
      </section>
    );
  }
  return (
    <section className="reconcile-card" data-connected="yes">
      <p>
        Dış kaynak: {report.scope.channel} · kapsam {report.scope.windowStartMs}–
        {report.scope.windowEndMs} · {report.ghost.length} hayalet
      </p>
    </section>
  );
}
