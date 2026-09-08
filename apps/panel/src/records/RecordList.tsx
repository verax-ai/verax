import { panelCopy } from "../copy.ts";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import type { PendingApproval, RailAction } from "../rail/types.ts";
import { recordLine, statusWord } from "./line.ts";
import { countRecords, summarySentence } from "./summary.ts";

export function RecordList({
  actions,
  status,
  pending,
  reconcile,
  selected,
  onSelect,
}: {
  actions: RailAction[];
  status: "loading" | "ok" | "error" | "empty";
  pending: PendingApproval[];
  reconcile: ReconcileCardReport | null;
  selected: string | null;
  onSelect: (ref: string) => void;
}) {
  const copy = panelCopy();
  const sentence = summarySentence(copy, countRecords(actions, pending, reconcile));
  const empty = actions.length === 0;
  return (
    <div className="records-view">
      <p className="records-summary" data-testid="records-summary">
        {sentence}
      </p>
      {empty ? (
        <div className="records-empty" data-testid="records-empty">
          <p>{copy["records.empty"]}</p>
          <p className="muted">{copy["records.empty.hint"]}</p>
          {status === "error" ? <p className="rule-missing">{copy["records.empty.error"]}</p> : null}
        </div>
      ) : (
        <ol className="record-list" data-testid="record-list">
          {actions.map((action) => {
            const ref = action.record.claims.ref ?? "unknown";
            const line = recordLine(copy, action, pending);
            const word = statusWord(copy, line.kind);
            return (
              <li key={ref}>
                <button
                  type="button"
                  className={`record-row focusable ${line.kind}${selected === ref ? " is-selected" : ""}`}
                  aria-pressed={selected === ref}
                  onClick={() => onSelect(ref)}
                >
                  <span className={`record-status ${line.kind}`}>{word}</span>
                  <span className="record-asked">{line.asked}</span>
                  <span className="record-rule">{line.rule}</span>
                  <span className="record-outcome">{line.outcome}</span>
                </button>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
