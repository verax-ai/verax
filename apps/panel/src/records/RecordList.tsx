import { panelCopy } from "../copy.ts";
import { fillCopy } from "../galaxy/coverage-line.ts";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import type { PendingApproval, RailAction } from "../rail/types.ts";
import { recordLine, statusWord } from "./line.ts";
import { countRecords, summarySentence } from "./summary.ts";

export function RecordList({
  actions,
  status,
  pending,
  reconcile,
  brains,
  selected,
  onSelect,
}: {
  actions: RailAction[];
  status: "loading" | "ok" | "error" | "empty";
  pending: PendingApproval[];
  reconcile: ReconcileCardReport | null;
  brains: string[];
  selected: string | null;
  onSelect: (ref: string) => void;
}) {
  const copy = panelCopy();
  const sentence = summarySentence(copy, countRecords(actions, pending, reconcile));
  const empty = actions.length === 0;
  // What the rail used to hold: who wrote into this ledger, and what is not
  // bound to it. It is one line about the source of the list, not a second
  // copy of the list.
  const source = [
    brains.length === 0
      ? copy["records.source.noAgents"]
      : fillCopy(copy["records.source.agents"], { agents: brains.join(", ") }),
    copy["records.source.noProjects"],
  ].join(" · ");
  return (
    <div className="records-view">
      <p className="records-summary" data-testid="records-summary">
        {sentence}
      </p>
      <p className="records-source muted" data-testid="records-source">
        {source}
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
