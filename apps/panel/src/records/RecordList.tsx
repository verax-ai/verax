import { useMemo, useState } from "react";
import { panelCopy } from "../copy.ts";
import { fillCopy } from "../fill.ts";
import type { ReconcileCardReport } from "../ReconcileCard.tsx";
import type { PendingApproval, RailAction } from "../rail/types.ts";
import { filterActions, filterActive, type RecordFilter } from "./filter.ts";
import { recordLine, statusWord, type RecordKind } from "./line.ts";
import { countRecords, summarySentence } from "./summary.ts";

const KINDS: readonly RecordKind[] = ["allow", "deny", "defer", "threw", "expired"];

export function RecordList({
  actions,
  status,
  pending,
  reconcile,
  brains,
  selected,
  onSelect,
  more = false,
  onOlder,
}: {
  actions: RailAction[];
  status: "loading" | "ok" | "error" | "empty";
  pending: PendingApproval[];
  reconcile: ReconcileCardReport | null;
  brains: string[];
  selected: string | null;
  onSelect: (ref: string) => void;
  /** Whether the ledger goes on past the oldest row on screen. */
  more?: boolean;
  onOlder?: () => void;
}) {
  const copy = panelCopy();
  const sentence = summarySentence(copy, countRecords(actions, pending, reconcile));
  const empty = actions.length === 0;
  // Narrowing is on the screen, over the rows it holds: the newest page and
  // the older pages asked for. The summary counts what is loaded; the line
  // under the bar says how many of those are shown.
  const [filter, setFilter] = useState<RecordFilter>({});
  const tools = useMemo(() => [...new Set(actions.map((a) => a.record.claims.subject))].sort(), [actions]);
  const shown = useMemo(() => filterActions(actions, pending, filter), [actions, pending, filter]);
  const narrowed = filterActive(filter);
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
      {empty ? null : (
        <div className="records-filter" data-testid="records-filter">
          <label>
            {copy["records.filter.agent"]}
            <select value={filter.agent ?? ""} onChange={(e) => setFilter({ ...filter, agent: e.target.value })}>
              <option value="">{copy["records.filter.agent.all"]}</option>
              {brains.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
          </label>
          <label>
            {copy["records.filter.tool"]}
            <select value={filter.tool ?? ""} onChange={(e) => setFilter({ ...filter, tool: e.target.value })}>
              <option value="">{copy["records.filter.tool.all"]}</option>
              {tools.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label>
            {copy["records.filter.kind"]}
            <select
              value={filter.kind ?? ""}
              onChange={(e) => setFilter({ ...filter, kind: e.target.value as RecordKind | "" })}
            >
              <option value="">{copy["records.filter.kind.all"]}</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {statusWord(copy, k)}
                </option>
              ))}
            </select>
          </label>
          <input
            type="search"
            value={filter.ref ?? ""}
            placeholder={copy["records.filter.ref"]}
            aria-label={copy["records.filter.ref"]}
            onChange={(e) => setFilter({ ...filter, ref: e.target.value })}
          />
          {narrowed ? (
            <button type="button" className="focusable" onClick={() => setFilter({})}>
              {copy["records.filter.clear"]}
            </button>
          ) : null}
          {narrowed ? (
            <p className="muted records-filter-shown" data-testid="records-filter-shown">
              {fillCopy(copy["records.filter.shown"], { shown: String(shown.length), loaded: String(actions.length) })}
            </p>
          ) : null}
        </div>
      )}
      {empty ? (
        <div className="records-empty" data-testid="records-empty">
          <p>{copy["records.empty"]}</p>
          <p className="muted">{copy["records.empty.hint"]}</p>
          {status === "error" ? <p className="rule-missing">{copy["records.empty.error"]}</p> : null}
        </div>
      ) : (
        <ol className="record-list" data-testid="record-list">
          {shown.map((action) => {
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
      {!empty && more ? (
        <div className="records-older" data-testid="records-older">
          <p className="muted">{fillCopy(copy["records.window"], { n: String(actions.length) })}</p>
          <button type="button" className="focusable" onClick={() => onOlder?.()}>
            {copy["records.older"]}
          </button>
        </div>
      ) : null}
    </div>
  );
}
