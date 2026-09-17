import { useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import type { Inventory } from "@verax-ai/inventory";
import { panelCopy } from "../copy.ts";
import { fillCopy } from "../fill.ts";
import { coverageLine } from "../rail/coverage.ts";
import { ReconcileCard, type ReconcileCardReport } from "../ReconcileCard.tsx";
import { BlackBox } from "../blackbox/BlackBox.tsx";
import type {
  AgentRow,
  AgentsAnswer,
  PendingApproval,
  RailAction,
  RailContestResult,
  RailFinding,
  RailWarning,
} from "../rail/types.ts";
import { RecordList } from "../records/RecordList.tsx";
import { exhibitAction, exhibitRef } from "../records/exhibit.ts";
import { approvalForRef } from "../records/approval-state.ts";
import { approveFailureText, approveOutcomeText } from "../records/approve-outcome.ts";
import { pairFromLedger } from "../records/pair.ts";
import { outcomeText, recordLine } from "../records/line.ts";
import { LANGS, readLang, writeLang, type Lang } from "../lang.ts";
import { formatMinor } from "../records/money.ts";
import { evidenceScope, guaranteeLabel, pinLabel, warningCodes } from "../records/scope.ts";
import { spendFields } from "../records/spend.ts";
import { Timeline } from "../records/Timeline.tsx";
import { formatStamp } from "../records/timeline.ts";

export type Healthz = {
  ok?: boolean;
  decisions?: number;
  effects?: number;
  lastDecisionMs?: number | null;
  lock?: { held: boolean; pid?: number } | string | null;
  heartbeat?: { atMs: number; lastDecisionN?: number; lastEffectN?: number } | null;
  witness?: { class: string; atMs: number } | null;
} | null;

export type ObservatoryStatus = "loading" | "ok" | "error" | "empty";

/** What the body answered. `error` is its own word, repeated, not guessed. */
export type ApproveOutcome = { ok: true; allowRef: string } | { ok: false; error: string };

/**
 * Why the ledger could not be read, as a reason the copy table can speak.
 * It used to arrive as a finished English sentence, which printed twice on
 * the error line ("ledger unreachable ledger unreachable: 500") and stayed
 * English on the Turkish screen. The machine's own words - a status code, a
 * message from the server - ride along in `detail` and are not translated.
 */
export type LedgerError = {
  code: "http" | "invalid-json" | "network" | "session";
  status?: number;
  detail?: string | null;
};

function errorReason(copy: ReturnType<typeof panelCopy>, error: LedgerError): string {
  if (error.code === "http") return fillCopy(copy["error.http"], { code: error.status ?? "" });
  if (error.code === "invalid-json") return copy["error.invalidJson"];
  if (error.code === "network") return copy["error.network"];
  return copy["error.session"];
}

const TAB_IDS = ["records", "box", "status"] as const;
type TabId = (typeof TAB_IDS)[number];
const TAB_COPY: Record<TabId, "tab.records" | "tab.box" | "tab.status"> = {
  records: "tab.records",
  box: "tab.box",
  status: "tab.status",
};

/**
 * Tabs that draw their own way into a record and need the whole width. The
 * black box is a full-width scene; its console opens the record it shows.
 */
const WIDE_TABS: readonly TabId[] = ["box"];

/**
 * Which tab an address opens on. An explicit ?tab= wins; a name the panel no
 * longer has - history, and the galaxy that was removed - opens the records.
 */
export function openingTab(search: string): TabId {
  const tab = new URLSearchParams(search).get("tab");
  if (TAB_IDS.includes(tab as TabId)) return tab as TabId;
  return "records";
}

function readTab(): TabId {
  if (typeof window === "undefined") return "records";
  return openingTab(window.location.search);
}

function shortHash(h: string | null | undefined): string {
  if (!h) return "—";
  return h.length > 12 ? `${h.slice(0, 8)}…` : h;
}

function statusLabel(copy: ReturnType<typeof panelCopy>, status: ObservatoryStatus): string {
  if (status === "ok") return copy["status.ok"];
  if (status === "empty") return copy["status.empty"];
  if (status === "error") return copy["status.error"];
  return copy["status.loading"];
}

function lockLabel(copy: ReturnType<typeof panelCopy>, health: Healthz): string {
  if (!health || health.lock == null) return copy.disconnected;
  if (typeof health.lock === "string") {
    if (health.lock === "held") return copy["lock.held"];
    if (health.lock === "open") return copy["lock.open"];
    return health.lock;
  }
  return health.lock.held ? copy["lock.held"] : copy["lock.open"];
}

export function Observatory({
  actions,
  status,
  demo,
  health = null,
  reconcile = null,
  error = null,
  stale = false,
  ageMs = null,
  onRefresh,
  onShowDemo,
  onContest,
  canApprove = false,
  onApprove,
  pending = [],
  inventory = null,
  nowMs = Date.now(),
  more = false,
  onOlder,
  agents = null,
  agentsFailed = false,
}: {
  actions: RailAction[];
  status: ObservatoryStatus;
  demo: boolean;
  pending?: PendingApproval[];
  /** Whether the ledger goes on past the oldest row on screen. */
  more?: boolean;
  onOlder?: () => void;
  /** The body's list of agents (/api/agents); null until read. */
  agents?: AgentsAnswer | null;
  /** The list was asked for and could not be read. */
  agentsFailed?: boolean;
  health?: Healthz;
  reconcile?: ReconcileCardReport | null;
  error?: LedgerError | null;
  stale?: boolean;
  ageMs?: number | null;
  inventory?: Inventory | null;
  nowMs?: number;
  onRefresh?: () => void;
  onShowDemo?: () => void;
  onContest?: (ref: string) => Promise<RailContestResult | void>;
  /**
   * Whether this session carries the approve scope. The body decides for real;
   * this only decides whether to draw a button, because a button that cannot
   * work is a promise the screen cannot keep.
   */
  canApprove?: boolean;
  onApprove?: (ref: string, requestHash: string) => Promise<ApproveOutcome>;
}) {
  const initialTab = useMemo<TabId>(() => readTab(), []);
  const [tab, setTab] = useState<TabId>(initialTab);
  const [selected, setSelected] = useState<string | null>(exhibitRef(actions));
  // panelCopy() is read during render all the way down, so a language
  // change only needs this subtree to render again.
  const [langNonce, setLangNonce] = useState(0);
  const lang = readLang();
  const [inspectFailed, setInspectFailed] = useState<Record<string, string>>({});
  const [audits, setAudits] = useState<
    Record<
      string,
      {
        guarantee?: "unconditional" | "conditional";
        warnings?: RailWarning[];
        witnessClass?: string | null;
        trustRoot?: { pinned: boolean; issuerMatches: boolean | null; source: "env" | "own-key" | null };
        finding?: RailFinding;
        summary?: string;
        pair?: { defer: { decision: string; reasonCode: string } | null; resolution: { decision: string; reasonCode: string } | null };
      }
    >
  >({});

  const action = actions.find((a) => a.record.claims.ref === selected) ?? exhibitAction(actions);
  const audit = action?.record.claims.ref ? audits[action.record.claims.ref] : undefined;
  const guarantee = audit?.guarantee ?? action?.guarantee;
  const summary = audit?.finding?.summary ?? action?.finding?.summary ?? "";
  const identityMissing = Boolean(
    action && !action.inputsBound && typeof action.record.claims.inputsHash === "string",
  );

  const brains = useMemo(() => {
    const set = new Set<string>();
    for (const a of actions) {
      if (a.inputs?.principal.brain) set.add(a.inputs.principal.brain);
    }
    return [...set];
  }, [actions]);

  useEffect(() => {
    if (typeof document !== "undefined") document.documentElement.lang = lang;
  }, [lang, langNonce]);

  useEffect(() => {
    const first = exhibitRef(actions);
    if (first !== null && selected === null) {
      setSelected(first);
    }
  }, [actions, selected]);

  const onKeyTabs = (e: KeyboardEvent) => {
    const i = TAB_IDS.indexOf(tab);
    if (e.key === "ArrowRight") {
      e.preventDefault();
      setTab(TAB_IDS[(i + 1) % TAB_IDS.length]!);
    }
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      setTab(TAB_IDS[(i - 1 + TAB_IDS.length) % TAB_IDS.length]!);
    }
  };

  const contest = async (ref: string) => {
    if (!onContest) return;
    const out = await onContest(ref);
    // A re-audit that did not complete has to say so. Storing only the good
    // case left a failed inspect looking exactly like a click that did
    // nothing, which is the one thing an account-for screen may not do.
    const failure = out && typeof out.error === "string" ? out.error : null;
    setInspectFailed((s) => {
      const next = { ...s };
      if (failure === null) delete next[ref];
      else next[ref] = failure;
      return next;
    });
    if (out && !out.error) {
      setAudits((s) => ({
        ...s,
        [ref]: {
          guarantee: out.guarantee,
          warnings: out.warnings,
          witnessClass: out.witnessClass,
          trustRoot: out.trustRoot,
          finding: out.finding,
          summary: out.finding?.summary,
          pair: out.pair,
        },
      }));
    }
    return out;
  };

  const copy = panelCopy();
  const pin = pinLabel(copy, audit?.trustRoot?.source ?? action?.trustRoot?.source ?? null);
  const cover = coverageLine(inventory, brains, nowMs, copy, demo);
  const lastMs = health?.lastDecisionMs ?? actions[0]?.record.claims.timestampMs ?? null;
  const witnessCounts = actions.reduce<Record<string, number>>((acc, a) => {
    const w = a.witnessClass ?? a.effect?.witnessClass ?? "none";
    acc[w] = (acc[w] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className={`observatory${tab === "records" ? " no-rail" : ""}${WIDE_TABS.includes(tab) ? " wide-tab" : ""}`}>
      {demo ? <p className="demo-badge">{copy["badge.demo"]}</p> : null}
      <div className="obs-top">
        <div role="tablist" aria-label={copy["aria.observatory"]} onKeyDown={onKeyTabs}>
          {TAB_IDS.map((id) => (
            <button
              key={id}
              type="button"
              role="tab"
              id={`tab-${id}`}
              aria-selected={tab === id}
              aria-controls={`panel-${id}`}
              tabIndex={tab === id ? 0 : -1}
              className="focusable"
              onClick={() => setTab(id)}
            >
              {copy[TAB_COPY[id]]}
            </button>
          ))}
        </div>
        <div className="lang-switch" role="group" aria-label={copy["lang.label"]}>
          {LANGS.map((code: Lang) => (
            <button
              key={code}
              type="button"
              className="focusable"
              aria-pressed={lang === code}
              onClick={() => {
                writeLang(code);
                setLangNonce((n) => n + 1);
              }}
            >
              {/* The code names itself in every language; only the group
                  label is copy. */}
              {code.toUpperCase()}
            </button>
          ))}
        </div>
        <p className={`rail-status ${status}${stale ? " stale" : ""}`} data-status={status}>
          {status === "error" ? (
            <>
              <span>{copy["status.error"]}</span>{" "}
              {error ? errorReason(copy, error) : null}
              {error?.detail ? <span className="muted"> · {error.detail}</span> : null}
            </>
          ) : (
            statusLabel(copy, status)
          )}
        </p>
        {ageMs !== null ? (
          <p className={stale ? "age stale" : "age"}>
            {fillCopy(copy["status.lastRead"], { n: Math.max(0, Math.floor(ageMs / 1000)) })}
          </p>
        ) : null}
        {onRefresh ? (
          <button type="button" className="refresh focusable" onClick={onRefresh}>
            {copy.refresh}
          </button>
        ) : null}
        {status === "error" && onShowDemo ? (
          <button type="button" className="refresh focusable" onClick={onShowDemo}>
            {copy.showDemo}
          </button>
        ) : null}
      </div>
      {/* The rail is the only way into a record from the status tab. On the
          records tab the middle pane is that way in, and what was left -- two
          lines about the ledger -- now sits under the sentence there. A column
          that wide has to carry more than a fact the view it borders can state
          in one line. */}
      {tab === "records" || WIDE_TABS.includes(tab) ? null : (
      <aside className="obs-left" aria-label={copy["aria.rail"]}>
        <h2>{copy["rail.ledger.agents"]}</h2>
        {brains.length === 0 ? <p className="muted">{copy.disconnected}</p> : (
          <ul className="rail-ledger" data-testid="rail-ledger-agents">
            {brains.map((b) => <li key={b}>{b}</li>)}
          </ul>
        )}
        {/* The roster is a document the body serves, not a measurement: its
            names are listed as declared, and the one sentence that counts
            says how many of them this ledger has heard from. */}
        <p className={cover.stale ? "muted rail-coverage stale" : "muted rail-coverage"} data-testid="inventory-coverage">
          {cover.text}
        </p>
        {inventory ? (
          <>
            <h2>{copy["rail.inventory.groups"]}</h2>
            {inventory.groups.length === 0 ? (
              <p className="muted">{copy.disconnected}</p>
            ) : (
              <ul className="rail-inventory" data-testid="rail-inventory-groups">
                {inventory.groups.map((g) => (
                  <li key={g.id}>{g.label}</li>
                ))}
              </ul>
            )}
            <h2>{copy["rail.inventory.agents"]}</h2>
            {inventory.agents.length === 0 ? (
              <p className="muted">{copy.disconnected}</p>
            ) : (
              <ul className="rail-inventory" data-testid="rail-inventory-agents">
                {inventory.agents.map((a) => (
                  <li key={a.id}>{a.label}</li>
                ))}
              </ul>
            )}
          </>
        ) : null}
        <h2>{copy.records}</h2>
        {actions.length === 0 ? (
          <p className="muted">{copy["summary.empty"]}</p>
        ) : (
          <ul className="rail-records" data-testid="rail-records">
            {actions.map((a) => {
              const ref = a.record.claims.ref ?? "unknown";
              const line = recordLine(copy, a, pending);
              return (
                <li key={ref}>
                  <button
                    type="button"
                    className="focusable"
                    onClick={() => {
                      setSelected(ref);
                      setTab("records");
                    }}
                  >
                    {line.label}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </aside>
      )}
      <section className="obs-main" id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {tab === "records" ? (
          <RecordList
            actions={actions}
            status={status}
            pending={pending}
            reconcile={reconcile}
            brains={brains}
            selected={action?.record.claims.ref ?? selected}
            onSelect={(ref) => setSelected(ref)}
            more={more}
            onOlder={onOlder}
          />
        ) : null}
        {tab === "status" ? (
          <StatusView
            actions={actions}
            health={health}
            lastMs={lastMs}
            witnessCounts={witnessCounts}
            reconcile={reconcile}
            pending={pending}
            canApprove={canApprove}
            onApprove={onApprove}
            agents={agents}
            agentsFailed={agentsFailed}
          />
        ) : null}
        {tab === "box" ? (
          <BlackBox
            actions={actions}
            pending={pending}
            decisions={health?.decisions}
            demo={demo}
            canApprove={canApprove}
            onApprove={onApprove}
            onRefresh={onRefresh}
            onOpenRecord={(ref) => {
              setSelected(ref);
              setTab("records");
            }}
          />
        ) : null}
      </section>
      {WIDE_TABS.includes(tab) ? null : (
      <aside className="obs-detail" aria-label={copy["aria.detail"]}>
        <DetailPane
          action={action}
          actions={actions}
          pending={pending}
          canApprove={canApprove}
          onApprove={onApprove}
          reconcile={reconcile}
          guarantee={guarantee}
          pin={pin}
          summary={summary}
          identityMissing={identityMissing}
          warnings={audit?.warnings ?? action?.warnings ?? []}
          witness={audit?.witnessClass ?? action?.witnessClass ?? action?.effect?.witnessClass ?? null}
          pair={audit?.pair}
          inspected={Boolean(action?.record.claims.ref && audits[action.record.claims.ref])}
          inspectFailed={action?.record.claims.ref ? inspectFailed[action.record.claims.ref] ?? null : null}
          issuerMatches={audit?.trustRoot?.issuerMatches ?? action?.trustRoot?.issuerMatches ?? null}
          pinSource={audit?.trustRoot?.source ?? action?.trustRoot?.source ?? null}
          onInspect={action?.record.claims.ref ? () => void contest(action.record.claims.ref as string) : undefined}
        />
      </aside>
      )}
      <Timeline
        actions={actions}
        selected={action?.record.claims.ref ?? selected}
        onSelect={(ref) => {
          setSelected(ref);
          setTab("records");
        }}
      />
    </div>
  );
}

/**
 * Money leaving, and it cannot be taken back. So: the tap asks first and
 * repeats what is about to be approved in the operator's own language; the
 * request the screen was showing goes along with the answer, so the body can
 * refuse if the screen has gone stale; and nothing here says "approved" that
 * the body did not say first - a refusal is repeated with its own reason.
 */
function ApproveControl({
  copy,
  row,
  onApprove,
}: {
  copy: ReturnType<typeof panelCopy>;
  row: PendingApproval;
  onApprove: (ref: string, requestHash: string) => Promise<ApproveOutcome>;
}) {
  const [asking, setAsking] = useState(false);
  const [sending, setSending] = useState(false);
  const [said, setSaid] = useState<string | null>(null);

  if (said !== null) {
    return (
      <p data-testid="approve-outcome" className="approve-outcome">
        {said}
      </p>
    );
  }
  if (!asking) {
    return (
      <button type="button" className="approve focusable" onClick={() => setAsking(true)}>
        {copy["approve.button"]}
      </button>
    );
  }
  const money = formatMinor(row.amount, row.currency, readLang());
  return (
    <div data-testid="approve-confirm" className="approve-confirm">
      <p>{copy["approve.title"]}</p>
      <p>
        {row.subject}
        {money !== null ? ` · ${money}` : ""}
        {row.payee === undefined ? "" : ` → ${String(row.payee)}`}
      </p>
      <p className="muted">{row.ruleText ?? copy["line.rule.none"]}</p>
      <button
        type="button"
        className="approve focusable"
        disabled={sending}
        onClick={() => {
          setSending(true);
          void onApprove(row.ref, row.requestHash).then(
            (out) => setSaid(approveOutcomeText(copy, out)),
            (err: unknown) => setSaid(approveFailureText(copy, err)),
          );
        }}
      >
        {sending ? copy["approve.sending"] : copy["approve.yes"]}
      </button>
      <button type="button" className="focusable" onClick={() => setAsking(false)}>
        {copy["approve.no"]}
      </button>
    </div>
  );
}

function StatusView({
  actions,
  health,
  lastMs,
  witnessCounts,
  reconcile,
  pending,
  canApprove,
  onApprove,
  agents = null,
  agentsFailed = false,
}: {
  actions: RailAction[];
  health: Healthz;
  lastMs: number | null;
  witnessCounts: Record<string, number>;
  canApprove?: boolean;
  onApprove?: (ref: string, requestHash: string) => Promise<ApproveOutcome>;
  reconcile: ReconcileCardReport | null;
  pending: PendingApproval[];
  agents?: AgentsAnswer | null;
  agentsFailed?: boolean;
}) {
  const copy = panelCopy();
  const effects = actions.filter((a) => a.effect).length;
  const lock = lockLabel(copy, health);
  const pinSource = actions.find((a) => a.trustRoot)?.trustRoot?.source;
  const open = pending.filter((p) => p.status === "pending");
  const who =
    Object.entries(witnessCounts)
      .map(([k, n]) => `${k} ${n}`)
      .join(" · ") || copy.disconnected;
  return (
    <div className="status-view">
      <p>{fillCopy(copy["status.decisions"], { n: health?.decisions ?? actions.length })}</p>
      <p>{fillCopy(copy["status.effects"], { n: health?.effects ?? effects })}</p>
      <p>
        {fillCopy(copy["status.lastDecision"], {
          when: lastMs !== null ? formatStamp(lastMs) : copy.disconnected,
        })}
      </p>
      <p>{fillCopy(copy["status.lock"], { state: lock })}</p>
      <p>{fillCopy(copy["witness.label"], { who })}</p>
      <p>
        {fillCopy(copy["status.pinSource"], {
          source: pinSource ?? copy["status.pinSource.unaudited"],
        })}
      </p>
      <AgentsTable copy={copy} agents={agents} failed={agentsFailed} />
      <section data-testid="pending-approvals" className="pending-approvals">
        <h3>{copy["pending.title"]}</h3>
        {open.length === 0 ? <p className="muted">{copy["pending.empty"]}</p> : (
          <ul>
            {open.map((p) => (
              <li key={p.ref}>
                {p.ref} · {p.subject} · {p.ruleText ?? ""} · {p.brain}
                {pendingMoney(copy, p)}
                {canApprove && onApprove ? (
                  <ApproveControl copy={copy} row={p} onApprove={onApprove} />
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
      <ReconcileCard report={reconcile} />
    </div>
  );
}

/**
 * One row per agent, as the body counted it: the roster's agents are on the
 * list whether or not they acted, and an agent the ledger heard from that
 * the roster does not name is marked as such rather than left out.
 */
function AgentsTable({
  copy,
  agents,
  failed,
}: {
  copy: ReturnType<typeof panelCopy>;
  agents: AgentsAnswer | null;
  failed: boolean;
}) {
  // Groups the operator closed. Keyed by group, so a poll that reorders the
  // rows does not reopen what was closed.
  const [folded, setFolded] = useState<Set<string>>(() => new Set());
  if (failed) {
    return (
      <section className="agents" data-testid="agents">
        <p className="rule-missing">{copy["agents.unmeasured"]}</p>
      </section>
    );
  }
  if (!agents) return null;
  const hours = Math.max(1, Math.round((agents.toMs - agents.fromMs) / 3_600_000));
  const stateWord = (row: AgentRow): string => {
    if (!row.roster) return copy["agents.state.offRoster"];
    const key = `agents.state.${row.roster.state}` as keyof typeof copy;
    return copy[key] ?? row.roster.state;
  };
  const groups = groupAgents(agents.agents, copy);
  return (
    <section className="agents" data-testid="agents">
      <h3>{fillCopy(copy["agents.title"], { h: String(hours), n: String(agents.agents.length) })}</h3>
      {agents.unattributed > 0 ? (
        <p className="muted">{fillCopy(copy["agents.unattributed"], { n: String(agents.unattributed) })}</p>
      ) : null}
      {agents.agents.length === 0 ? (
        <p className="muted">{copy["agents.empty"]}</p>
      ) : (
        <table className="agents-table" data-testid="agents-table">
          <thead>
            <tr>
              <th>{copy["agents.col.agent"]}</th>
              <th>{copy["agents.col.group"]}</th>
              <th>{copy["agents.col.state"]}</th>
              <th>{copy["agents.col.decisions"]}</th>
              <th>{copy["agents.col.denied"]}</th>
              <th>{copy["agents.col.pending"]}</th>
              <th>{copy["agents.col.last"]}</th>
            </tr>
          </thead>
          {groups.map((group) => {
            const open = !folded.has(group.key);
            return (
              <tbody key={group.key}>
                <tr className="agents-group">
                  <td colSpan={7}>
                    <button
                      type="button"
                      className="focusable"
                      aria-expanded={open}
                      onClick={() => {
                        const next = new Set(folded);
                        if (open) next.add(group.key);
                        else next.delete(group.key);
                        setFolded(next);
                      }}
                    >
                      {fillCopy(copy["agents.group.line"], {
                        group: group.label,
                        n: String(group.rows.length),
                        pending: String(group.rows.reduce((sum, row) => sum + row.pending, 0)),
                      })}
                    </button>
                  </td>
                </tr>
                {open
                  ? group.rows.map((row) => (
                      <tr key={row.brain} className={row.pending > 0 ? "agent-row has-pending" : "agent-row"}>
                        <td>{row.roster?.label ?? row.brain}</td>
                        <td>{row.roster?.group ?? ""}</td>
                        <td>{stateWord(row)}</td>
                        <td>{row.decisions}</td>
                        <td>{row.denied}</td>
                        <td>{row.pending}</td>
                        <td>{row.lastMs === null ? copy.unmeasured : formatStamp(row.lastMs)}</td>
                      </tr>
                    ))
                  : null}
              </tbody>
            );
          })}
        </table>
      )}
    </section>
  );
}

/**
 * The rows folded under the roster's groups, in the order the groups first
 * appear in the body's list (which is pending first, then most recent).
 * An agent the roster does not name is filed under "not on the roster"; a
 * roster agent without a group under "no group". Both are groups of their
 * own so that folding one machine's agents away never hides them.
 */
function groupAgents(
  rows: readonly AgentRow[],
  copy: ReturnType<typeof panelCopy>,
): { key: string; label: string; rows: AgentRow[] }[] {
  const out = new Map<string, { key: string; label: string; rows: AgentRow[] }>();
  for (const row of rows) {
    const key = row.roster === null ? " off" : row.roster.group === null ? " none" : `g:${row.roster.group}`;
    const label =
      row.roster === null
        ? copy["agents.state.offRoster"]
        : row.roster.group === null
          ? copy["agents.group.none"]
          : row.roster.group;
    let group = out.get(key);
    if (!group) {
      group = { key, label, rows: [] };
      out.set(key, group);
    }
    group.rows.push(row);
  }
  return [...out.values()];
}

/**
 * The ledger holds money in minor units. The record screen was taught to read
 * them in 3fafdcb; this list kept printing the stored number beside the
 * currency, which states a sum a hundred times too large, and its test froze
 * that. An amount that cannot be read is left out rather than shown raw.
 */
function pendingMoney(copy: ReturnType<typeof panelCopy>, row: PendingApproval): string {
  const payee = row.payee === undefined ? null : String(row.payee);
  const money = formatMinor(row.amount, row.currency, readLang());
  if (row.subject === "spend" && payee !== null) {
    return money !== null ? ` · ${money} → ${payee}` : ` · ${copy["spend.amount.unmeasured"]} → ${payee}`;
  }
  const parts: string[] = [];
  if (payee !== null) parts.push(payee);
  if (money !== null) parts.push(money);
  else if (row.amount !== undefined) parts.push(copy["spend.amount.unmeasured"]);
  return parts.length === 0 ? "" : ` · ${parts.join(" · ")}`;
}

function chainLine(
  copy: ReturnType<typeof panelCopy>,
  key: "chain.defer" | "chain.resolve",
  action: RailAction,
): string {
  return copy[key]
    .replace("{decision}", action.record.claims.decision)
    .replace("{reason}", action.record.claims.reasonCode)
    .replace("{ref}", action.record.claims.ref ?? copy.unmeasured)
    .replace("{when}", formatStamp(action.record.claims.timestampMs))
    .replace("{decider}", action.record.claims.decider);
}

function waitingApproval(
  action: RailAction | null,
  pending: PendingApproval[],
): PendingApproval | undefined {
  if (!action || action.record.claims.decision !== "defer") return undefined;
  const row = approvalForRef(pending, action.record.claims.ref);
  return row?.status === "pending" ? row : undefined;
}

function DetailPane({
  action,
  actions,
  pending,
  canApprove,
  onApprove,
  reconcile,
  guarantee,
  pin,
  summary,
  identityMissing,
  warnings,
  witness,
  onInspect,
  pair,
  inspected,
  inspectFailed,
  issuerMatches,
  pinSource,
}: {
  action: RailAction | null;
  actions: RailAction[];
  pending: PendingApproval[];
  canApprove?: boolean;
  onApprove?: (ref: string, requestHash: string) => Promise<ApproveOutcome>;
  reconcile: ReconcileCardReport | null;
  guarantee?: "unconditional" | "conditional";
  pin: string;
  summary: string;
  identityMissing: boolean;
  warnings: RailWarning[];
  witness: string | null;
  onInspect?: () => void;
  pair?: { defer: { decision: string; reasonCode: string } | null; resolution: { decision: string; reasonCode: string } | null };
  inspected: boolean;
  inspectFailed: string | null;
  issuerMatches: boolean | null;
  pinSource: "env" | "own-key" | null;
}) {
  const copy = panelCopy();
  const missing = action?.rule && "missing" in action.rule ? action.rule.missing : null;
  const matched = action?.rule && !("missing" in action.rule) ? action.rule : null;
  const inputs = action?.inputs;
  const ledgerPair = pairFromLedger(actions, action, pending);
  const waiting = waitingApproval(action, pending);
  const approveRef = useRef<HTMLDivElement>(null);
  const offersApprove = Boolean(canApprove && onApprove && waiting);
  const waitingRef = waiting?.ref ?? null;
  // On a phone the detail band sits below the list. Selecting a waiting
  // record used to open the pane off-screen, so the tap looked like nothing
  // happened. Bring the control the operator just asked for into view.
  // Keyed on the record, not on the row or the handler: the screen redraws
  // every second and re-reads the ledger every five, and each pass hands
  // down new objects. Keyed on those, the page pulled the operator back to
  // the button every second they tried to read anything else.
  useLayoutEffect(() => {
    if (!offersApprove) return;
    approveRef.current?.scrollIntoView?.({ block: "center", inline: "nearest" });
  }, [offersApprove, waitingRef]);
  const scope = evidenceScope(copy, {
    action,
    inspected,
    issuerMatches,
    pinSource,
    reconcile,
  });
  const spend = action ? spendFields(copy, action, pending, reconcile) : null;
  return (
    <div className="detail-pane">
      <h2>{copy["detail.title"]}</h2>
      {!action ? (
        <p className="muted">{copy["records.empty"]}</p>
      ) : (
        <>
          {/* The pane answers the five questions the product is built on, in
              their own words. A question it cannot answer yet is written down
              and marked, not dropped: a list that quietly omits what it cannot
              show is the thing this screen exists to replace. */}
          <h3>{copy["question.did"]}</h3>
          <p>
            {action.record.claims.subject} · {shortHash(action.record.claims.ref)}
          </p>
          {spend ? (
            <section className="spend-fields" data-testid="spend-fields">
              <p>{spend.amount}</p>
              <p>{spend.payee}</p>
              <p>{spend.approver}</p>
              <p>{spend.statement}</p>
            </section>
          ) : null}
          <p data-testid="detail-result">{outcomeText(copy, action, pending)}</p>
          {canApprove && onApprove && waiting ? (
            <div ref={approveRef} data-testid="record-approve">
              <ApproveControl copy={copy} row={waiting} onApprove={onApprove} />
            </div>
          ) : null}
          {ledgerPair.defer && ledgerPair.resolution ? (
            <div data-testid="explain-pair" className="decision-chain">
              <p>{chainLine(copy, "chain.defer", ledgerPair.defer)}</p>
              <p>{chainLine(copy, "chain.resolve", ledgerPair.resolution)}</p>
            </div>
          ) : pair?.defer && pair.resolution ? (
            <p data-testid="explain-pair">
              {pair.defer.decision} {pair.defer.reasonCode} → {pair.resolution.decision} {pair.resolution.reasonCode}
            </p>
          ) : null}
          <h3>{copy["question.counterpart"]}</h3>
          <p>
            {action.effect
              ? `${action.effect.row.effectClass} ${action.effect.receipt ? copy["receipt.yes"] : copy["receipt.no"]} · ${action.effect.attestation ? copy["attestation.yes"] : copy["attestation.no"]}`
              : copy["effect.none"]}{" "}
            · {fillCopy(copy["witness.label"], { who: witness ?? copy.disconnected })}
          </p>
          <ul data-testid="evidence-scope" className="evidence-scope">
            <li data-testid="scope-signature">{scope.signature}</li>
            <li data-testid="scope-witness">{scope.witness}</li>
            <li data-testid="scope-external">{scope.external}</li>
            <li>
              {fillCopy(copy["guarantee.label"], { state: guaranteeLabel(copy, guarantee) })} · {pin}
              {warnings.length > 0 ? ` ${warningCodes(warnings)}` : ""}
              {summary && !/^balanced$/i.test(summary.trim()) ? ` ${summary}` : ""}
            </li>
          </ul>
          <h3>{copy["question.current"]}</h3>
          {identityMissing ? (
            <p className="rule-missing" data-testid="detail-identity">
              {copy["detail.identityMissing"]}
            </p>
          ) : inputs ? (
            <p>
              {inputs.principal.brain} · {inputs.principal.scopes.join(", ")} ·{" "}
              {inputs.inputs.map((i) => `${i.id} ${shortHash(i.versionHash)} ${i.validFromMs}–${i.validUntilMs}`).join("; ") || copy["inputs.none"]}
            </p>
          ) : (
            <p className="muted">{copy.disconnected}</p>
          )}
          <h3>{copy["question.impact"]}</h3>
          <p className="muted" data-testid="question-impact">{copy["question.impact.empty"]}</p>
          <h3>{copy["question.rules"]}</h3>
          {missing ? (
            <p className="rule-missing" data-testid="detail-policy">{copy["line.rule.missing"]}</p>
          ) : (
            <p data-testid="detail-policy">
              {shortHash(action.record.claims.policyHash)} {matched?.text ?? copy["line.rule.none"]}
            </p>
          )}
          {onInspect ? (
            <button type="button" className="contest focusable" onClick={onInspect}>
              {copy.inspect}
            </button>
          ) : null}
          {inspectFailed ? (
            <p className="rule-missing" data-testid="inspect-failed">
              {copy["inspect.failed"].replace("{error}", inspectFailed)}
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}
