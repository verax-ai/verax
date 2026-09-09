import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { Galaxy, type GalaxySelect } from "@verax-ai/galaxy/react";
import { inventoryToGalaxy, mergeGalaxy, type GalaxyModel, type Inventory } from "@verax-ai/galaxy";
import { ledgerToGalaxy } from "../galaxy/adapter.ts";
import { coverageLine } from "../galaxy/coverage-line.ts";
import { panelCopy } from "../copy.ts";
import { ReconcileCard, type ReconcileCardReport } from "../ReconcileCard.tsx";
import { type RailContestResult } from "../rail/Rail.tsx";
import type { PendingApproval, RailAction, RailFinding, RailWarning } from "../rail/types.ts";
import { RecordList } from "../records/RecordList.tsx";
import { pairFromLedger } from "../records/pair.ts";
import { outcomeText, recordLine } from "../records/line.ts";
import { evidenceScope, pinLabel, warningCodes } from "../records/scope.ts";
import { spendFields } from "../records/spend.ts";
import { Timeline } from "../records/Timeline.tsx";
import { formatStamp } from "../records/timeline.ts";
import bodyEn from "../../../body-map/src/copy/en.json";
import bodyTr from "../../../body-map/src/copy/tr.json";

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

const TAB_IDS = ["records", "galaxy", "status"] as const;
type TabId = (typeof TAB_IDS)[number];
const TAB_COPY: Record<TabId, "tab.records" | "tab.galaxy" | "tab.status"> = {
  records: "tab.records",
  galaxy: "tab.galaxy",
  status: "tab.status",
};

function readTab(): TabId {
  if (typeof window === "undefined") return "records";
  const q = new URLSearchParams(window.location.search).get("tab");
  if (q === "history") return "records";
  return TAB_IDS.includes(q as TabId) ? (q as TabId) : "records";
}

const ANATOMY = [
  { key: "head", tr: bodyTr["head.part"], en: bodyEn["head.part"] },
  { key: "face", tr: bodyTr["face.part"], en: bodyEn["face.part"] },
  { key: "core", tr: bodyTr["core.part"], en: bodyEn["core.part"] },
  { key: "hands", tr: bodyTr["hands.part"], en: bodyEn["hands.part"] },
  { key: "torso", tr: bodyTr["torso.part"], en: bodyEn["torso.part"] },
  { key: "ground", tr: bodyTr["ground.part"], en: bodyEn["ground.part"] },
  { key: "whole", tr: bodyTr["whole.part"], en: bodyEn["whole.part"] },
] as const;

function reducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function shortHash(h: string | null | undefined): string {
  if (!h) return "—";
  return h.length > 12 ? `${h.slice(0, 8)}…` : h;
}

/**
 * An empty ledger draws an empty sky, which reads as a broken page rather than
 * as "nothing has been decided yet". The scene stays - the core still says
 * whether the body has a heartbeat - and a line says why it is empty.
 */
function GalaxyTab({
  model,
  ready,
  onSelect,
  coverageText,
  focusId,
  onFocus,
}: {
  model: GalaxyModel;
  ready: boolean;
  onSelect: (hit: GalaxySelect) => void;
  coverageText: string;
  focusId: string | null;
  onFocus: (id: string | null) => void;
}) {
  const copy = panelCopy();
  const empty =
    model.stars.length === 0 && model.planets.length === 0 && model.agents.length === 0;
  return (
    <>
      <p className="galaxy-coverage" data-testid="galaxy-coverage">
        {coverageText}
      </p>
      {empty ? (
        <p className="galaxy-empty" data-testid="galaxy-empty">
          {copy["galaxy.empty"]}
        </p>
      ) : null}
      <Galaxy
        model={model}
        ready={ready}
        onSelect={onSelect}
        hiddenLabelsText={copy["galaxy.labels.hidden"]}
        crowdedLabelsText={copy["galaxy.labels.hidden.crowd"]}
        focusId={focusId}
        onFocus={onFocus}
        focusText={copy["galaxy.focus"]}
        leaveFocusText={copy["galaxy.focus.leave"]}
      />
    </>
  );
}

export function Observatory({
  actions,
  status,
  demo,
  health = null,
  reconcile = null,
  errorText = null,
  stale = false,
  ageMs = null,
  onRefresh,
  onShowDemo,
  onContest,
  pending = [],
  inventory = null,
  nowMs = Date.now(),
}: {
  actions: RailAction[];
  status: ObservatoryStatus;
  demo: boolean;
  pending?: PendingApproval[];
  health?: Healthz;
  reconcile?: ReconcileCardReport | null;
  errorText?: string | null;
  stale?: boolean;
  ageMs?: number | null;
  inventory?: Inventory | null;
  nowMs?: number;
  onRefresh?: () => void;
  onShowDemo?: () => void;
  onContest?: (ref: string) => Promise<RailContestResult | void>;
}) {
  const initialTab = useMemo<TabId>(() => readTab(), []);
  const [tab, setTab] = useState<TabId>(initialTab);
  const [selected, setSelected] = useState<string | null>(actions[0]?.record.claims.ref ?? null);
  const [focusId, setFocusId] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    const q = new URLSearchParams(window.location.search).get("focus");
    return q && q.length > 0 ? q : null;
  });
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

  const action = actions.find((a) => a.record.claims.ref === selected) ?? actions[0] ?? null;
  const audit = action?.record.claims.ref ? audits[action.record.claims.ref] : undefined;
  const guarantee = audit?.guarantee ?? action?.guarantee;
  const pin = pinLabel(audit?.trustRoot?.source ?? action?.trustRoot?.source ?? null);
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
    if (actions[0]?.record.claims.ref && selected === null) {
      setSelected(actions[0].record.claims.ref);
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
  const ledgerModel = useMemo(
    () => ledgerToGalaxy(actions, health, reconcile),
    [actions, health, reconcile],
  );
  const scene = useMemo(() => {
    if (!inventory) return ledgerModel;
    return mergeGalaxy(ledgerModel, inventoryToGalaxy(inventory));
  }, [ledgerModel, inventory]);
  const cover = coverageLine(inventory, ledgerModel, nowMs, copy, demo);
  const lastMs = health?.lastDecisionMs ?? actions[0]?.record.claims.timestampMs ?? null;
  const witnessCounts = actions.reduce<Record<string, number>>((acc, a) => {
    const w = a.witnessClass ?? a.effect?.witnessClass ?? "none";
    acc[w] = (acc[w] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className={`observatory${reducedMotion() ? "" : ""}`}>
      {demo ? <p className="demo-badge">{copy["badge.demo"]}</p> : null}
      <div className="obs-top">
        <div role="tablist" aria-label="Gözlemevi" onKeyDown={onKeyTabs}>
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
        <p className={`rail-status ${status}${stale ? " stale" : ""}`} data-status={status}>
          {status === "error" ? (
            <>
              <span>error</span> {errorText}
            </>
          ) : (
            status
          )}
        </p>
        {ageMs !== null ? <p className={stale ? "age stale" : "age"}>last read {Math.max(0, Math.floor(ageMs / 1000))} s ago</p> : null}
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
      <aside className="obs-left" aria-label="Kayıt grupları">
        <h2>{copy["rail.ledger.projects"]}</h2>
        <p className="muted">{copy.disconnected}</p>
        <h2>{copy["rail.ledger.agents"]}</h2>
        {brains.length === 0 ? <p className="muted">{copy.disconnected}</p> : (
          <ul className="rail-ledger" data-testid="rail-ledger-agents">
            {brains.map((b) => <li key={b}>{b}</li>)}
          </ul>
        )}
        {inventory ? (
          <>
            <h2>{copy["rail.inventory.groups"]}</h2>
            {inventory.groups.length === 0 ? (
              <p className="muted">{copy.disconnected}</p>
            ) : (
              <ul className="rail-inventory" data-testid="rail-inventory-groups">
                {inventory.groups.map((g) => (
                  <li key={g.id}>
                    <button type="button" className="focusable" onClick={() => { setFocusId(g.id); setTab("galaxy"); }}>
                      {g.label}
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <h2>{copy["rail.inventory.agents"]}</h2>
            {inventory.agents.length === 0 ? (
              <p className="muted">{copy.disconnected}</p>
            ) : (
              <ul className="rail-inventory" data-testid="rail-inventory-agents">
                {inventory.agents.map((a) => (
                  <li key={a.id}>
                    <button
                      type="button"
                      className="focusable"
                      onClick={() => {
                        if (a.groupId) {
                          setFocusId(a.groupId);
                          setTab("galaxy");
                        }
                      }}
                    >
                      {a.label}
                    </button>
                  </li>
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
      <section className="obs-main" id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {tab === "records" ? (
          <RecordList
            actions={actions}
            status={status}
            pending={pending}
            reconcile={reconcile}
            selected={action?.record.claims.ref ?? selected}
            onSelect={(ref) => setSelected(ref)}
          />
        ) : null}
        {tab === "galaxy" ? (
          <GalaxyTab
            model={scene}
            ready={status !== "loading"}
            coverageText={cover.text}
            focusId={focusId}
            onFocus={setFocusId}
            onSelect={(hit) => {
              if (hit.kind === "star") setSelected(hit.id);
              if (hit.kind === "planet") setFocusId(hit.id);
            }}
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
          />
        ) : null}
      </section>
      <aside className="obs-detail" aria-label="İşlem ayrıntısı">
        <DetailPane
          action={action}
          actions={actions}
          pending={pending}
          reconcile={reconcile}
          guarantee={guarantee}
          pin={pin}
          summary={summary}
          identityMissing={identityMissing}
          warnings={audit?.warnings ?? action?.warnings ?? []}
          witness={audit?.witnessClass ?? action?.witnessClass ?? action?.effect?.witnessClass ?? null}
          pair={audit?.pair}
          inspected={Boolean(action?.record.claims.ref && audits[action.record.claims.ref])}
          issuerMatches={audit?.trustRoot?.issuerMatches ?? action?.trustRoot?.issuerMatches ?? null}
          pinSource={audit?.trustRoot?.source ?? action?.trustRoot?.source ?? null}
          onInspect={action?.record.claims.ref ? () => void contest(action.record.claims.ref as string) : undefined}
        />
      </aside>
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

function StatusView({
  actions,
  health,
  lastMs,
  witnessCounts,
  reconcile,
  pending,
}: {
  actions: RailAction[];
  health: Healthz;
  lastMs: number | null;
  witnessCounts: Record<string, number>;
  reconcile: ReconcileCardReport | null;
  pending: PendingApproval[];
}) {
  const copy = panelCopy();
  const effects = actions.filter((a) => a.effect).length;
  const lock = health && "lock" in health && health.lock != null ? String(typeof health.lock === "string" ? health.lock : health.lock.held ? "held" : "open") : "bağlı değil";
  const pinSource = actions.find((a) => a.trustRoot)?.trustRoot?.source;
  const open = pending.filter((p) => p.status === "pending");
  return (
    <div className="status-view">
      <p>karar {health?.decisions ?? actions.length}</p>
      <p>etki {health?.effects ?? effects}</p>
      <p>son karar {lastMs ?? "bağlı değil"}</p>
      <p>kilit {lock}</p>
      <p>tanık {Object.entries(witnessCounts).map(([k, n]) => `${k} ${n}`).join(" · ") || "bağlı değil"}</p>
      <p>pin kaynağı {pinSource ?? "denetlenmedi"}</p>
      <section data-testid="pending-approvals" className="pending-approvals">
        <h3>{copy["pending.title"]}</h3>
        {open.length === 0 ? <p className="muted">{copy["pending.empty"]}</p> : (
          <ul>
            {open.map((p) => (
              <li key={p.ref}>
                {p.ref} · {p.subject} · {p.ruleText ?? ""} · {p.brain}
                {p.subject === "spend" && p.amount !== undefined && p.payee !== undefined
                  ? ` · ${String(p.amount)} ${p.currency !== undefined ? String(p.currency) : ""} → ${String(p.payee)}`.replace("  ", " ")
                  : `${p.payee !== undefined ? ` · ${String(p.payee)}` : ""}${p.amount !== undefined ? ` · ${String(p.amount)}` : ""}`}
              </li>
            ))}
          </ul>
        )}
      </section>
      <ReconcileCard report={reconcile} />
      <AnatomyDocument />
    </div>
  );
}

function AnatomyDocument() {
  const copy = panelCopy();
  return (
    <section className="anatomy-document" data-testid="anatomy-document">
      <h3>{copy["tab.anatomy"]}</h3>
      <p className="muted">{copy["anatomy.approx"]}</p>
      <ul>
        {ANATOMY.map((a) => (
          <li key={a.key} data-anchor={a.key}>
            {a.tr} / {a.en}
          </li>
        ))}
      </ul>
    </section>
  );
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

function DetailPane({
  action,
  actions,
  pending,
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
  issuerMatches,
  pinSource,
}: {
  action: RailAction | null;
  actions: RailAction[];
  pending: PendingApproval[];
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
  issuerMatches: boolean | null;
  pinSource: "env" | "own-key" | null;
}) {
  const copy = panelCopy();
  const missing = action?.rule && "missing" in action.rule ? action.rule.missing : null;
  const matched = action?.rule && !("missing" in action.rule) ? action.rule : null;
  const inputs = action?.inputs;
  const ledgerPair = pairFromLedger(actions, action, pending);
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
          <h3>{copy["detail.request"]}</h3>
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
          <h3>{copy["detail.inputs"]}</h3>
          {identityMissing ? (
            <p className="rule-missing">identity hash on the record; inputs document unavailable</p>
          ) : inputs ? (
            <p>
              {inputs.principal.brain} · {inputs.principal.scopes.join(", ")} ·{" "}
              {inputs.inputs.map((i) => `${i.id} ${shortHash(i.versionHash)} ${i.validFromMs}–${i.validUntilMs}`).join("; ") || "inputs []"}
            </p>
          ) : (
            <p className="muted">{copy.disconnected}</p>
          )}
          <h3>{copy["detail.policy"]}</h3>
          {missing ? (
            <p className="rule-missing">{missing}</p>
          ) : (
            <p>
              {shortHash(action.record.claims.policyHash)} {matched?.text ?? "no matching rule"}
            </p>
          )}
          <h3>{copy["detail.result"]}</h3>
          <p data-testid="detail-result">{outcomeText(copy, action, pending)}</p>
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
          <h3>{copy["detail.evidence"]}</h3>
          <p>
            {action.effect
              ? `${action.effect.row.effectClass} ${action.effect.receipt ? copy["receipt.yes"] : copy["receipt.no"]} · ${action.effect.attestation ? copy["attestation.yes"] : copy["attestation.no"]}`
              : copy["effect.none"]}{" "}
            · tanık {witness ?? "none"}
          </p>
          <h3>{copy["detail.scope"]}</h3>
          <ul data-testid="evidence-scope" className="evidence-scope">
            <li data-testid="scope-signature">{scope.signature}</li>
            <li data-testid="scope-witness">{scope.witness}</li>
            <li data-testid="scope-external">{scope.external}</li>
            <li>
              guarantee {guarantee ?? copy.disconnected} {pin}
              {warnings.length > 0 ? ` ${warningCodes(warnings)}` : ""}
              {summary && !/^balanced$/i.test(summary.trim()) ? ` ${summary}` : ""}
            </li>
          </ul>
          {onInspect ? (
            <button type="button" className="contest focusable" onClick={onInspect}>
              {copy.inspect}
            </button>
          ) : null}
        </>
      )}
    </div>
  );
}
