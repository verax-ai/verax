import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { Galaxy } from "@verax-ai/galaxy/react";
import { ledgerToGalaxy } from "../galaxy/adapter.ts";
import { panelCopy } from "../copy.ts";
import { ReconcileCard, type ReconcileCardReport } from "../ReconcileCard.tsx";
import { Rail, type RailContestResult } from "../rail/Rail.tsx";
import type { PendingApproval, RailAction, RailFinding, RailWarning } from "../rail/types.ts";
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

const TAB_IDS = ["status", "galaxy", "history"] as const;
type TabId = (typeof TAB_IDS)[number];
const TAB_COPY: Record<TabId, "tab.status" | "tab.galaxy" | "tab.history"> = {
  status: "tab.status",
  galaxy: "tab.galaxy",
  history: "tab.history",
};

const ANATOMY = [
  { key: "head", tr: bodyTr["head.part"], en: bodyEn["head.part"], prod: bodyTr["head.prod"], left: "50.8%", top: "5.5%" },
  { key: "face", tr: bodyTr["face.part"], en: bodyEn["face.part"], prod: bodyTr["face.prod"], left: "50.8%", top: "10.6%" },
  { key: "core", tr: bodyTr["core.part"], en: bodyEn["core.part"], prod: bodyTr["core.prod"], left: "45.5%", top: "23.7%" },
  { key: "hands", tr: bodyTr["hands.part"], en: bodyEn["hands.part"], prod: bodyTr["hands.prod"], left: "50.8%", top: "43.6%" },
  { key: "torso", tr: bodyTr["torso.part"], en: bodyEn["torso.part"], prod: bodyTr["torso.prod"], left: "51.5%", top: "48%" },
  { key: "ground", tr: bodyTr["ground.part"], en: bodyEn["ground.part"], prod: bodyTr["ground.prod"], left: "60.6%", top: "91.8%" },
  { key: "whole", tr: bodyTr["whole.part"], en: bodyEn["whole.part"], prod: bodyTr["whole.prod"], left: "50%", top: "70%" },
] as const;

function reducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function pinLabel(source: "env" | "own-key" | null | undefined): string {
  if (source === "env") return "pin: env";
  if (source === "own-key") return "pin: own key";
  return "pin: none";
}

function shortHash(h: string | null | undefined): string {
  if (!h) return "—";
  return h.length > 12 ? `${h.slice(0, 8)}…` : h;
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
  onRefresh?: () => void;
  onShowDemo?: () => void;
  onContest?: (ref: string) => Promise<RailContestResult | void>;
}) {
  const initialTab = useMemo<TabId>(() => {
    if (typeof window === "undefined") return "galaxy";
    const q = new URLSearchParams(window.location.search).get("tab");
    return TAB_IDS.includes(q as TabId) ? (q as TabId) : "galaxy";
  }, []);
  const [tab, setTab] = useState<TabId>(initialTab);
  const [selected, setSelected] = useState<string | null>(actions[0]?.record.claims.ref ?? null);
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
        <h2>{copy.projects}</h2>
        <p className="muted">{copy.disconnected}</p>
        <h2>{copy.agents}</h2>
        {brains.length === 0 ? <p className="muted">{copy.disconnected}</p> : (
          <ul>{brains.map((b) => <li key={b}>{b}</li>)}</ul>
        )}
        <h2>{copy.records}</h2>
        <ul>
          {actions.map((a) => {
            const ref = a.record.claims.ref ?? "unknown";
            return (
              <li key={ref}>
                <button type="button" className="focusable" onClick={() => { setSelected(ref); setTab("history"); }}>
                  {ref}
                </button>
              </li>
            );
          })}
        </ul>
      </aside>
      <section className="obs-main" id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
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
        {tab === "galaxy" ? (
          <Galaxy
            model={ledgerToGalaxy(actions, health, reconcile)}
            onSelect={(hit) => {
              if (hit.kind === "star") setSelected(hit.id);
            }}
          />
        ) : null}
        {tab === "history" ? (
          <Rail
            actions={actions}
            onContest={contest}
            onSelect={(ref) => setSelected(ref)}
          />
        ) : null}
      </section>
      <aside className="obs-detail" aria-label="İşlem ayrıntısı">
        <DetailPane
          action={action}
          guarantee={guarantee}
          pin={pin}
          summary={summary}
          identityMissing={identityMissing}
          warnings={audit?.warnings ?? action?.warnings ?? []}
          witness={audit?.witnessClass ?? action?.witnessClass ?? action?.effect?.witnessClass ?? null}
          pair={audit?.pair}
          onInspect={action?.record.claims.ref ? () => void contest(action.record.claims.ref as string) : undefined}
        />
      </aside>
      <footer className="obs-timeline" aria-label="Zaman çizgisi">
        <ol>
          {actions.map((a) => (
            <li key={a.record.claims.ref ?? a.record.claims.timestampMs}>
              <button
                type="button"
                className="focusable"
                onClick={() => {
                  if (a.record.claims.ref) setSelected(a.record.claims.ref);
                  setTab("history");
                }}
              >
                {a.record.claims.timestampMs} {a.record.claims.subject} {a.record.claims.decision}
              </button>
            </li>
          ))}
        </ol>
      </footer>
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
            {a.tr} / {a.en} · {a.prod}
          </li>
        ))}
      </ul>
    </section>
  );
}

const MAP_N = 12;
const BODY_X = 220;
const BODY_Y = 80;

function SystemMap({ actions }: { actions: RailAction[] }) {
  const copy = panelCopy();
  const recent = actions.slice(0, MAP_N);
  const pairs = new Map<string, { brain: string; subject: string; count: number }>();
  for (const a of recent) {
    const brain = a.inputs?.principal.brain ?? "unknown";
    const subject = a.record.claims.subject;
    const key = `${brain}\t${subject}`;
    const prev = pairs.get(key);
    pairs.set(key, { brain, subject, count: (prev?.count ?? 0) + 1 });
  }
  const brains = [...new Set([...pairs.values()].map((p) => p.brain))];
  const subjects = [...new Set([...pairs.values()].map((p) => p.subject))];
  const newest = recent[0];
  const newestKey = newest
    ? `${newest.inputs?.principal.brain ?? "unknown"}\t${newest.record.claims.subject}`
    : "";
  const [flash, setFlash] = useState(newestKey);
  useEffect(() => {
    if (reducedMotion() || newestKey === "") {
      setFlash("");
      return;
    }
    setFlash(newestKey);
    const id = window.setTimeout(() => setFlash(""), 400);
    return () => window.clearTimeout(id);
  }, [newestKey]);

  const max = Math.max(1, ...[...pairs.values()].map((p) => p.count));
  return (
    <svg className="system-map" viewBox="0 0 640 320" role="img" aria-label={copy["tab.map"]}>
      {brains.map((b, i) => (
        <text key={b} x={80} y={40 + i * 36} fill="#EAF2F8" textAnchor="middle">
          {b}
        </text>
      ))}
      <text x={BODY_X} y={BODY_Y} fill="#EAF2F8" textAnchor="middle">
        {copy["map.body"]}
      </text>
      {subjects.map((s, i) => (
        <text key={s} x={400} y={40 + i * 28} fill="#EAF2F8">
          {s}
        </text>
      ))}
      {[...pairs.values()].map((p) => {
        const bi = brains.indexOf(p.brain);
        const si = subjects.indexOf(p.subject);
        const x1 = 80;
        const y1 = 40 + bi * 36;
        const x2 = 400;
        const y2 = 40 + si * 28;
        const thick = 1 + (2.5 * p.count) / max;
        const op = 0.25 + (0.55 * p.count) / max;
        const on = flash === `${p.brain}\t${p.subject}`;
        return (
          <g key={`${p.brain}-${p.subject}`}>
            <line
              data-edge={`${p.brain}|${p.subject}`}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke="#5CE1FF"
              strokeWidth={thick}
              strokeOpacity={on ? 1 : op}
              className={on ? "edge-flash" : undefined}
            />
            <line
              x1={x1}
              y1={y1}
              x2={BODY_X}
              y2={BODY_Y}
              stroke="#5CE1FF"
              strokeWidth={1}
              strokeOpacity={0.2}
            />
          </g>
        );
      })}
    </svg>
  );
}

function DetailPane({
  action,
  guarantee,
  pin,
  summary,
  identityMissing,
  warnings,
  witness,
  onInspect,
  pair,
}: {
  action: RailAction | null;
  guarantee?: "unconditional" | "conditional";
  pin: string;
  summary: string;
  identityMissing: boolean;
  warnings: RailWarning[];
  witness: string | null;
  onInspect?: () => void;
  pair?: { defer: { decision: string; reasonCode: string } | null; resolution: { decision: string; reasonCode: string } | null };
}) {
  const copy = panelCopy();
  const missing = action?.rule && "missing" in action.rule ? action.rule.missing : null;
  const matched = action?.rule && !("missing" in action.rule) ? action.rule : null;
  const inputs = action?.inputs;
  return (
    <div className="detail-pane">
      <h2>{copy["detail.title"]}</h2>
      {!action ? <p className="muted">{copy.disconnected}</p> : (
        <>
          <h3>{copy["detail.request"]}</h3>
          <p>
            {action.record.claims.subject} · {shortHash(action.record.claims.ref)}
          </p>
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
          {missing ? <p className="rule-missing">{missing}</p> : (
            <p>
              {shortHash(action.record.claims.policyHash)} {matched?.text ?? "no matching rule"}
            </p>
          )}
          <h3>{copy["detail.result"]}</h3>
          <p>
            {action.record.claims.decision} {action.record.claims.reasonCode}
          </p>
          {pair?.defer && pair.resolution ? (
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
          <p data-testid="evidence-scope">
            guarantee {guarantee ?? copy.disconnected} {pin}
            {warnings.length > 0 ? ` ${warnings.map((w) => w.code).join(" ")}` : ""}
            {summary && !/^balanced$/i.test(summary.trim()) ? ` ${summary}` : ""}
          </p>
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
