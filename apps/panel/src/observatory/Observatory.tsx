import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { Stage } from "@verax-ai/presence";
import { ReconcileCard, type ReconcileCardReport } from "../ReconcileCard.tsx";
import { Rail, type RailContestResult } from "../rail/Rail.tsx";
import type { RailAction, RailFinding, RailWarning } from "../rail/types.ts";
import en from "../../../body-map/src/copy/en.json";
import tr from "../../../body-map/src/copy/tr.json";

export type Healthz = {
  ok?: boolean;
  decisions?: number;
  effects?: number;
  lastDecisionMs?: number | null;
  lock?: { held: boolean; pid?: number } | string | null;
} | null;

export type ObservatoryStatus = "loading" | "ok" | "error" | "empty";

const TABS = [
  { id: "status", label: "Genel durum" },
  { id: "map", label: "Sistem haritası" },
  { id: "history", label: "İşlem geçmişi" },
  { id: "anatomy", label: "Anatomi" },
] as const;

type TabId = (typeof TABS)[number]["id"];

const ANATOMY = [
  { key: "head", tr: tr["head.part"], en: en["head.part"], prod: tr["head.prod"] },
  { key: "face", tr: tr["face.part"], en: en["face.part"], prod: tr["face.prod"] },
  { key: "core", tr: tr["core.part"], en: en["core.part"], prod: tr["core.prod"] },
  { key: "hands", tr: tr["hands.part"], en: en["hands.part"], prod: tr["hands.prod"] },
  { key: "torso", tr: tr["torso.part"], en: en["torso.part"], prod: tr["torso.prod"] },
  { key: "ground", tr: tr["ground.part"], en: en["ground.part"], prod: tr["ground.prod"] },
  { key: "whole", tr: tr["whole.part"], en: en["whole.part"], prod: tr["whole.prod"] },
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
}: {
  actions: RailAction[];
  status: ObservatoryStatus;
  demo: boolean;
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
    if (typeof window === "undefined") return "status";
    const q = new URLSearchParams(window.location.search).get("tab");
    return TABS.some((t) => t.id === q) ? (q as TabId) : "status";
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
    const i = TABS.findIndex((t) => t.id === tab);
    if (e.key === "ArrowRight") {
      e.preventDefault();
      setTab(TABS[(i + 1) % TABS.length]!.id);
    }
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      setTab(TABS[(i - 1 + TABS.length) % TABS.length]!.id);
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
        },
      }));
    }
    return out;
  };

  const lastMs = health?.lastDecisionMs ?? actions[0]?.record.claims.timestampMs ?? null;
  const witnessCounts = actions.reduce<Record<string, number>>((acc, a) => {
    const w = a.witnessClass ?? a.effect?.witnessClass ?? "none";
    acc[w] = (acc[w] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className={`observatory${reducedMotion() ? "" : ""}`}>
      {demo ? <p className="demo-badge">ÖRNEK SENARYO</p> : null}
      <div className="obs-top">
        <div role="tablist" aria-label="Gözlemevi" onKeyDown={onKeyTabs}>
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls={`panel-${t.id}`}
              tabIndex={tab === t.id ? 0 : -1}
              className="focusable"
              onClick={() => setTab(t.id)}
            >
              {t.label}
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
            Refresh
          </button>
        ) : null}
        {status === "error" && onShowDemo ? (
          <button type="button" className="refresh focusable" onClick={onShowDemo}>
            Örnek senaryoyu göster
          </button>
        ) : null}
      </div>
      <aside className="obs-left" aria-label="Kayıt grupları">
        <h2>Projeler</h2>
        <p className="muted">bağlı değil</p>
        <h2>Ajanlar</h2>
        {brains.length === 0 ? <p className="muted">bağlı değil</p> : (
          <ul>{brains.map((b) => <li key={b}>{b}</li>)}</ul>
        )}
        <h2>Kayıtlar</h2>
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
          />
        ) : null}
        {tab === "map" ? <SystemMap actions={actions} /> : null}
        {tab === "history" ? (
          <Rail
            actions={actions}
            onContest={contest}
            onSelect={(ref) => setSelected(ref)}
          />
        ) : null}
        {tab === "anatomy" ? (
          <div className="anatomy">
            <Stage particles={false} rain={false} breath="procedural" />
            <ul className="anatomy-labels">
              {ANATOMY.map((a) => (
                <li key={a.key} data-anchor={a.key}>
                  {a.tr} / {a.en} · {a.prod}
                </li>
              ))}
            </ul>
          </div>
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
}: {
  actions: RailAction[];
  health: Healthz;
  lastMs: number | null;
  witnessCounts: Record<string, number>;
  reconcile: ReconcileCardReport | null;
}) {
  const effects = actions.filter((a) => a.effect).length;
  const lock = health && "lock" in health && health.lock != null ? String(typeof health.lock === "string" ? health.lock : health.lock.held ? "held" : "open") : "bağlı değil";
  const pinSource = actions.find((a) => a.trustRoot)?.trustRoot?.source;
  return (
    <div className="status-view">
      <p>karar {health?.decisions ?? actions.length}</p>
      <p>etki {health?.effects ?? effects}</p>
      <p>son karar {lastMs ?? "bağlı değil"}</p>
      <p>kilit {lock}</p>
      <p>tanık {Object.entries(witnessCounts).map(([k, n]) => `${k} ${n}`).join(" · ") || "bağlı değil"}</p>
      <p>pin kaynağı {pinSource ?? "denetlenmedi"}</p>
      <ReconcileCard report={reconcile} />
    </div>
  );
}

function SystemMap({ actions }: { actions: RailAction[] }) {
  const brains = [...new Set(actions.map((a) => a.inputs?.principal.brain).filter(Boolean))] as string[];
  const tools = [...new Set(actions.map((a) => a.record.claims.subject))];
  const policy = shortHash(actions[0]?.record.claims.policyHash);
  return (
    <svg className="system-map" viewBox="0 0 640 320" role="img" aria-label="Sistem haritası">
      {brains.map((b, i) => (
        <text key={b} x={40} y={40 + i * 28} fill="#EAF2F8">{b}</text>
      ))}
      <text x={220} y={80} fill="#EAF2F8">gövde</text>
      {tools.map((t, i) => (
        <text key={t} x={360} y={40 + i * 24} fill="#EAF2F8">{t}</text>
      ))}
      <text x={40} y={220} fill="#EAF2F8">politika {policy}</text>
      <text x={220} y={220} fill="#EAF2F8">defter</text>
      <text x={360} y={220} fill="#EAF2F8">imzalayıcılar</text>
      <text x={500} y={220} fill="#EAF2F8">tanık self</text>
      {actions.slice(0, 8).map((a, i) => (
        <line
          key={a.record.claims.ref ?? i}
          x1={80}
          y1={50}
          x2={220}
          y2={80}
          stroke="#5CE1FF"
          strokeOpacity={0.25 + i * 0.05}
        />
      ))}
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
}: {
  action: RailAction | null;
  guarantee?: "unconditional" | "conditional";
  pin: string;
  summary: string;
  identityMissing: boolean;
  warnings: RailWarning[];
  witness: string | null;
  onInspect?: () => void;
}) {
  const missing = action?.rule && "missing" in action.rule ? action.rule.missing : null;
  const matched = action?.rule && !("missing" in action.rule) ? action.rule : null;
  const inputs = action?.inputs;
  return (
    <div className="detail-pane">
      <h2>İşlem ayrıntısı</h2>
      {!action ? <p className="muted">bağlı değil</p> : (
        <>
          <h3>Talep</h3>
          <p>
            {action.record.claims.subject} · {shortHash(action.record.claims.ref)}
          </p>
          <h3>Kullanılan bilgi</h3>
          {identityMissing ? (
            <p className="rule-missing">identity hash on the record; inputs document unavailable</p>
          ) : inputs ? (
            <p>
              {inputs.principal.brain} · {inputs.principal.scopes.join(", ")} ·{" "}
              {inputs.inputs.map((i) => `${i.id} ${shortHash(i.versionHash)} ${i.validFromMs}–${i.validUntilMs}`).join("; ") || "inputs []"}
            </p>
          ) : (
            <p className="muted">bağlı değil</p>
          )}
          <h3>Politika</h3>
          {missing ? <p className="rule-missing">{missing}</p> : (
            <p>
              {shortHash(action.record.claims.policyHash)} {matched?.text ?? "no matching rule"}
            </p>
          )}
          <h3>Sonuç</h3>
          <p>
            {action.record.claims.decision} {action.record.claims.reasonCode}
          </p>
          <h3>Kanıt</h3>
          <p>
            {action.effect
              ? `${action.effect.row.effectClass} receipt ${action.effect.receipt ? "var" : "yok"} · attestation ${action.effect.attestation ? "var" : "yok"}`
              : "etki yok"}{" "}
            · tanık {witness ?? "none"}
          </p>
          <h3>Kanıt kapsamı</h3>
          <p data-testid="evidence-scope">
            guarantee {guarantee ?? "bağlı değil"} {pin}
            {warnings.length > 0 ? ` ${warnings.map((w) => w.code).join(" ")}` : ""}
            {summary && !/^balanced$/i.test(summary.trim()) ? ` ${summary}` : ""}
          </p>
          {onInspect ? (
            <button type="button" className="contest focusable" onClick={onInspect}>
              Kaydı incele
            </button>
          ) : null}
        </>
      )}
    </div>
  );
}
