import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type PointerEvent } from "react";
import { createPortal } from "react-dom";
import codexCss from "./codex.css?raw";
import panelCss from "./panel.css?raw";
import "./fonts.css";
import { panelCopy, readLang, type Copy } from "../copy.ts";
import { fillCopy } from "../fill.ts";
import type { ApproveOutcome } from "../observatory/Observatory.tsx";
import type { PendingApproval, RailAction } from "../rail/types.ts";
import { approveFailureText, approveOutcomeText } from "../records/approve-outcome.ts";
import { formatMinor } from "../records/money.ts";
import { formatStamp } from "../records/timeline.ts";
import { consoleView, layerCounts, splitMoney, type ConsoleView } from "./console.ts";

export type BlackBoxProps = {
  actions: RailAction[];
  pending: PendingApproval[];
  /** The body's own decision count when it gave one; otherwise the rows read. */
  decisions?: number;
  demo: boolean;
  canApprove: boolean;
  onApprove?: (ref: string, requestHash: string) => Promise<ApproveOutcome>;
  onOpenRecord: (ref: string) => void;
  onRefresh?: () => void;
};

const MARK = "/black-box/verax-mark-glow.webp";

/**
 * The black box from the public site, standing on this ledger.
 *
 * The site's stylesheet is copied (less one blur the panel does not draw) and read inside a
 * shadow root, as the site does, so it cannot collide with the panel's. What changed is what
 * the box says: every number on it is counted from the ledger, a layer the body
 * is not connected to says so instead of naming a product, and the console
 * shows a request the body recorded - never a sample, unless the panel is in
 * its sample scenario and says that too.
 */
export function BlackBox(props: BlackBoxProps) {
  const host = useRef<HTMLElement>(null);
  const [mount, setMount] = useState<HTMLElement | null>(null);

  useLayoutEffect(() => {
    const el = host.current;
    if (!el) return;
    const shadow = el.shadowRoot ?? el.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = `${codexCss}\n${panelCss}`;
    const cx = document.createElement("div");
    cx.className = "cx";
    shadow.replaceChildren(style, cx);
    setMount(cx);
  }, []);

  return (
    <section ref={host} className="black-box" data-testid="black-box">
      {mount ? createPortal(<BoxContent {...props} />, mount) : null}
    </section>
  );
}

function clock(ms: number | undefined): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "—";
  return formatStamp(ms).slice(11);
}

function BoxContent(props: BlackBoxProps) {
  const copy = panelCopy();
  const lang = readLang();
  const view = consoleView(props.actions, props.pending);
  const counts = layerCounts(props.actions, props.pending, props.decisions);
  const lastMs = props.actions.reduce<number | undefined>(
    (max, a) => (max === undefined || a.record.claims.timestampMs > max ? a.record.claims.timestampMs : max),
    undefined,
  );
  const consoleRef = useRef<HTMLElement>(null);
  const toConsole = () => consoleRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });

  return (
    <>
      <section className="hero shell">
        <div className="hero-type">
          <div className="eyebrow">
            <i></i> {copy["box.eyebrow"]}
          </div>
          <h2 className="h1">
            {copy["box.title"]}
            <br />
            <span>{copy["box.titleDim"]}</span>
          </h2>
          <p>
            {fillCopy(copy["box.lede.records"], { n: counts.records })}
            <br />
            {fillCopy(copy["box.lede.waiting"], { n: counts.waiting })}
          </p>
          <a
            className="button white"
            href="#box-console"
            onClick={(e) => {
              e.preventDefault();
              toConsole();
            }}
          >
            {copy["box.cta"]} <span>↗</span>
          </a>
          <div className="small-note">
            <span>01 /</span>{" "}
            {lastMs === undefined ? copy["box.note.none"] : fillCopy(copy["box.note.last"], { when: formatStamp(lastMs) })}
          </div>
        </div>
        <Stage copy={copy} counts={counts} />
        <div className="hero-bottom">
          <span>
            <i></i> {copy["box.bottom.left"]}
          </span>
          <span>
            {copy["box.bottom.mid"]} <b>↓</b>
          </span>
          <span>VERAX / 4 {copy["box.bottom.right"]}</span>
        </div>
      </section>

      <section className="lab shell" id="box-console" ref={consoleRef}>
        <div className="section-heading">
          <div>
            <span className="eyebrow">02 / {copy["box.console.eyebrow"]}</span>
            <h2>
              {copy["box.console.title"]}
              <br />
              <span>{copy["box.console.titleDim"]}</span>
            </h2>
          </div>
          <p>{copy[`box.console.note.${view.kind}`]}</p>
        </div>
        <div className="lab-console">
          <div className="lab-bar">
            <div>
              <span className="status-light"></span> VERAX / {copy["box.console.room"]}
            </div>
            <span>{props.demo ? copy["box.console.sample"] : copy["box.console.live"]}</span>
            {props.onRefresh ? (
              <button type="button" onClick={props.onRefresh}>
                {copy.refresh} ↺
              </button>
            ) : null}
          </div>
          <ConsoleBody copy={copy} lang={lang} view={view} counts={counts} {...props} />
          <div className="lab-footnote">{props.demo ? copy["box.footnote.demo"] : copy["box.footnote"]}</div>
        </div>
      </section>
    </>
  );
}

/**
 * The box itself: opens and closes, turns under a drag, and breathes while it
 * is on screen until the operator takes it over. Same timings as the site.
 */
function Stage({ copy, counts }: { copy: Copy; counts: ReturnType<typeof layerCounts> }) {
  const stage = useRef<HTMLDivElement>(null);
  const camera = useRef<HTMLDivElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [breathing, setBreathing] = useState(false);
  const [dragging, setDragging] = useState(false);
  const view = useRef({ pitch: 57, yaw: -33 });
  const drag = useRef<{ id: number; x: number; y: number; pitch: number; yaw: number } | null>(null);
  const takenOver = useRef(false);

  const setView = () => {
    camera.current?.style.setProperty("--pitch", `${view.current.pitch}deg`);
    camera.current?.style.setProperty("--yaw", `${view.current.yaw}deg`);
  };
  const takeOver = () => {
    takenOver.current = true;
    setBreathing(false);
  };

  // one breath: 3.2 s in (.breathing in codex.css), 1.2 s held, 3.2 s out, 1.2 s held
  useEffect(() => {
    const el = stage.current;
    if (!el) return;
    const lessMotion = typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (lessMotion) {
      setExpanded(true);
      return;
    }
    if (typeof IntersectionObserver === "undefined") return;
    const BREATH = { first: 800, open: 4400, closed: 4400 };
    let timer = 0;
    let onScreen = false;
    let open = false;
    let hovering = false;
    const stop = () => {
      clearTimeout(timer);
      timer = 0;
    };
    const schedule = (delay: number) => {
      stop();
      if (takenOver.current || !onScreen) return;
      timer = window.setTimeout(() => {
        if (takenOver.current) return;
        if (hovering) return schedule(600);
        open = !open;
        setExpanded(open);
        schedule(open ? BREATH.open : BREATH.closed);
      }, delay);
    };
    setBreathing(true);
    const enter = () => (hovering = true);
    const leave = () => (hovering = false);
    el.addEventListener("pointerenter", enter);
    el.addEventListener("pointerleave", leave);
    const io = new IntersectionObserver(
      ([entry]) => {
        onScreen = Boolean(entry?.isIntersecting);
        if (onScreen) schedule(timer ? BREATH.closed : BREATH.first);
        else stop();
      },
      { threshold: 0.35 },
    );
    io.observe(el);
    return () => {
      stop();
      io.disconnect();
      el.removeEventListener("pointerenter", enter);
      el.removeEventListener("pointerleave", leave);
    };
  }, []);

  const onDown = (event: PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    takeOver();
    drag.current = { id: event.pointerId, x: event.clientX, y: event.clientY, ...view.current };
    event.currentTarget.setPointerCapture?.(event.pointerId);
    setDragging(true);
  };
  const onMove = (event: PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d || d.id !== event.pointerId) return;
    view.current = {
      yaw: d.yaw + (event.clientX - d.x) * 0.35,
      pitch: Math.max(25, Math.min(78, d.pitch - (event.clientY - d.y) * 0.22)),
    };
    setView();
  };
  const stopDrag = () => {
    drag.current = null;
    setDragging(false);
  };

  const pad = String(counts.records).padStart(4, "0");
  return (
    <div
      ref={stage}
      className={`object-stage${expanded ? " exploded" : ""}${breathing ? " breathing" : ""}${dragging ? " dragging" : ""}`}
    >
      <div className="scene-haze"></div>
      <div className="orbit orbit-one"></div>
      <div className="orbit orbit-two"></div>
      <div className="scene-cross c1">+</div>
      <div className="scene-cross c2">+</div>
      <span className="scene-meta">
        {copy["box.meta"]}
        <br />
        <b>{copy["box.meta.view"]}</b>
      </span>
      <div className="floor-grid"></div>
      <div className="object-shadow"></div>
      <div
        ref={camera}
        className="object-camera"
        role="img"
        aria-label={copy["box.stageAria"]}
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={stopDrag}
        onPointerCancel={stopDrag}
        onLostPointerCapture={stopDrag}
      >
        <div className="assembly">
          <div className="solid base" style={{ "--level": 0, "--color": "#76a7ff" } as CSSProperties}>
            <div className="face top">
              <div className="circuit"></div>
              <span className="board-label" data-testid="box-record-count">
                {copy["box.layer.record"]} / {pad}
              </span>
            </div>
            <div className="face bottom"></div>
            <div className="face side front">
              <span className="leds">● ● ●</span>
              <span className="micro-label">{copy["box.layer.ledger"]}</span>
            </div>
            <div className="face side back"></div>
            <div className="face side left"></div>
            <div className="face side right">
              <span className="vents"></span>
            </div>
          </div>
          <div className="solid spend" style={{ "--level": 1, "--color": "#aac8ff" } as CSSProperties}>
            <div className="face top">
              <div className="circuit"></div>
              <div className="chip">
                <small>{copy["box.layer.spend"]}</small>
                <b>VERAX</b>
                <span>{fillCopy(copy["box.layer.spend.count"], { n: counts.spend, waiting: counts.waiting })}</span>
              </div>
              <span className="board-label">03 / {copy["box.layer.spend.board"]}</span>
            </div>
            <div className="face bottom"></div>
            <div className="face side front">
              <span className="micro-label">VERAX / {copy["box.layer.spend"]}</span>
            </div>
            <div className="face side back"></div>
            <div className="face side left"></div>
            <div className="face side right"></div>
          </div>
          <div className="solid memory" style={{ "--level": 2, "--color": "#5895ff" } as CSSProperties}>
            <div className="face top">
              <div className="circuit"></div>
              <div className="chip">
                <small>{copy["box.layer.memory"]}</small>
                <b>VERAX</b>
                <span>{fillCopy(copy["box.layer.memory.count"], { n: counts.memory })}</span>
              </div>
              <span className="board-label">02 / {copy["box.layer.memory.board"]}</span>
            </div>
            <div className="face bottom"></div>
            <div className="face side front">
              <span className="micro-label">VERAX / {copy["box.layer.memory"]}</span>
            </div>
            <div className="face side back"></div>
            <div className="face side left"></div>
            <div className="face side right"></div>
          </div>
          <div className="solid lid unbound" style={{ "--level": 3, "--color": "#367eff" } as CSSProperties}>
            <div className="face top">
              <div className="brushed"></div>
              <div className="lid-logo">
                <img src={MARK} alt="" width={240} height={163} decoding="async" />
                <span>VERAX</span>
              </div>
              <span className="lid-number">V / 001</span>
              <i className="screw s1"></i>
              <i className="screw s2"></i>
              <i className="screw s3"></i>
              <i className="screw s4"></i>
              <span className="board-label">{copy["box.layer.data.board"]}</span>
            </div>
            <div className="face bottom"></div>
            <div className="face side front">
              <span className="micro-label">
                {copy["box.layer.data"]} / {copy["box.layer.unbound"]}
              </span>
              <span className="leds">●</span>
            </div>
            <div className="face side back"></div>
            <div className="face side left"></div>
            <div className="face side right">
              <span className="vents"></span>
            </div>
          </div>
        </div>
      </div>
      <div className="scene-label label-top">
        <span>01</span>
        <div>
          {copy["box.layer.data"]}
          <small>{copy["box.label.top"]}</small>
        </div>
        <i></i>
      </div>
      <div className="scene-label label-bottom">
        <i></i>
        <span>03</span>
        <div>
          {copy["box.layer.spend"]}
          <small>{copy["box.label.bottom"]}</small>
        </div>
      </div>
      <div className="object-controls">
        <span className="drag-hint">{copy["box.drag"]}</span>
        <button
          type="button"
          aria-pressed={expanded}
          onClick={() => {
            takeOver();
            setExpanded((v) => !v);
          }}
        >
          {expanded ? copy["box.close"] : copy["box.open"]} <span>{expanded ? "−" : "+"}</span>
        </button>
        <button
          type="button"
          aria-label={copy["box.reset"]}
          onClick={() => {
            takeOver();
            view.current = { pitch: 57, yaw: -33 };
            setView();
            setExpanded(false);
          }}
        >
          ↺
        </button>
      </div>
    </div>
  );
}

function ConsoleBody({
  copy,
  lang,
  view,
  counts,
  canApprove,
  onApprove,
  onOpenRecord,
}: BlackBoxProps & { copy: Copy; lang: ReturnType<typeof readLang>; view: ConsoleView; counts: ReturnType<typeof layerCounts> }) {
  if (view.kind === "none") {
    return (
      <div className="lab-body">
        <div className="request">
          <h3>{copy["box.none"]}</h3>
        </div>
        <div className="ledger">
          <div className="ledger-heading">
            <span>{copy["box.ledger"]}</span>
            <span data-testid="box-badge">{copy["box.badge.none"]}</span>
          </div>
          <p className="console-empty">{copy["box.console.note.none"]}</p>
        </div>
      </div>
    );
  }

  const { row, defer, resolution } = view;
  const money = formatMinor(row.amount, row.currency, lang);
  const parts = splitMoney(row.amount, row.currency, lang);
  const payee = row.payee === undefined ? null : String(row.payee);
  const approver = resolution?.inputs?.approver;
  const waiting = view.kind === "waiting";

  return (
    <div className="lab-body">
      <div className="request">
        <div className="agent-avatar">
          {(row.brain[0] ?? "?").toUpperCase()}
          <span>{String(counts.waiting).padStart(2, "0")}</span>
        </div>
        <span className="eyebrow">{row.brain}</span>
        <h3>
          {waiting ? copy["box.request.waiting"] : copy["box.request.answered"]}
          <br />
          {row.subject}
          {payee === null ? "" : ` → ${payee}`}
        </h3>
        <div className="amount" data-testid="box-amount">
          {parts ? (
            <>
              {parts.whole}
              <span>{parts.fraction}</span>
            </>
          ) : (
            copy["spend.amount.unmeasured"]
          )}
        </div>
        {waiting ? <p>{fillCopy(copy["box.request.expires"], { when: formatStamp(row.expiresAtMs) })}</p> : <p></p>}
        <div className="policy-badge">
          <span>⌑</span> {fillCopy(copy["box.request.rule"], { rule: row.ruleText ?? copy["line.rule.none"] })}
        </div>
        {waiting ? (
          canApprove && onApprove ? (
            <ConsoleApprove copy={copy} row={row} money={money} payee={payee} onApprove={onApprove} />
          ) : (
            <p className="decision-scope" data-testid="box-no-scope">
              {copy["box.request.noScope"]}
            </p>
          )
        ) : null}
      </div>
      <div className="ledger">
        <div className="ledger-heading">
          <span>{copy["box.ledger"]}</span>
          <span data-testid="box-badge">{copy[`box.badge.${view.kind}`]}</span>
        </div>
        <ol className="timeline">
          <li className="done">
            <i></i>
            <div>
              <span>{copy["box.step.request"]}</span>
              <small>
                {row.subject} / {row.brain}
              </small>
            </div>
            <time>{clock(defer?.record.claims.timestampMs)}</time>
          </li>
          <li className="done">
            <i></i>
            <div>
              <span>{copy["box.step.rule"]}</span>
              <small>{defer?.record.claims.reasonCode ?? copy.unmeasured}</small>
            </div>
            <time>{clock(defer?.record.claims.timestampMs)}</time>
          </li>
          <li className={waiting ? "waiting" : "done"}>
            <i></i>
            <div>
              <span>
                {waiting
                  ? copy["box.step.wait"]
                  : view.kind === "approved"
                    ? copy["box.step.approved"]
                    : copy["box.step.expired"]}
              </span>
              <small>
                {waiting
                  ? copy["box.step.wait.detail"]
                  : approver
                    ? `${approver.id}${approver.via ? ` / ${approver.via}` : ""}`
                    : "—"}
              </small>
            </div>
            <time>{clock(resolution?.record.claims.timestampMs)}</time>
          </li>
          <li className={resolution ? "done" : ""}>
            <i></i>
            <div>
              <span>{resolution ? copy["box.step.record.done"] : copy["box.step.record.wait"]}</span>
              <small>{resolution?.record.claims.ref ?? "—"}</small>
            </div>
            <time>{clock(resolution?.record.claims.timestampMs)}</time>
          </li>
        </ol>
        <div className="record-preview">
          <div>
            <span>{copy["box.record.amount"]}</span>
            <strong data-testid="box-record-amount">{money ?? "—"}</strong>
          </div>
          <div className="digest">
            <span>{copy["box.record.hash"]}</span>
            <code>{row.requestHash}</code>
          </div>
          <div className="integrity-row">
            <span>{copy["box.record.signature"]}</span>
            <button type="button" onClick={() => onOpenRecord(resolution?.record.claims.ref ?? row.ref)}>
              {copy["box.record.open"]} ↗
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Asks first, sends the request the screen shows, and repeats the body's answer. */
function ConsoleApprove({
  copy,
  row,
  money,
  payee,
  onApprove,
}: {
  copy: Copy;
  row: PendingApproval;
  money: string | null;
  payee: string | null;
  onApprove: (ref: string, requestHash: string) => Promise<ApproveOutcome>;
}) {
  const [asking, setAsking] = useState(false);
  const [sending, setSending] = useState(false);
  const [said, setSaid] = useState<string | null>(null);

  if (said !== null) {
    return (
      <p className="decision-said" data-testid="box-approve-outcome">
        {said}
      </p>
    );
  }
  if (!asking) {
    return (
      <div className="decision-buttons">
        <button type="button" className="button blue" onClick={() => setAsking(true)}>
          {copy["approve.button"]} <span>✓</span>
        </button>
      </div>
    );
  }
  return (
    <div className="decision-buttons" data-testid="box-approve-confirm">
      <p className="decision-ask">
        {copy["approve.title"]}
        <small>
          {row.subject}
          {money !== null ? ` · ${money}` : ""}
          {payee === null ? "" : ` → ${payee}`} · {row.ruleText ?? copy["line.rule.none"]}
        </small>
      </p>
      <button
        type="button"
        className="button blue"
        disabled={sending}
        onClick={() => {
          setSending(true);
          void onApprove(row.ref, row.requestHash).then(
            (out) => setSaid(approveOutcomeText(copy, out)),
            (err: unknown) => setSaid(approveFailureText(copy, err)),
          );
        }}
      >
        {sending ? copy["approve.sending"] : copy["approve.yes"]} <span>✓</span>
      </button>
      <button type="button" className="button outline" onClick={() => setAsking(false)}>
        {copy["approve.no"]} <span>×</span>
      </button>
    </div>
  );
}
