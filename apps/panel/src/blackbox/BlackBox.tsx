import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { createPortal } from "react-dom";
import recorderCss from "./recorder.css?raw";
import "./fonts.css";
import { panelCopy, readLang, type Copy } from "../copy.ts";
import { fillCopy } from "../fill.ts";
import type { ApproveOutcome } from "../observatory/Observatory.tsx";
import type { PendingApproval, RailAction } from "../rail/types.ts";
import { approveFailureText, approveOutcomeText } from "../records/approve-outcome.ts";
import { usePinnedApproval } from "../records/approve-pin.ts";
import { formatMinor } from "../records/money.ts";
import { formatStamp } from "../records/timeline.ts";
import { consoleView, splitMoney, type ConsoleView } from "./console.ts";
import { chainFor, gapWords, layTape, recordHealth, type ChainLink, type Tape, type TapeMark } from "./recorder.ts";

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

/**
 * The black box, read like a flight recorder: every decision on one tape, the
 * chain of the one picked, what is waiting for the operator, and what the
 * record can vouch for. It draws inside a shadow root so its stylesheet stays
 * its own.
 */
export function BlackBox(props: BlackBoxProps) {
  const host = useRef<HTMLElement>(null);
  const [mount, setMount] = useState<HTMLElement | null>(null);

  useLayoutEffect(() => {
    const el = host.current;
    if (!el) return;
    const shadow = el.shadowRoot ?? el.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = recorderCss;
    const cx = document.createElement("div");
    cx.className = "cx";
    shadow.replaceChildren(style, cx);
    setMount(cx);
  }, []);

  return (
    <section ref={host} className="black-box" data-testid="black-box">
      {mount ? createPortal(<Recorder {...props} />, mount) : null}
    </section>
  );
}

function clock(ms: number | undefined | null): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "—";
  return formatStamp(ms).slice(11, 19);
}

function Recorder(props: BlackBoxProps) {
  const copy = panelCopy();
  const lang = readLang();
  const view = consoleView(props.actions, props.pending);
  const tape = useMemo(() => layTape(props.actions), [props.actions]);
  const health = recordHealth(props.actions, props.pending, props.decisions);

  const opening = view.kind === "none" ? null : view.defer;
  const newest = tape.marks[tape.marks.length - 1]?.action ?? null;
  const [picked, setPicked] = useState<RailAction | null>(null);
  const selected = (picked && props.actions.includes(picked) ? picked : null) ?? opening ?? newest;

  return (
    <div className="rec">
      <header className="rec-head">
        <p className="rec-summary">
          {fillCopy(copy["rec.summary"], {
            n: health.decisions,
            agents: health.agents,
            denied: health.denied,
            waiting: health.waiting,
          })}
        </p>
        <div className="rec-source">
          <span className={props.demo ? "src sample" : "src live"}>
            {props.demo ? copy["box.console.sample"] : copy["box.console.live"]}
          </span>
        </div>
      </header>

      <TapeView copy={copy} lang={lang} tape={tape} selected={selected} onPick={setPicked} />

      <div className="rec-grid">
        <ChainView
          copy={copy}
          action={selected}
          actions={props.actions}
          pending={props.pending}
          onOpenRecord={props.onOpenRecord}
        />
        <aside className="queue" aria-labelledby="rec-waiting-title">
          <h3 id="rec-waiting-title">{copy["rec.waiting.title"]}</h3>
          <WaitingBody copy={copy} lang={lang} view={view} {...props} />
          <p className="footnote">{props.demo ? copy["box.footnote.demo"] : copy["box.footnote"]}</p>
        </aside>
      </div>

      <HealthView copy={copy} health={health} />
    </div>
  );
}

const DECISION_WORD: Record<TapeMark["decision"], string> = {
  allow: "rec.legend.allow",
  deny: "rec.legend.deny",
  defer: "rec.legend.defer",
};

function TapeView({
  copy,
  lang,
  tape,
  selected,
  onPick,
}: {
  copy: Copy;
  lang: "tr" | "en";
  tape: Tape;
  selected: RailAction | null;
  onPick: (a: RailAction) => void;
}) {
  if (tape.marks.length === 0) {
    return (
      <section className="tape empty" aria-label={copy["rec.tape.aria"]}>
        <h2>{copy["rec.tape.title"]}</h2>
        <p>{copy["rec.tape.empty"]}</p>
      </section>
    );
  }
  const pickedMark = tape.marks.find((m) => m.action === selected);
  return (
    <section className="tape" aria-label={copy["rec.tape.aria"]}>
      <div className="tape-top">
        <h2>{copy["rec.tape.title"]}</h2>
        <ul className="legend">
          <li className="allow">{copy["rec.legend.allow"]}</li>
          <li className="deny">{copy["rec.legend.deny"]}</li>
          <li className="defer">{copy["rec.legend.defer"]}</li>
          <li className="effect">{copy["rec.legend.effect"]}</li>
        </ul>
      </div>
      <div className="reel">
        {pickedMark ? <i className="cursor" style={{ "--x": pickedMark.x } as CSSProperties} /> : null}
        {tape.breaks.map((b) => (
          <span key={b.x} className="break" style={{ "--x": b.x } as CSSProperties}>
            <span>{fillCopy(copy["rec.tape.break"], { gap: gapWords(b.ms, lang) })}</span>
          </span>
        ))}
        {tape.lanes.map((lane, i) => (
          <div className="lane" key={lane}>
            <span className="lane-name">{lane}</span>
            <div className="track">
              {tape.marks
                .filter((m) => m.lane === i)
                .map((m) => (
                  <button
                    type="button"
                    key={m.key}
                    className={`mark ${m.decision}${m.hasEffect ? " fx" : ""}${m.action === selected ? " on" : ""}`}
                    style={{ left: `${m.x}%` } as CSSProperties}
                    aria-pressed={m.action === selected}
                    aria-label={fillCopy(copy["rec.mark"], {
                      time: formatStamp(m.timestampMs),
                      subject: m.subject,
                      decision: copy[DECISION_WORD[m.decision]] ?? m.decision,
                    })}
                    title={`${formatStamp(m.timestampMs)}  ${m.subject}`}
                    onClick={() => onPick(m.action)}
                  >
                    <i />
                  </button>
                ))}
            </div>
          </div>
        ))}
      </div>
      <div className="axis">
        <time>{tape.firstMs === null ? "—" : formatStamp(tape.firstMs)}</time>
        <time>{tape.lastMs === null ? "—" : formatStamp(tape.lastMs)}</time>
      </div>
      <p className="tape-note">{copy["rec.tape.note"]}</p>
    </section>
  );
}

function ChainView({
  copy,
  action,
  actions,
  pending,
  onOpenRecord,
}: {
  copy: Copy;
  action: RailAction | null;
  actions: RailAction[];
  pending: PendingApproval[];
  onOpenRecord: (ref: string) => void;
}) {
  if (!action) {
    return (
      <section className="chain" aria-labelledby="rec-chain-title">
        <h3 id="rec-chain-title">{copy["rec.chain.title"]}</h3>
        <p className="quiet">{copy["rec.chain.pick"]}</p>
      </section>
    );
  }
  const c = action.record.claims;
  const links = chainFor(action, actions, pending);
  return (
    <section className="chain" aria-labelledby="rec-chain-title">
      <div className="chain-head">
        <h3 id="rec-chain-title">{copy["rec.chain.title"]}</h3>
        <span className="when">
          <time>{formatStamp(c.timestampMs)}</time>
          {c.ref ? <code>{c.ref}</code> : null}
        </span>
      </div>
      <ol className="links" data-testid="box-chain">
        {links.map((l) => (
          <LinkRow key={l.id} copy={copy} link={l} />
        ))}
      </ol>
      {c.ref ? (
        <button type="button" className="ghost open" onClick={() => onOpenRecord(c.ref!)}>
          {copy["box.record.open"]}
        </button>
      ) : null}
    </section>
  );
}

function LinkRow({ copy, link }: { copy: Copy; link: ChainLink }) {
  return (
    <li className={`link ${link.state}`} data-link={link.id}>
      <i aria-hidden="true" />
      <div>
        <b>{copy[`rec.step.${link.id}`]}</b>
        <span className="state">{copy[`rec.state.${link.state}`]}</span>
        <p>{copy[`rec.say.${link.say}`]}</p>
        {link.detail ? <small>{link.detail}</small> : null}
        {link.code ? <code>{link.code}</code> : null}
      </div>
    </li>
  );
}

function HealthView({ copy, health }: { copy: Copy; health: ReturnType<typeof recordHealth> }) {
  const witness = Object.entries(health.witness);
  return (
    <section className="health" aria-labelledby="rec-health-title">
      <h3 id="rec-health-title">{copy["rec.health.title"]}</h3>
      <dl>
        <div>
          <dt>{copy["rec.health.witness"]}</dt>
          <dd>
            {witness.length === 0 ? copy["rec.health.witness.none"] : witness.map(([k, n]) => `${k} ${n}`).join(", ")}
            <small>{copy["rec.health.witness.note"]}</small>
          </dd>
        </div>
        <div>
          <dt>{copy["rec.health.inputs"]}</dt>
          <dd>{fillCopy(copy["rec.health.inputs.value"], { n: health.inputsBound, total: health.decisions })}</dd>
        </div>
        <div>
          <dt>{copy["rec.health.trust"]}</dt>
          <dd className={health.trustPinned === true ? "ok" : "warn"}>
            {health.trustPinned === null
              ? copy["rec.health.trust.unread"]
              : health.trustPinned
                ? copy["rec.health.trust.pinned"]
                : copy["rec.health.trust.open"]}
          </dd>
        </div>
        <div>
          <dt>{copy["rec.health.verify"]}</dt>
          <dd className="warn">{copy["rec.health.verify.value"]}</dd>
        </div>
      </dl>
    </section>
  );
}

function WaitingBody({
  copy,
  lang,
  view,
  canApprove,
  onApprove,
}: BlackBoxProps & { copy: Copy; lang: ReturnType<typeof readLang>; view: ConsoleView }) {
  if (view.kind === "none") {
    return (
      <div className="request">
        <span className="badge none" data-testid="box-badge">
          {copy["box.badge.none"]}
        </span>
        <p className="quiet">{copy["box.none"]}</p>
      </div>
    );
  }
  const { row, resolution } = view;
  const money = formatMinor(row.amount, row.currency, lang);
  const parts = splitMoney(row.amount, row.currency, lang);
  const payee = row.payee === undefined ? null : String(row.payee);
  const approver = resolution?.inputs?.approver;
  const waiting = view.kind === "waiting";
  return (
    <div className="request">
      <span className={`badge ${view.kind}`} data-testid="box-badge">
        {copy[`box.badge.${view.kind}`]}
      </span>
      <p className="who">
        {row.brain}
        <span>
          {row.subject}
          {payee === null ? "" : ` → ${payee}`}
        </span>
      </p>
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
      <p className="rule">{fillCopy(copy["box.request.rule"], { rule: row.ruleText ?? copy["line.rule.none"] })}</p>
      {waiting ? <p className="quiet">{fillCopy(copy["box.request.expires"], { when: formatStamp(row.expiresAtMs) })}</p> : null}
      {!waiting && approver ? <p className="quiet">{`${approver.id}${approver.via ? ` / ${approver.via}` : ""}`}</p> : null}
      {waiting ? (
        canApprove && onApprove ? (
          <ConsoleApprove
            key={`${row.ref}:${row.requestHash}`}
            copy={copy}
            row={row}
            money={money}
            payee={payee}
            onApprove={onApprove}
          />
        ) : (
          <p className="decision-scope" data-testid="box-no-scope">
            {copy["box.request.noScope"]}
          </p>
        )
      ) : null}
      <dl className="facts">
        <div>
          <dt>{copy["box.record.amount"]}</dt>
          <dd data-testid="box-record-amount">{money ?? "—"}</dd>
        </div>
        <div>
          <dt>{copy["box.record.hash"]}</dt>
          <dd>
            <code>{row.requestHash}</code>
          </dd>
        </div>
      </dl>
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
  const pin = usePinnedApproval(row);

  if (pin.said !== null) {
    return (
      <p className="decision-said" data-testid="box-approve-outcome">
        {pin.said}
      </p>
    );
  }
  if (!pin.asking) {
    return (
      <div className="decision-buttons">
        <button type="button" className="primary" onClick={() => pin.ask()}>
          {copy["approve.button"]}
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
        className="primary"
        disabled={pin.sending}
        onClick={() => {
          const started = pin.beginSend();
          if (!started) return;
          void onApprove(started.row.ref, started.row.requestHash).then(
            (out) => {
              if (!pin.acceptResult(started.epoch)) return;
              pin.setSaid(approveOutcomeText(copy, out));
            },
            (err: unknown) => {
              if (!pin.acceptResult(started.epoch)) return;
              pin.setSaid(approveFailureText(copy, err));
            },
          );
        }}
      >
        {pin.sending ? copy["approve.sending"] : copy["approve.yes"]}
      </button>
      <button type="button" className="ghost" onClick={() => pin.dismiss()}>
        {copy["approve.no"]}
      </button>
    </div>
  );
}
