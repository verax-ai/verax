import { useState } from "react";
import { panelCopy, readLang } from "./copy.ts";
import { fillCopy } from "./fill.ts";

/** What GET /api/halt answers. `since` is absent when the switch predates the history file. */
export type HaltState = { halted: boolean; since?: { atMs: number; by: string; via: "cli" | "http" } };

export type SwitchOutcome = { ok: true; state: HaltState } | { ok: false; error: string };

function when(atMs: number): string {
  const lang = readLang();
  return new Date(atMs).toLocaleString(lang === "tr" ? "tr-TR" : "en-GB", {
    dateStyle: "short",
    timeStyle: "short",
  });
}

/**
 * The panel's `verax halt`. Stopping asks once and then refuses everything
 * the agent sends through the body; resuming asks once and needs the approve
 * scope, which the body checks again. Nothing here decides: every press is
 * sent and the screen draws what the body answered.
 *
 * `state` is null until the body has answered. An unknown switch draws no
 * button: a stop that might already be on must not read as "running".
 *
 * It sits at the end of the panel's top bar and takes no row of its own: the
 * panel fills the window, and a bar above it pushed the timeline off screen.
 */
export function StopSwitch({
  state,
  canResume,
  onHalt,
  onResume,
}: {
  state: HaltState | null;
  canResume: boolean;
  onHalt: () => Promise<SwitchOutcome>;
  onResume: () => Promise<SwitchOutcome>;
}) {
  const copy = panelCopy();
  const [asking, setAsking] = useState(false);
  const [sending, setSending] = useState(false);
  const [said, setSaid] = useState<string | null>(null);

  if (state === null) return null;

  const press = (action: () => Promise<SwitchOutcome>) => {
    setSending(true);
    setSaid(null);
    void action().then(
      (out) => {
        setSending(false);
        setAsking(false);
        if (!out.ok) setSaid(fillCopy(copy["stop.failed"], { reason: out.error }));
      },
      (err: unknown) => {
        setSending(false);
        setAsking(false);
        setSaid(fillCopy(copy["stop.failed"], { reason: err instanceof Error ? err.message : String(err) }));
      },
    );
  };

  if (!state.halted) {
    return (
      <div className="stop-switch" data-testid="stop-bar">
        {said !== null && <p className="stop-said">{said}</p>}
        {asking ? (
          <div className="stop-confirm" data-testid="stop-confirm">
            <p className="stop-title">{copy["stop.title"]}</p>
            <p className="muted">{copy["stop.explain"]}</p>
            <button type="button" className="stop focusable" disabled={sending} onClick={() => press(onHalt)}>
              {sending ? copy["stop.sending"] : copy["stop.yes"]}
            </button>
            <button type="button" className="focusable" disabled={sending} onClick={() => setAsking(false)}>
              {copy["stop.no"]}
            </button>
          </div>
        ) : (
          <button type="button" className="stop focusable" onClick={() => setAsking(true)}>
            {copy["stop.button"]}
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="stop-switch halted" role="alert" data-testid="stop-halted" title={copy["stop.halted.explain"]}>
      <p className="stop-title">{copy["stop.halted"]}</p>
      {state.since && <p>{fillCopy(copy["stop.halted.by"], { who: state.since.by, when: when(state.since.atMs) })}</p>}
      {said !== null && <p className="stop-said">{said}</p>}
      {!canResume ? (
        <p className="muted">{copy["stop.resume.needApprove"]}</p>
      ) : asking ? (
        <div className="stop-confirm" data-testid="resume-confirm">
          <p>{copy["stop.resume.title"]}</p>
          <button type="button" className="resume focusable" disabled={sending} onClick={() => press(onResume)}>
            {sending ? copy["stop.sending"] : copy["stop.resume.yes"]}
          </button>
          <button type="button" className="focusable" disabled={sending} onClick={() => setAsking(false)}>
            {copy["stop.no"]}
          </button>
        </div>
      ) : (
        <button type="button" className="resume focusable" onClick={() => setAsking(true)}>
          {copy["stop.resume"]}
        </button>
      )}
    </div>
  );
}
