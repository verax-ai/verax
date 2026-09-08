import { panelCopy } from "../copy.ts";
import type { RailAction } from "../rail/types.ts";
import { timelineMarks } from "./timeline.ts";

function reducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function Timeline({
  actions,
  selected,
  onSelect,
}: {
  actions: RailAction[];
  selected: string | null;
  onSelect: (ref: string) => void;
}) {
  const copy = panelCopy();
  const marks = timelineMarks(actions);
  const quiet = reducedMotion();
  return (
    <footer className={`obs-timeline${quiet ? " is-static" : ""}`} aria-label={copy["timeline.label"]}>
      {marks.length === 0 ? (
        <p className="muted timeline-empty">{copy["timeline.empty"]}</p>
      ) : (
        <div className="timeline-track" data-testid="timeline-track">
          {marks.map((mark) => (
            <button
              key={mark.ref}
              type="button"
              className={`timeline-mark focusable${selected === mark.ref ? " is-selected" : ""}`}
              style={{ left: `${mark.leftPct}%` }}
              aria-pressed={selected === mark.ref}
              aria-current={selected === mark.ref ? "true" : undefined}
              onClick={() => onSelect(mark.ref)}
            >
              <span className="timeline-stamp">{mark.stamp}</span>
            </button>
          ))}
        </div>
      )}
    </footer>
  );
}
