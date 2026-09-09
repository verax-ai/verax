import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { panelCopy } from "../copy.ts";
import type { RailAction } from "../rail/types.ts";
import { formatStamp, sameUtcDay, timelineGroups, timelineMarks } from "./timeline.ts";

/** Wide enough for a time of day plus the mark's own padding and border. */
const MARK_WIDTH_PX = 88;

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
  const trackRef = useRef<HTMLDivElement | null>(null);
  const [trackWidth, setTrackWidth] = useState(0);

  const measure = useCallback(() => {
    const el = trackRef.current;
    setTrackWidth(el ? el.getBoundingClientRect().width : 0);
  }, []);

  useLayoutEffect(measure, [measure, marks.length]);
  useEffect(() => {
    if (typeof window === "undefined") return;
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [measure]);

  const short = sameUtcDay(marks);
  const groups = timelineGroups(marks, trackWidth, MARK_WIDTH_PX, short);
  const times = marks.map((m) => m.timestampMs);
  const span =
    marks.length === 0
      ? ""
      : copy["timeline.span"]
          .replace("{from}", formatStamp(Math.min(...times)))
          .replace("{to}", formatStamp(Math.max(...times)));

  return (
    <footer className={`obs-timeline${quiet ? " is-static" : ""}`} aria-label={copy["timeline.label"]}>
      {marks.length === 0 ? (
        <p className="muted timeline-empty">{copy["timeline.empty"]}</p>
      ) : (
        <>
          <p className="timeline-span" data-testid="timeline-span">
            {span}
          </p>
          <div className="timeline-track" data-testid="timeline-track" ref={trackRef}>
            {groups.map((group) => {
              const on = selected !== null && group.refs.includes(selected);
              // An unmeasured track places by percentage, the way it always
              // has; a measured one places in pixels so nothing hangs off
              // either end.
              const style =
                group.leftPx < 0
                  ? { left: `${marks.find((m) => m.ref === group.key)?.leftPct ?? 0}%` }
                  : { left: `${group.leftPx}px`, transform: "none" };
              return (
                <button
                  key={group.key}
                  type="button"
                  className={`timeline-mark focusable${on ? " is-selected" : ""}${group.count > 1 ? " is-fold" : ""}`}
                  style={style}
                  title={group.title}
                  aria-pressed={on}
                  aria-current={on ? "true" : undefined}
                  aria-label={
                    group.count > 1 ? copy["timeline.group"].replace("{n}", String(group.count)) : group.title
                  }
                  onClick={() => onSelect(group.refs[0] as string)}
                >
                  <span className="timeline-stamp">
                    {group.count > 1
                      ? copy["timeline.group"].replace("{n}", String(group.count))
                      : group.label}
                  </span>
                </button>
              );
            })}
          </div>
        </>
      )}
    </footer>
  );
}
