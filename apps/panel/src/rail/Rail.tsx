import { useState } from "react";
import type { RailAction, RailFinding } from "./types.ts";

export type RailProps = {
  actions: RailAction[];
  onContest?: (ref: string) => Promise<{ reAuditedAt?: number; finding?: RailFinding } | void>;
};

function kindOf(action: RailAction): "allow" | "deny" | "threw" {
  if (action.effect?.row.effectClass.endsWith(":threw")) return "threw";
  return action.record.claims.decision === "deny" ? "deny" : "allow";
}

function iconOf(kind: "allow" | "deny" | "threw"): string {
  if (kind === "allow") return "+";
  if (kind === "deny") return "x";
  return "!";
}

export function Rail({ actions, onContest }: RailProps) {
  const [open, setOpen] = useState<string | null>(actions[0]?.record.claims.ref ?? null);
  const [stamp, setStamp] = useState<Record<string, string>>({});
  const [findings, setFindings] = useState<Record<string, RailFinding>>({});

  return (
    <nav className="rail" aria-label="Account-for rail">
      <ol>
        {actions.map((action) => {
          const ref = action.record.claims.ref ?? "unknown";
          const kind = kindOf(action);
          const expanded = open === ref;
          const finding = findings[ref] ?? action.finding;
          const brain = action.effect?.row.actor ?? "not on the decision record";
          const ruleLine = action.rule ? JSON.stringify(action.rule) : "no matching rule";
          return (
            <li key={ref}>
              <button
                type="button"
                className={`row focusable ${kind}`}
                aria-expanded={expanded}
                onClick={() => setOpen(expanded ? null : ref)}
              >
                <span className="icon" aria-hidden="true">
                  {iconOf(kind)}
                </span>
                <span>
                  {action.record.claims.subject} {kind}
                </span>
              </button>
              {expanded ? (
                <section className="questions">
                  <h2>What did you do</h2>
                  <p>
                    {action.record.claims.subject} {action.record.claims.decision}{" "}
                    {action.record.claims.reasonCode} at {action.record.claims.timestampMs} by{" "}
                    {action.record.claims.decider} for brain {brain}
                  </p>
                  {action.effect ? (
                    <p>
                      {action.effect.row.effectClass} {action.effect.row.effectHash} at{" "}
                      {action.effect.row.timestampMs}
                    </p>
                  ) : (
                    <p>no effect row</p>
                  )}
                  <h2>Is there a counterpart</h2>
                  <p>
                    {finding?.code ?? "not requested"} {finding?.label ?? ""} hashes{" "}
                    {action.record.claims.effectHash ?? "none"} /{" "}
                    {action.effect?.row.effectHash ?? "none"}
                  </p>
                  <h2>Was the information current</h2>
                  <p>not tracked yet</p>
                  <h2>What did it do to the company</h2>
                  <p>not connected</p>
                  <h2>Was it within the rules</h2>
                  <p>
                    policy {action.record.claims.policyHash} rule {action.rule?.id ?? "none"} {ruleLine}{" "}
                    {action.rule?.text ?? ""}
                  </p>
                  <button
                    type="button"
                    className="contest focusable"
                    onClick={async () => {
                      if (!action.record.claims.ref || !onContest) return;
                      const out = await onContest(action.record.claims.ref);
                      const at =
                        out && "reAuditedAt" in out && out.reAuditedAt ? out.reAuditedAt : Date.now();
                      setStamp((s) => ({ ...s, [ref]: `re-audited at ${at}` }));
                      if (out && "finding" in out && out.finding) {
                        setFindings((s) => ({ ...s, [ref]: out.finding as RailFinding }));
                      }
                    }}
                  >
                    Contest
                  </button>
                  {stamp[ref] ? <p>{stamp[ref]}</p> : null}
                </section>
              ) : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
