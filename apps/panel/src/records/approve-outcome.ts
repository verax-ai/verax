import type { Copy } from "../copy.ts";
import { fillCopy } from "../fill.ts";
import type { ApproveOutcome } from "../observatory/Observatory.tsx";

/**
 * The sentence an approve control prints once the body has answered. Two
 * screens approve - the pending list and the black box console - and both say
 * exactly this, so the words for "stale" or "refused" cannot drift apart.
 */
export function approveOutcomeText(copy: Copy, out: ApproveOutcome): string {
  if (out.ok) return fillCopy(copy["approve.done"], { ref: out.allowRef });
  if (out.error === "stale") return copy["approve.stale"];
  if (out.error === "sample-not-sent") return copy["approve.sample"];
  return fillCopy(copy["approve.refused"], { reason: out.error });
}

export function approveFailureText(copy: Copy, err: unknown): string {
  return fillCopy(copy["approve.refused"], { reason: err instanceof Error ? err.message : "unknown" });
}
