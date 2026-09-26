import { useEffect, useRef, useState } from "react";

import { pinnedApproveTarget, type PinnedApproval } from "./approve-target.ts";

export type { PinnedApproval } from "./approve-target.ts";
export { pinnedApproveTarget } from "./approve-target.ts";

/**
 * Confirmation state belongs to the row the operator pressed Approve on.
 * If that row leaves the screen, the confirmation closes and a later Yes
 * sends nothing for the row that replaced it.
 */
export function usePinnedApproval(row: PinnedApproval) {
  const [asking, setAsking] = useState(false);
  const [sending, setSending] = useState(false);
  const [said, setSaid] = useState<string | null>(null);
  const captured = useRef<PinnedApproval | null>(null);
  const epoch = useRef(0);
  const ref = row.ref;
  const requestHash = row.requestHash;

  useEffect(() => {
    const held = captured.current;
    if (!held) return;
    if (pinnedApproveTarget(held, { ref, requestHash })) return;
    epoch.current += 1;
    captured.current = null;
    setAsking(false);
    setSending(false);
    setSaid(null);
  }, [ref, requestHash]);

  function ask(): void {
    captured.current = { ref: row.ref, requestHash: row.requestHash };
    setSaid(null);
    setAsking(true);
  }

  function dismiss(): void {
    epoch.current += 1;
    captured.current = null;
    setAsking(false);
    setSending(false);
  }

  function beginSend(): { row: PinnedApproval; epoch: number } | null {
    const held = pinnedApproveTarget(captured.current, row);
    if (!held) {
      dismiss();
      return null;
    }
    const token = epoch.current;
    setSending(true);
    return { row: held, epoch: token };
  }

  function acceptResult(token: number): boolean {
    return epoch.current === token;
  }

  return { asking, sending, said, setSaid, ask, dismiss, beginSend, acceptResult };
}
