/** Codes the brain is told, when that string is not the recorded reason.
 *  The ledger row always keeps the recorded code. An unmapped code is
 *  spoken as itself. */
const SPOKEN_REASON: Readonly<Record<string, string>> = {
  "tenant-mismatch": "not-found",
};

export function spokenReason(reasonCode: string): string {
  return SPOKEN_REASON[reasonCode] ?? reasonCode;
}
