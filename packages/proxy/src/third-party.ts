import { createPublicKey } from "node:crypto";
import { canonical } from "@cedulon/core";
import { verifyEffectExtract, type EffectRow, type SignedEffectExtract } from "@cedulon/effect-extract";

/** Compare key material, not PEM whitespace or line endings. */
export function samePublicKey(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  try {
    return createPublicKey(a).export({ type: "spki", format: "der" })
      .equals(createPublicKey(b).export({ type: "spki", format: "der" }));
  } catch { return false; }
}

/** External receipts are meaningful only under a reader-supplied pin. */
export function thirdPartyReceiptCoversRow(receipt: SignedEffectExtract | undefined, row: unknown, key: string): boolean {
  try {
    return !!receipt && createPublicKey(key).asymmetricKeyType === "ed25519" &&
      verifyEffectExtract(receipt, key) && receipt.body.effects.length === 1 &&
      canonical(receipt.body.effects[0]) === canonical(row);
  } catch { return false; }
}

/** A valid signature must also describe this dispatch, not another call. */
export function thirdPartyReceiptRejection(
  value: unknown, key: string, ref: string | undefined, effectClass: string, effectHash: string,
): string | null {
  const receipt = value as SignedEffectExtract | undefined;
  try {
    if (!receipt || !verifyEffectExtract(receipt, key)) return "signature";
    if (receipt.body.effects.length !== 1) return "effect-count";
    const row: EffectRow = receipt.body.effects[0]!;
    if (!ref || row.ref !== ref) return "ref";
    if (row.effectClass !== effectClass) return "effect-class";
    if (row.effectHash !== effectHash) return "effect-hash";
    if (receipt.body.deciderId !== "verax-proxy") return "decider";
    if (receipt.body.windowStartMs !== row.timestampMs) return "window-start";
    if (receipt.body.windowEndMs !== row.timestampMs + 1) return "window-end";
    return null;
  } catch { return "malformed-receipt"; }
}
