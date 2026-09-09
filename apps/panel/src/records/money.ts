import type { Lang } from "../lang.ts";

/**
 * The ledger stores money in minor units: a 10.00 TRY payment is 1000.
 * Printing that number next to its currency states an amount a hundred
 * times too large, on the one screen whose whole claim is that the record
 * can be trusted. The exponent is not assumed to be two — it comes from
 * the currency itself, so a zero-decimal currency is not shifted.
 *
 * Returns null when the amount or the currency cannot be read. A caller
 * that gets null says the amount was not measured; it never falls back to
 * printing the raw minor number.
 */
export function formatMinor(amountMinor: unknown, currency: unknown, lang: Lang): string | null {
  if (typeof amountMinor !== "number" || !Number.isFinite(amountMinor)) return null;
  if (typeof currency !== "string" || currency.trim() === "") return null;
  const code = currency.trim().toUpperCase();
  try {
    const format = new Intl.NumberFormat(lang, { style: "currency", currency: code });
    const digits = format.resolvedOptions().maximumFractionDigits ?? 2;
    return format.format(amountMinor / 10 ** digits);
  } catch {
    return null;
  }
}
