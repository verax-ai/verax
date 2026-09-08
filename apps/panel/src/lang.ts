/**
 * The language lives apart from the copy tables. `copy.ts` imports JSON, and a
 * JSON import needs an import attribute the node test runner will not supply,
 * so a pure module that only needs the language must not reach through it.
 */
export type Lang = "en" | "tr";

export function readLang(): Lang {
  if (typeof window === "undefined") return "tr";
  try {
    const q = new URLSearchParams(window.location.search).get("lang");
    if (q === "en" || q === "tr") return q;
  } catch {
    return "tr";
  }
  return "tr";
}
