/**
 * The language lives apart from the copy tables. `copy.ts` imports JSON, and a
 * JSON import needs an import attribute the node test runner will not supply,
 * so a pure module that only needs the language must not reach through it.
 *
 * English is the default. The ledger writes its own words in English --
 * `spend`, `approval-required`, `approved-by-operator` -- and the screen quotes
 * them; a Turkish frame around English machine text reads as two languages in
 * one sentence. It is also the language the operators who are not in this room
 * will arrive in. A reader who wants another one says so, and the screen
 * remembers.
 */
export type Lang = "en" | "tr";

export const LANGS: readonly Lang[] = ["en", "tr"];

const STORAGE_KEY = "verax.lang";

function asLang(value: string | null): Lang | null {
  return value === "en" || value === "tr" ? value : null;
}

function fromQuery(): Lang | null {
  try {
    return asLang(new URLSearchParams(window.location.search).get("lang"));
  } catch {
    return null;
  }
}

function fromStorage(): Lang | null {
  try {
    return asLang(window.localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

export function readLang(): Lang {
  if (typeof window === "undefined") return "en";
  return fromQuery() ?? fromStorage() ?? "en";
}

/**
 * Remember the reader's choice and put it in the address, so a screen that was
 * asked for in one language can be handed to someone else in that language.
 * Either half may be refused by the browser; neither is required for the
 * choice to take effect on this render.
 */
export function writeLang(lang: Lang): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // A browser that refuses storage still gets the language from the address.
  }
  try {
    const url = new URL(window.location.href);
    url.searchParams.set("lang", lang);
    window.history.replaceState({}, "", url);
  } catch {
    // Leaving the address alone is not a reason to drop the choice.
  }
}
