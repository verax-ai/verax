import en from "./copy/en.json";
import tr from "./copy/tr.json";

export type Copy = Record<string, string>;
export type Lang = "en" | "tr";

const TABLES: Record<Lang, Copy> = { en, tr };

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

export function panelCopy(lang: Lang = readLang()): Copy {
  return TABLES[lang];
}
