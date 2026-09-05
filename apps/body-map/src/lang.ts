import en from "./copy/en.json";
import tr from "./copy/tr.json";

export type Copy = Record<string, string>;
export type Lang = "en" | "tr";

const TABLES: Record<Lang, Copy> = { en, tr };

export function readLang(): Lang {
  if (typeof window === "undefined") return "en";
  try {
    const q = new URLSearchParams(window.location.search).get("lang");
    if (q === "tr" || q === "en") {
      window.localStorage.setItem("verax-lang", q);
      return q;
    }
    const stored = window.localStorage.getItem("verax-lang");
    return stored === "tr" ? "tr" : "en";
  } catch {
    return "en";
  }
}

export function copyFor(lang: Lang): Copy {
  return TABLES[lang];
}

export function keysOf(copy: Copy): string[] {
  return Object.keys(copy).sort();
}
