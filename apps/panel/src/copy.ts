import { readLang, type Lang } from "./lang.ts";
import en from "./copy/en.json";
import tr from "./copy/tr.json";

export type Copy = Record<string, string>;
export { readLang, type Lang } from "./lang.ts";

const TABLES: Record<Lang, Copy> = { en, tr };

export function panelCopy(lang: Lang = readLang()): Copy {
  return TABLES[lang];
}
