import type { Lang } from "../src/lang.ts";

/**
 * Ask for a language explicitly, without disturbing the rest of the address.
 *
 * The panel opens in English. A test that asserts Turkish copy is testing the
 * Turkish table, not the default, and has to say so; one that asserts English
 * is testing what the product ships and says that too. Before this existed the
 * default was Turkish and every such test read as though it had no opinion.
 *
 * The first version replaced the whole query string and quietly dropped the
 * `demo=1` a test had just set, which is why it sets a single parameter.
 */
export function setLang(lang: Lang): void {
  const url = new URL(window.location.href);
  url.searchParams.set("lang", lang);
  window.history.replaceState({}, "", url);
}
