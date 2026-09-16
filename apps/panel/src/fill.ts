/**
 * Puts values into a copy line's `{name}` slots. It lives on its own so the
 * modules that only need it never pull in the copy tables, which are JSON
 * and load under Vite but not under node's test runner.
 */
export function fillCopy(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{([a-zA-Z]+)\}/g, (_, key: string) => String(vars[key] ?? ""));
}
