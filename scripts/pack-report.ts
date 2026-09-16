/**
 * Reads the file list out of `npm pack --dry-run --json`.
 *
 * The shape of that output differs by npm version: an array of reports on
 * npm 10, an object keyed by package name on npm 12. A reader that knows only
 * one of them reports "no files" on the other, and a check that asks "does the
 * tarball ship dist/index.js" then fails for a reason that has nothing to do
 * with the tarball. That happened on the Linux runner while this passed here.
 */

export type PackReport = { files?: { path: string }[] };

export function packReportFiles(stdout: string, name: string): { files: string[]; why: string } {
  const text = stdout.trim();
  const starts = [text.indexOf("["), text.indexOf("{")].filter((i) => i >= 0);
  if (starts.length === 0) {
    return { files: [], why: `npm pack --json printed no json: ${text.slice(0, 160)}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.slice(Math.min(...starts)));
  } catch (err) {
    return { files: [], why: `unreadable json: ${(err as Error).message}` };
  }
  const report = Array.isArray(parsed)
    ? ((parsed as PackReport[])[0] ?? null)
    : ((parsed as Record<string, PackReport>)[name] ??
        Object.values(parsed as Record<string, PackReport>)[0] ??
        null);
  const files = (report?.files ?? []).map((f) => f.path.replace(/\\/g, "/"));
  const shape = Array.isArray(parsed) ? "array" : "object";
  return { files, why: files.length === 0 ? `no files in the ${shape} report` : "" };
}
