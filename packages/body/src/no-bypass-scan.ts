import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

export type BypassHit = {
  file: string;
  line: number;
  why: string;
  text: string;
};

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      walk(full, out);
      continue;
    }
    if (name.endsWith(".ts") || name.endsWith(".js") || name.endsWith(".mjs")) {
      out.push(full);
    }
  }
  return out;
}

const IMPORT_TOOLS = /(?:from|import)\s+["'][^"']*tools\/[^"']+["']/;
const DYNAMIC_IMPORT = /\bimport\s*\(/g;
const NEW_FUNCTION = /new Function\s*\(/;
const EVAL_CALL = /\beval\s*\(/;
const VM = /\bvm\b/;
const PROCESS_BINDING = /process\.binding/;
const REQUIRE = /\brequire\s*\(/;
const CREATE_REQUIRE = /\bcreateRequire\b/;
const CONCAT_TOOLS = /["']\.\/to["']\s*\+\s*["']ols/;
const CHILD = /\bchild_process\b/;
const WORKER = /\bworker_threads\b/;

function stripCommentsPreservingLines(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/\/\/.*$/gm, (m) => " ".repeat(m.length));
}

function lineAt(text: string, index: number): number {
  return text.slice(0, index).split(/\n/).length;
}

export function scanNoBypass(
  base = pkgRoot,
  extra: Array<{ file: string; text: string }> = [],
): BypassHit[] {
  const hits: BypassHit[] = [];
  const files = [
    ...walk(join(base, "src")).map((full) => ({
      file: relative(base, full).replace(/\\/g, "/"),
      text: readFileSync(full, "utf8"),
    })),
    ...(existsSync(join(base, "tests"))
      ? walk(join(base, "tests")).map((full) => ({
          file: relative(base, full).replace(/\\/g, "/"),
          text: readFileSync(full, "utf8"),
        }))
      : []),
    ...extra,
  ];
  for (const { file, text } of files) {
    const rel = file.replace(/\\/g, "/");
    if (rel === "src/no-bypass-scan.ts") continue;
    const wiring = rel === "src/wiring.ts";
    const stripped = stripCommentsPreservingLines(text);
    const originalLines = text.split(/\r?\n/);
    for (const match of stripped.matchAll(DYNAMIC_IMPORT)) {
      const index = match.index ?? 0;
      const line = lineAt(stripped, index);
      hits.push({
        file,
        line,
        why: "dynamic-import",
        text: (originalLines[line - 1] ?? "").trim(),
      });
    }
    const lines = stripped.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? "";
      const push = (why: string) => {
        hits.push({ file, line: i + 1, why, text: (originalLines[i] ?? "").trim() });
      };
      if (IMPORT_TOOLS.test(line) && !wiring) {
        push("static import of tools/");
      }
      if (NEW_FUNCTION.test(line)) push("new-function");
      if (EVAL_CALL.test(line)) push("eval");
      if (VM.test(line)) push("vm");
      if (PROCESS_BINDING.test(line)) push("process.binding");
      if (REQUIRE.test(line)) push("require(");
      if (CREATE_REQUIRE.test(line)) push("createRequire");
      if (CONCAT_TOOLS.test(line)) push("concatenated tools path");
      if (CHILD.test(line)) push("child_process");
      if (WORKER.test(line)) push("worker_threads");
    }
  }
  return hits;
}
