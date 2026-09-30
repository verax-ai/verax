// A production package that does `try { require("x") } catch {}` for a name
// the shipped tree does not contain leaves a hole in the module search path:
// Node walks every ancestor's node_modules up to the drive root, and stock
// Windows lets any user create C:\node_modules. This lists every such
// guarded require or import in the body's production tree and fails when a
// name does not resolve inside this checkout, unless it is on the reviewed
// list below.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire, isBuiltin } from "node:module";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Reviewed: the guarded require is in a package the body never loads.
 * Each entry names the file relative to its package and the missing name.
 */
export const REVIEWED = [
  {
    pkg: "debug",
    file: "src/node.js",
    name: "supports-color",
    why: "debug is in the tree for express, which the body does not import; importing every module cli.ts imports leaves debug out of the module cache (measured 28 Sep 2026)",
  },
];

const TRY = /\btry\s*\{/g;
// require("x") or import("x") of a bare specifier.
const LOAD = /\b(?:require|import)\(\s*["']([^"'./][^"']*)["']\s*\)/g;

/**
 * The body of every try block, found by counting braces from its opening
 * brace. Strings and comments are not parsed, so a brace inside one can
 * shorten or lengthen a block. A load inside a nested block is inside the
 * outer block too, so it is found either way.
 */
export function tryBlocks(text) {
  const blocks = [];
  for (const m of text.matchAll(TRY)) {
    let depth = 1;
    let i = m.index + m[0].length;
    const start = i;
    while (i < text.length && depth > 0) {
      const c = text[i];
      if (c === "{") depth++;
      else if (c === "}") depth--;
      i++;
    }
    blocks.push(text.slice(start, depth === 0 ? i - 1 : i));
  }
  return blocks;
}

/** Every bare name a try block requires or imports, once each. */
export function guardedNames(text) {
  const names = new Set();
  for (const block of tryBlocks(text)) {
    for (const m of block.matchAll(LOAD)) names.add(m[1]);
  }
  return [...names];
}

/**
 * The name resolves to a file inside this checkout. A copy found anywhere
 * else, such as a planted C:\node_modules, is exactly the hole this guard
 * looks for, so it does not count as being in the tree.
 */
export function resolvesInTree(name, fromFile, root = repo) {
  let found;
  try {
    found = createRequire(fromFile).resolve(name);
  } catch {
    return false;
  }
  const rel = relative(root, found);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** npm's own CLI script, run with this Node: no shell, so nothing is concatenated into a command line. */
function npmCli() {
  const candidates = [
    process.env.npm_execpath,
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
    join(dirname(process.execPath), "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ];
  const found = candidates.find((file) => file && /npm-cli\.js$/.test(file) && existsSync(file));
  if (!found) throw new Error("optional-require-guard: cannot find npm-cli.js next to this Node");
  return found;
}

function productionPackages() {
  const out = execFileSync(process.execPath, [npmCli(), "ls", "--omit=dev", "--all", "--parseable", "-w", "@verax-ai/body"], {
    cwd: repo,
    encoding: "utf8",
  });
  return [...new Set(out.split(/\r?\n/).filter((line) => line.includes(`${sep}node_modules${sep}`)))];
}

function jsFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...jsFiles(full));
    else if (/\.(c|m)?js$/.test(entry.name)) files.push(full);
  }
  return files;
}

function packageName(dir) {
  try {
    return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).name ?? dir;
  } catch {
    return dir;
  }
}

export function scan() {
  const findings = [];
  for (const dir of productionPackages()) {
    const pkg = packageName(dir);
    for (const file of jsFiles(dir)) {
      const text = readFileSync(file, "utf8");
      for (const name of guardedNames(text)) {
        if (isBuiltin(name)) continue;
        // Not in the tree: a planted copy would be the one that loads.
        if (resolvesInTree(name, file)) continue;
        const rel = relative(dir, file).split(sep).join("/");
        const reviewed = REVIEWED.some((r) => r.pkg === pkg && r.file === rel && r.name === name);
        findings.push({ pkg, file: rel, name, reviewed });
      }
    }
  }
  return findings;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const findings = scan();
  for (const f of findings) {
    process.stdout.write(`${f.reviewed ? "reviewed" : "UNREVIEWED"} ${f.pkg}/${f.file} try-requires ${f.name}, which is not in the tree\n`);
  }
  const open = findings.filter((f) => !f.reviewed);
  process.exitCode = open.length === 0 ? 0 : 1;
}
