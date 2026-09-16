#!/usr/bin/env node
// Installs what npm would publish, from a directory that is not this one, and
// asks the installed thing to speak. The repository tree proves nothing here:
// Node does not run TypeScript out of node_modules, so a package whose entry
// points at src/*.ts installs cleanly and then fails on first import.
//
// Run: node --experimental-strip-types scripts/pack-smoke.ts

import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { packReportFiles } from "./pack-report.ts";

const PACKAGES = ["@verax-ai/inventory", "@verax-ai/proxy", "@verax-ai/body"] as const;

// npm and npx are scripts on Windows and need a shell; node is an executable
// whose path holds a space, and a shell would split it.
function run(cmd: string, args: string[], cwd: string): { status: number; out: string; stdout: string } {
  const shell = process.platform === "win32" && cmd !== process.execPath;
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", shell });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}`, stdout: r.stdout ?? "" };
}

const failures: string[] = [];
function check(ok: boolean, what: string, detail = ""): void {
  process.stdout.write(`${ok ? "ok  " : "FAIL"} ${what}${detail ? ` - ${detail}` : ""}\n`);
  if (!ok) failures.push(what);
}

const repo = process.cwd();
const packDir = mkdtempSync(join(tmpdir(), "verax-pack-"));
const tarballs = new Map<string, string>();

for (const name of PACKAGES) {
  const packed = run("npm", ["pack", "-w", name, "--pack-destination", packDir, "--silent"], repo);
  check(packed.status === 0, `npm pack ${name}`, packed.status === 0 ? "" : packed.out.slice(0, 400));
  const file = readdirSync(packDir).find((f) => f.startsWith(name.replace("@", "").replace("/", "-")));
  if (!file) {
    check(false, `tarball for ${name}`);
    continue;
  }
  tarballs.set(name, join(packDir, file));
  const listing = run("npm", ["pack", "--dry-run", "--json", "-w", name], repo);
  const { files, why } = packReportFiles(listing.stdout, name);
  check(files.length > 0, `${name}: npm lists the packed files`, why);
  check(!files.some((f) => /^(src|tests)\//.test(f)), `${name}: no sources or tests in the tarball`);
  check(
    !files.some((f) => f.endsWith(".ts") && !f.endsWith(".d.ts")),
    `${name}: no TypeScript entry files`,
    files.filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts")).join(" "),
  );
  check(files.includes("dist/index.js"), `${name}: ships dist/index.js`);
  check(!files.some((f) => /(^|\/)state\/|\.pem$|dev-token/.test(f)), `${name}: no keys or state`);
}

// A consumer that is not this repository. The two libraries are pinned through
// overrides because they are not on the registry yet; body asks for them by name.
const consumer = mkdtempSync(join(tmpdir(), "verax-consumer-"));
writeFileSync(
  join(consumer, "package.json"),
  `${JSON.stringify(
    {
      name: "verax-pack-smoke",
      private: true,
      version: "1.0.0",
      type: "module",
      dependencies: { "@verax-ai/body": `file:${tarballs.get("@verax-ai/body")}` },
      overrides: {
        "@verax-ai/proxy": `file:${tarballs.get("@verax-ai/proxy")}`,
        "@verax-ai/inventory": `file:${tarballs.get("@verax-ai/inventory")}`,
      },
    },
    null,
    2,
  )}\n`,
  "utf8",
);

const install = run("npm", ["install", "--silent", "--no-audit", "--no-fund"], consumer);
check(install.status === 0, "clean install of the published packages", install.out.slice(0, 600));

const help = run("npx", ["--no-install", "verax", "--help"], consumer);
check(help.status === 0 && /Usage: verax/.test(help.out), "verax --help from the installed bin", help.out.slice(0, 300));

const version = run("npx", ["--no-install", "verax", "--version"], consumer);
check(/^\d+\.\d+\.\d+/.test(version.out.trim()), "verax --version prints a version", version.out.trim().slice(0, 80));

writeFileSync(join(consumer, "probe.mjs"), 'import("@verax-ai/body").then(() => console.log("imported"));\n', "utf8");
const probe = run(process.execPath, ["probe.mjs"], consumer);
check(probe.status === 0 && /imported/.test(probe.out), "importing @verax-ai/body in a plain Node process", probe.out.slice(0, 300));

process.stdout.write(`\npack-smoke: ${failures.length === 0 ? "green" : `${failures.length} failed`}\n`);
process.stdout.write(`tarballs: ${packDir}\nconsumer: ${consumer}\n`);
process.exit(failures.length === 0 ? 0 : 1);
