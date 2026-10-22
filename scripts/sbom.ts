#!/usr/bin/env node
// Writes one CycloneDX JSON file per published workspace package, using
// npm's built-in `npm sbom`. Nothing is added to package.json dependencies.
//
// Run: node --experimental-strip-types scripts/sbom.ts

import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const WORKSPACES = [
  { workspace: "@verax-ai/inventory", slug: "inventory" },
  { workspace: "@verax-ai/proxy", slug: "proxy" },
  { workspace: "@verax-ai/body", slug: "body" },
] as const;

type CycloneDx = {
  bomFormat?: unknown;
  components?: unknown;
  metadata?: { component?: unknown };
};

function run(cmd: string, args: string[], cwd: string): { status: number; out: string; stdout: string } {
  const shell = process.platform === "win32" && cmd !== process.execPath;
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", shell });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}`, stdout: r.stdout ?? "" };
}

function parseJsonObject(stdout: string): unknown {
  const start = stdout.indexOf("{");
  if (start < 0) {
    throw new Error(`npm sbom printed no json: ${stdout.slice(0, 240)}`);
  }
  return JSON.parse(stdout.slice(start));
}

export function writeSboms(destDir: string, repo: string): string[] {
  mkdirSync(destDir, { recursive: true });
  const written: string[] = [];
  for (const { workspace, slug } of WORKSPACES) {
    const pkg = JSON.parse(readFileSync(join(repo, "packages", slug, "package.json"), "utf8")) as {
      version?: unknown;
    };
    if (typeof pkg.version !== "string" || pkg.version.length === 0) {
      throw new Error(`${workspace} has no version`);
    }
    // --sbom-format cyclonedx and --workspace: docs.npmjs.com/cli/v11/commands/npm-sbom
    // --package-lock-only is not passed: that mode drops description/homepage/engines.
    const generated = run("npm", ["sbom", "--sbom-format", "cyclonedx", "--workspace", workspace], repo);
    if (generated.status !== 0) {
      throw new Error(`npm sbom --workspace ${workspace} failed:\n${generated.out.slice(0, 800)}`);
    }
    const bom = parseJsonObject(generated.stdout) as CycloneDx;
    if (bom.bomFormat !== "CycloneDX") {
      throw new Error(`${workspace}: bomFormat is ${JSON.stringify(bom.bomFormat)}, not "CycloneDX"`);
    }
    const listed = Array.isArray(bom.components) ? bom.components : [];
    // npm puts the subject in metadata.component. A package with no
    // dependencies (inventory) would otherwise have an empty list.
    if (listed.length === 0 && bom.metadata?.component && typeof bom.metadata.component === "object") {
      bom.components = [bom.metadata.component];
    }
    if (!Array.isArray(bom.components) || bom.components.length === 0) {
      throw new Error(`${workspace}: CycloneDX component list is empty`);
    }
    const file = join(destDir, `${slug}-${pkg.version}.cdx.json`);
    writeFileSync(file, `${JSON.stringify(bom, null, 2)}\n`, "utf8");
    written.push(file);
  }
  return written;
}

const invoked = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
  try {
    const files = writeSboms(join(repo, "sbom"), repo);
    for (const file of files) {
      process.stdout.write(`wrote ${file}\n`);
    }
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : err}\n`);
    process.exit(1);
  }
}
