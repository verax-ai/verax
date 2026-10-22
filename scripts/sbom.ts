#!/usr/bin/env node
// Writes one CycloneDX JSON file for the three packages a customer installs
// plus their production dependencies. npm sbom cannot run against this
// workspace root: it has no version, so the purl type is "range".
// The working path packs the three, installs the tarballs into a temporary
// verax-sbom directory, then runs npm sbom there.
//
// Run: node --experimental-strip-types scripts/sbom.ts

import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { runNpm } from "./lib/npm-run.ts";

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

function parseJsonObject(stdout: string): unknown {
  const start = stdout.indexOf("{");
  if (start < 0) {
    throw new Error(`npm sbom printed no json: ${stdout.slice(0, 240)}`);
  }
  return JSON.parse(stdout.slice(start));
}

export function readShipVersion(repo: string): string {
  const versions = WORKSPACES.map(({ slug, workspace }) => {
    const pkg = JSON.parse(readFileSync(join(repo, "packages", slug, "package.json"), "utf8")) as {
      version?: unknown;
    };
    if (typeof pkg.version !== "string" || pkg.version.length === 0) {
      throw new Error(`${workspace} has no version`);
    }
    return { workspace, version: pkg.version };
  });
  const version = versions[0]!.version;
  for (const row of versions) {
    if (row.version !== version) {
      throw new Error(`${row.workspace} is ${row.version}, expected ${version}`);
    }
  }
  return version;
}

export function writeSbom(destDir: string, repo: string): string {
  const version = readShipVersion(repo);
  mkdirSync(destDir, { recursive: true });
  const staging = mkdtempSync(join(tmpdir(), "verax-sbom-"));
  try {
    const packDir = join(staging, "p");
    mkdirSync(packDir, { recursive: true });
    // -w and --pack-destination: docs.npmjs.com/cli/v11/commands/npm-pack
    const packed = runNpm(
      [
        "pack",
        "-w",
        "@verax-ai/proxy",
        "-w",
        "@verax-ai/inventory",
        "-w",
        "@verax-ai/body",
        "--pack-destination",
        packDir,
      ],
      repo,
    );
    if (packed.status !== 0) {
      throw new Error(`npm pack for SBOM failed:\n${packed.out.slice(0, 800)}`);
    }

    writeFileSync(
      join(staging, "package.json"),
      `${JSON.stringify({ name: "verax-sbom", version: "1.0.0", private: true })}\n`,
      "utf8",
    );

    const tarballs = readdirSync(packDir)
      .filter((name) => name.endsWith(".tgz"))
      .sort()
      .map((name) => join(packDir, name));
    if (tarballs.length === 0) {
      throw new Error("npm pack wrote no tarballs");
    }

    // --ignore-scripts: docs.npmjs.com/cli/v11/using-npm/config#ignore-scripts
    const installed = runNpm(["install", "--no-audit", "--no-fund", "--ignore-scripts", ...tarballs], staging);
    if (installed.status !== 0) {
      throw new Error(`npm install for SBOM failed:\n${installed.out.slice(0, 1200)}`);
    }

    // --sbom-format cyclonedx and --omit: docs.npmjs.com/cli/v11/commands/npm-sbom
    const generated = runNpm(["sbom", "--sbom-format", "cyclonedx", "--omit", "dev"], staging);
    if (generated.status !== 0) {
      throw new Error(`npm sbom failed:\n${generated.out.slice(0, 800)}`);
    }
    const bom = parseJsonObject(generated.stdout) as CycloneDx;
    if (bom.bomFormat !== "CycloneDX") {
      throw new Error(`bomFormat is ${JSON.stringify(bom.bomFormat)}, not "CycloneDX"`);
    }
    const listed = Array.isArray(bom.components) ? bom.components : [];
    if (listed.length === 0 && bom.metadata?.component && typeof bom.metadata.component === "object") {
      bom.components = [bom.metadata.component];
    }
    if (!Array.isArray(bom.components) || bom.components.length === 0) {
      throw new Error("CycloneDX component list is empty");
    }
    const file = join(destDir, `verax-${version}.cdx.json`);
    writeFileSync(file, `${JSON.stringify(bom, null, 2)}\n`, "utf8");
    return file;
  } finally {
    rmSync(staging, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
}

const invoked = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
  try {
    const file = writeSbom(join(repo, "sbom"), repo);
    process.stdout.write(`wrote ${file}\n`);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : err}\n`);
    process.exit(1);
  }
}
