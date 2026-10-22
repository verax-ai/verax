#!/usr/bin/env node
// Builds an offline bundle, then installs it the way an air-gapped host
// would: empty directory, --offline, the bundle cache, the packed tarballs.
// A registry request fails the run because --offline refuses it.
//
// Run: node --experimental-strip-types scripts/offline-bundle-smoke.ts

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { defaultElevated } from "../packages/body/src/install.ts";
import { runNpm, runNpx } from "./lib/npm-run.ts";
import { buildOfflineBundle, readShipVersion, tarballPaths, verifySha256Sums } from "./offline-bundle.ts";

const failures: string[] = [];
function check(ok: boolean, what: string, detail = ""): void {
  process.stdout.write(`${ok ? "ok  " : "FAIL"} ${what}${detail ? ` - ${detail}` : ""}\n`);
  if (!ok) failures.push(what);
}

function parseJsonObject(stdout: string): unknown {
  const start = stdout.indexOf("{");
  if (start < 0) {
    throw new Error(`npm ls printed no json: ${stdout.slice(0, 240)}`);
  }
  return JSON.parse(stdout.slice(start));
}

function componentName(component: { name?: unknown; group?: unknown }): string | null {
  if (typeof component.name === "string" && component.name.startsWith("@")) {
    return component.name;
  }
  if (typeof component.group === "string" && typeof component.name === "string") {
    return `${component.group}/${component.name}`;
  }
  return typeof component.name === "string" ? component.name : null;
}

function installedVersions(tree: unknown): Map<string, string> {
  const versions = new Map<string, string>();
  const walk = (node: unknown, key?: string) => {
    if (!node || typeof node !== "object") return;
    const rec = node as { name?: unknown; version?: unknown; dependencies?: unknown };
    const name = typeof rec.name === "string" ? rec.name : key;
    if (name && typeof rec.version === "string") versions.set(name, rec.version);
    if (rec.dependencies && typeof rec.dependencies === "object" && rec.dependencies) {
      for (const [depName, dep] of Object.entries(rec.dependencies as Record<string, unknown>)) {
        walk(dep, depName);
      }
    }
  };
  walk(tree);
  return versions;
}

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const version = readShipVersion(repo);
const bundleParent = mkdtempSync(join(tmpdir(), "verax-offline-bundle-"));
const consumerParent =
  process.platform === "win32" && defaultElevated("win32") && process.env.ProgramFiles
    ? process.env.ProgramFiles
    : tmpdir();
const consumer = mkdtempSync(join(consumerParent, "verax-offline-consumer-"));
const cleanup = { recursive: true, force: true, maxRetries: 10, retryDelay: 200 } as const;

try {
  const bundle = buildOfflineBundle(repo, join(bundleParent, `verax-offline-${version}`));
  check(true, `built ${bundle}`);

  try {
    const sbomFile = join(bundle, "sbom", `verax-${version}.cdx.json`);
    const bom = JSON.parse(readFileSync(sbomFile, "utf8")) as {
      bomFormat?: unknown;
      components?: unknown;
    };
    check(
      bom.bomFormat === "CycloneDX" && Array.isArray(bom.components) && bom.components.length > 0,
      `bundle SBOM is CycloneDX with components (${sbomFile})`,
    );
  } catch (err) {
    check(false, "bundle SBOM is CycloneDX with components", err instanceof Error ? err.message : "read failed");
  }

  try {
    verifySha256Sums(bundle);
    check(true, "SHA256SUMS matches every file in the bundle");
  } catch (err) {
    check(false, "SHA256SUMS matches every file in the bundle", err instanceof Error ? err.message : "verify failed");
  }

  writeFileSync(
    join(consumer, "package.json"),
    `${JSON.stringify({ name: "verax-offline-smoke", private: true, version: "1.0.0" })}\n`,
    "utf8",
  );
  const tarballs = tarballPaths(bundle);
  // --offline: no network requests (docs.npmjs.com/cli/v11/using-npm/config#offline).
  // --cache: npm's cache directory (docs.npmjs.com/cli/v11/using-npm/config#cache).
  // --ignore-scripts: skip lifecycle scripts (docs.npmjs.com/cli/v11/using-npm/config#ignore-scripts).
  const install = runNpm(
    [
      "install",
      "--offline",
      "--cache",
      join(bundle, "npm-cache"),
      "--no-audit",
      "--no-fund",
      "--ignore-scripts",
      ...tarballs,
    ],
    consumer,
  );
  check(install.status === 0, "npm install --offline from the bundle cache", install.out.slice(0, 800));

  const printed = runNpx(["--no-install", "verax", "--version"], consumer);
  const line = printed.stdout.trim().split(/\r?\n/)[0] ?? "";
  check(
    printed.status === 0 && line === version,
    "verax --version from the offline install",
    (line || printed.out.trim()).slice(0, 80),
  );

  try {
    const sbomFile = join(bundle, "sbom", `verax-${version}.cdx.json`);
    const bom = JSON.parse(readFileSync(sbomFile, "utf8")) as {
      components?: unknown;
    };
    const listed = Array.isArray(bom.components) ? bom.components : [];
    const ls = runNpm(["ls", "--json", "--all", "--omit", "dev", "--offline"], consumer);
    const installed = installedVersions(parseJsonObject(ls.stdout));
    const verax = listed
      .map((row) => (row && typeof row === "object" ? row : null))
      .filter((row): row is { name?: unknown; group?: unknown; version?: unknown } => row !== null)
      .map((row) => ({ name: componentName(row), version: row.version }))
      .filter((row): row is { name: string; version: string } => typeof row.name === "string" && typeof row.version === "string");
    const ours = verax.filter((row) => row.name.startsWith("@verax-ai/"));
    const third = verax.find((row) => !row.name.startsWith("@verax-ai/") && installed.has(row.name));
    const oursMatch =
      ours.length > 0 && ours.every((row) => installed.get(row.name) === row.version);
    const thirdMatch = third !== undefined && installed.get(third.name) === third.version;
    check(
      oursMatch && thirdMatch,
      "SBOM versions match offline npm ls --json",
      oursMatch && thirdMatch
        ? `${ours.length} @verax-ai/* and ${third!.name}@${third!.version}`
        : `ours=${ours.map((row) => `${row.name}@${row.version}≠${installed.get(row.name) ?? "missing"}`).join(",") || "none"}; third=${third ? `${third.name}@${third.version}≠${installed.get(third.name) ?? "missing"}` : "none"}`,
    );
  } catch (err) {
    check(false, "SBOM versions match offline npm ls --json", err instanceof Error ? err.message : "compare failed");
  }
} catch (err) {
  check(false, "offline bundle smoke", err instanceof Error ? err.message : "smoke failed");
} finally {
  rmSync(consumer, cleanup);
  rmSync(bundleParent, cleanup);
}

process.stdout.write(`\noffline-smoke: ${failures.length === 0 ? "green" : `${failures.length} failed`}\n`);
process.exit(failures.length === 0 ? 0 : 1);
