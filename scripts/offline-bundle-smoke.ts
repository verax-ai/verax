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
  const install = runNpm(
    ["install", "--offline", "--cache", join(bundle, "npm-cache"), "--no-audit", "--no-fund", ...tarballs],
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
} catch (err) {
  check(false, "offline bundle smoke", err instanceof Error ? err.message : "smoke failed");
} finally {
  rmSync(consumer, cleanup);
  rmSync(bundleParent, cleanup);
}

process.stdout.write(`\noffline-smoke: ${failures.length === 0 ? "green" : `${failures.length} failed`}\n`);
process.exit(failures.length === 0 ? 0 : 1);
