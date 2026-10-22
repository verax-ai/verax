#!/usr/bin/env node
// Builds verax-offline-<version>/ on a machine that can reach the npm
// registry: packed tarballs, an npm cache filled from those tarballs, the
// CycloneDX files, SHA256SUMS, and INSTALL-OFFLINE.md.
//
// Run: node --experimental-strip-types scripts/offline-bundle.ts

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { WORKSPACES, writeSboms } from "./sbom.ts";

function run(cmd: string, args: string[], cwd: string): { status: number; out: string; stdout: string } {
  const shell = process.platform === "win32" && cmd !== process.execPath;
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", shell });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}`, stdout: r.stdout ?? "" };
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

export function walkFiles(root: string, rel = ""): string[] {
  const dir = rel ? join(root, rel) : root;
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const child = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...walkFiles(root, child));
    else out.push(child);
  }
  return out;
}

export function writeSha256Sums(bundle: string): string {
  const lines = walkFiles(bundle)
    .filter((rel) => rel !== "SHA256SUMS")
    .sort()
    .map((rel) => {
      const digest = createHash("sha256").update(readFileSync(join(bundle, rel))).digest("hex");
      return `${digest}  ${rel}`;
    });
  const text = `${lines.join("\n")}\n`;
  const path = join(bundle, "SHA256SUMS");
  writeFileSync(path, text, "utf8");
  return path;
}

export function verifySha256Sums(bundle: string): void {
  const listed = new Map<string, string>();
  const raw = readFileSync(join(bundle, "SHA256SUMS"), "utf8");
  for (const line of raw.split(/\n/)) {
    if (line === "") continue;
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    if (!match) {
      throw new Error(`SHA256SUMS line is not '<sha256>  <path>': ${line.slice(0, 160)}`);
    }
    listed.set(match[2]!, match[1]!);
  }
  const present = walkFiles(bundle)
    .filter((rel) => rel !== "SHA256SUMS")
    .sort();
  const expected = [...listed.keys()].sort();
  if (present.length !== expected.length || present.some((rel, i) => rel !== expected[i])) {
    throw new Error("SHA256SUMS and the bundle files differ");
  }
  for (const rel of present) {
    const digest = createHash("sha256").update(readFileSync(join(bundle, rel))).digest("hex");
    if (digest !== listed.get(rel)) {
      throw new Error(`SHA256SUMS mismatch: ${rel}`);
    }
  }
}

export function tarballPaths(bundle: string): string[] {
  const dir = join(bundle, "packages");
  const names = readdirSync(dir)
    .filter((name) => name.endsWith(".tgz"))
    .sort();
  for (const slug of ["inventory", "proxy", "body"]) {
    if (!names.some((name) => name.includes(`verax-ai-${slug}-`) && name.endsWith(".tgz"))) {
      throw new Error(`packages/ has no tarball for ${slug}`);
    }
  }
  return names.map((name) => join(dir, name));
}

function installOfflineDoc(version: string): string {
  return `# Install Verax ${version} without the npm registry

This directory is a bundle produced on a machine that could reach the
registry. Copy the whole directory. Do not add or remove files before
you check SHA256SUMS.

## Check the files

On a host with GNU coreutils:

\`\`\`sh
sha256sum -c SHA256SUMS
\`\`\`

On any host with Node:

\`\`\`sh
node --input-type=module -e "import { createHash } from 'node:crypto'; import { readFileSync } from 'node:fs'; for (const line of readFileSync('SHA256SUMS','utf8').split(/\\n/)) { if (!line) continue; const [hash, file] = line.split(/ {2}/); const got = createHash('sha256').update(readFileSync(file)).digest('hex'); if (got !== hash) { console.error('mismatch', file); process.exit(1); } } console.log('SHA256SUMS ok');"
\`\`\`

## Install

Node 22.6 or newer. In an empty directory, pointing \`--cache\` at this
bundle's \`npm-cache\` and the tarballs under \`packages/\`:

\`\`\`sh
npm install --offline --cache /path/to/this/bundle/npm-cache --no-audit --no-fund /path/to/this/bundle/packages/verax-ai-inventory-${version}.tgz /path/to/this/bundle/packages/verax-ai-proxy-${version}.tgz /path/to/this/bundle/packages/verax-ai-body-${version}.tgz
npx --no-install verax --version
\`\`\`

\`--offline\` refuses a registry request
(https://docs.npmjs.com/cli/v11/using-npm/config#offline). \`--cache\` is
npm's cache directory
(https://docs.npmjs.com/cli/v11/using-npm/config#cache). \`--no-audit\`
and \`--no-fund\` stop the install from talking to the registry for
those side reports
(https://docs.npmjs.com/cli/v11/using-npm/config#audit,
https://docs.npmjs.com/cli/v11/using-npm/config#fund).

## What this does not do

npm provenance attestations cannot be checked on a host that cannot
reach the registry. \`npm audit signatures\` needs the registry
(https://docs.npmjs.com/cli/v11/commands/npm-audit). Run that on the
connected machine that built this bundle, then move the bundle.

This is \`npm install\` of the three packages. It is not \`verax install\`,
which still talks to the registry and writes an administrator-owned
service.

The CycloneDX files under \`sbom/\` were produced by \`npm sbom --sbom-format cyclonedx\`
for each workspace package.
`;
}

export function buildOfflineBundle(repo: string, dest?: string): string {
  const version = readShipVersion(repo);
  const bundle = dest ?? join(repo, `verax-offline-${version}`);
  if (existsSync(bundle)) {
    rmSync(bundle, { recursive: true, force: true });
  }
  mkdirSync(join(bundle, "packages"), { recursive: true });
  mkdirSync(join(bundle, "npm-cache"), { recursive: true });

  for (const { workspace } of WORKSPACES) {
    // --pack-destination and --workspace: docs.npmjs.com/cli/v11/commands/npm-pack
    const packed = run(
      "npm",
      ["pack", "--workspace", workspace, "--pack-destination", join(bundle, "packages"), "--loglevel", "silent"],
      repo,
    );
    if (packed.status !== 0) {
      throw new Error(`npm pack ${workspace} failed:\n${packed.out.slice(0, 800)}`);
    }
  }

  writeSboms(join(bundle, "sbom"), repo);

  const staging = mkdtempSync(join(tmpdir(), "verax-offline-fill-"));
  try {
    writeFileSync(
      join(staging, "package.json"),
      `${JSON.stringify({ name: "verax-offline-fill", private: true, version: "1.0.0" })}\n`,
      "utf8",
    );
    const tarballs = tarballPaths(bundle);
    const cache = join(bundle, "npm-cache");
    const installed = run(
      "npm",
      ["install", "--cache", cache, "--no-audit", "--no-fund", ...tarballs],
      staging,
    );
    if (installed.status !== 0) {
      throw new Error(`filling npm-cache failed:\n${installed.out.slice(0, 1200)}`);
    }
    const logs = join(cache, "_logs");
    if (existsSync(logs)) {
      rmSync(logs, { recursive: true, force: true });
    }
  } finally {
    rmSync(staging, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }

  writeFileSync(join(bundle, "INSTALL-OFFLINE.md"), installOfflineDoc(version), "utf8");
  writeSha256Sums(bundle);
  return bundle;
}

const invoked = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
  try {
    const bundle = buildOfflineBundle(repo);
    process.stdout.write(`offline-bundle: ${bundle}\n`);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : err}\n`);
    process.exit(1);
  }
}
