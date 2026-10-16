#!/usr/bin/env node
// Reads what npm, Docker Hub, GitHub, Zenodo and the MCP registry hold for
// the version in this tree, and the text on the Docker Hub page, and fails
// if any of them disagrees. It needs the
// network, so it is not part of `npm test`; the comparison itself is
// scripts/release-facts.ts and is tested offline.
//
// Run after a release: npm run release:check

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { latestRecord } from "./registry-record.ts";
import { releaseProblems, statusMatrixVersion, type ReleaseFacts } from "./release-facts.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ZENODO_CONCEPT = "22811593";
const REGISTRY_NAME = "io.github.verax-ai/verax";
const IMAGE = "veraxai/verax";

const readJson = (rel: string) => JSON.parse(readFileSync(join(root, rel), "utf8")) as Record<string, unknown>;

async function getJson(url: string, headers: Record<string, string> = {}): Promise<unknown | null> {
  try {
    // Zenodo answers 403 to a request without a user agent of its own.
    const res = await fetch(url, {
      headers: { accept: "application/json", "user-agent": "verax-release-check (+https://github.com/verax-ai/verax)", ...headers },
    });
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

async function npmLatest(name: string): Promise<string | null> {
  const doc = (await getJson(`https://registry.npmjs.org/${name.replace("/", "%2f")}`, {
    accept: "application/vnd.npm.install-v1+json",
  })) as { "dist-tags"?: { latest?: unknown } } | null;
  const v = doc?.["dist-tags"]?.latest;
  return typeof v === "string" ? v : null;
}

async function dockerDigest(tag: string): Promise<string | null> {
  const doc = (await getJson(`https://hub.docker.com/v2/repositories/${IMAGE}/tags/${tag}`)) as { digest?: unknown } | null;
  return typeof doc?.digest === "string" ? doc.digest : null;
}

async function dockerTexts(): Promise<{ description: string | null; overview: string | null }> {
  const doc = (await getJson(`https://hub.docker.com/v2/repositories/${IMAGE}/`)) as {
    description?: unknown;
    full_description?: unknown;
  } | null;
  return {
    description: typeof doc?.description === "string" ? doc.description : null,
    overview: typeof doc?.full_description === "string" ? doc.full_description : null,
  };
}

async function tagCommit(version: string): Promise<string | null> {
  const token = process.env.GITHUB_TOKEN;
  const doc = (await getJson(
    `https://api.github.com/repos/verax-ai/verax/commits/v${version}`,
    token ? { authorization: `Bearer ${token}` } : {},
  )) as { sha?: unknown } | null;
  return typeof doc?.sha === "string" ? doc.sha : null;
}

async function zenodoLatest(): Promise<string | null> {
  const doc = (await getJson(`https://zenodo.org/api/records/${ZENODO_CONCEPT}/versions/latest`)) as {
    metadata?: { version?: unknown };
  } | null;
  const v = doc?.metadata?.version;
  return typeof v === "string" ? v : null;
}

async function registryLatest(): Promise<string | null> {
  try {
    const res = await fetch(`https://registry.modelcontextprotocol.io/v0/servers?search=${encodeURIComponent(REGISTRY_NAME)}`);
    return latestRecord(await res.text(), REGISTRY_NAME).found?.version ?? null;
  } catch {
    return null;
  }
}

const packages: Record<string, string> = {};
for (const dir of ["body", "proxy", "inventory"]) {
  const pkg = readJson(`packages/${dir}/package.json`);
  packages[String(pkg.name)] = String(pkg.version);
}
const version = String(readJson("packages/body/package.json").version);

const npm: Record<string, string | null> = {};
for (const name of Object.keys(packages)) npm[name] = await npmLatest(name);
const docker = await dockerTexts();

const facts: ReleaseFacts = {
  version,
  packages,
  npmLatest: npm,
  releaseCommit: await tagCommit(version),
  platformsSha: String(readJson("docs/platforms.json").sha),
  statusMatrixVersion: statusMatrixVersion(readFileSync(join(root, "docs", "STATUS.md"), "utf8")),
  dockerVersionDigest: await dockerDigest(version),
  dockerLatestDigest: await dockerDigest("latest"),
  zenodoLatestVersion: await zenodoLatest(),
  registryLatestVersion: await registryLatest(),
  bodyDescription: String(readJson("packages/body/package.json").description),
  dockerOverviewInTree: readFileSync(join(root, "docs", "dockerhub.md"), "utf8"),
  dockerDescription: docker.description,
  dockerOverview: docker.overview,
};

const problems = releaseProblems(facts);
if (problems.length === 0) {
  process.stdout.write(`release-check: ${version} on npm, Docker Hub, GitHub, Zenodo and the MCP registry\n`);
  process.exit(0);
}
process.stderr.write(`release-check: ${version} — ${problems.length} place(s) disagree:\n`);
for (const p of problems) process.stderr.write(`  ${p}\n`);
process.exit(1);
