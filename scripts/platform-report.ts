#!/usr/bin/env node
// Turns one commit's install-e2e and pack-smoke jobs into docs/PLATFORMS.md
// and docs/platforms.json. The run page is the evidence; this table only
// points at it.
//
// Run: node --experimental-strip-types scripts/platform-report.ts <full sha>
//   or: npm run platforms:report -- <full sha>

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export const CLAIM = {
  service: "installs as a separate service account and starts the service",
  signingKey: "a non-admin user cannot read the signing key",
  approvalQueue: "a non-admin user cannot write the approval queue",
  installedCode: "a non-admin user cannot change the installed code",
  agentToken: "the agent token works through the service",
  plantedDir: "a directory planted by a non-admin user is refused",
  installRace: "a non-admin user racing the install cannot plant inside the Verax root",
  packSmoke: "the npm packages install cleanly and init / serve / a tool call / verify work",
} as const;

const PROBE = [CLAIM.service, CLAIM.signingKey, CLAIM.approvalQueue, CLAIM.installedCode, CLAIM.agentToken];

export const OS_NOTE =
  "Where the jobs API did not include a step summary, the platform and architecture come from the job name and runner label.";

export type WorkflowKind = "install-e2e" | "pack-smoke";

export type ReportJob = {
  name: string;
  conclusion: string | null;
  htmlUrl: string;
  platform: string;
  architecture: string;
  checked: readonly string[];
};

export type PlatformRow = {
  platform: string;
  architecture: string;
  checked: string[];
  result: "success" | "failed";
  conclusion: string | null;
  runUrl: string;
  job: string;
};

export type PlatformDocument = {
  sha: string;
  date: string;
  statement: string;
  osNote: string;
  rows: PlatformRow[];
};

export function platformStatement(sha: string, date: string): string {
  return `This table is generated from CI for commit ${oneLine(sha)} on ${oneLine(date)}, and only these platforms are claimed.`;
}

/**
 * Windows is the only install job where a non-admin account plants a
 * directory and races the install. The macOS pre-created directory is made
 * with sudo, so it is not that claim. The uninstall steps force success
 * (`exit 0` or `|| true`) and do not check that the service, the code and
 * the account are gone, so that claim is not listed.
 */
export function claimsForJob(workflow: WorkflowKind, jobName: string): string[] {
  if (workflow === "pack-smoke") return [CLAIM.packSmoke];
  if (jobName.startsWith("windows")) return [...PROBE, CLAIM.plantedDir, CLAIM.installRace];
  if (jobName.startsWith("linux") || jobName.startsWith("macos")) return [...PROBE];
  return [];
}

export function resultOf(conclusion: string | null): "success" | "failed" {
  return conclusion === "success" ? "success" : "failed";
}

/**
 * The Actions REST job payload exposes the job name, conclusion, html_url
 * and runner labels. It does not expose the step summary, so the OS and
 * the CPU architecture are derived from the job name and the runner label.
 * `summaryFields` uses an `OS:` / `Architecture:` line when a payload
 * string actually carries one.
 */
export function derivePlatform(jobName: string, labels: readonly string[]): { platform: string; architecture: string } {
  const label = labels.find((item) => item.length > 0) ?? "";
  const haystack = `${jobName} ${label}`.toLowerCase();
  const named = (platform: string) => (label ? `${platform} (${label})` : platform);
  if (/\bwindows\b/.test(haystack) || haystack.includes("windows-")) {
    return { platform: named("Windows"), architecture: "x64" };
  }
  if (haystack.includes("macos-13") || haystack.includes("macos-15-intel")) {
    return { platform: named("macOS"), architecture: "x64" };
  }
  if (/\bmacos\b/.test(haystack) || haystack.includes("darwin")) {
    return { platform: named("macOS"), architecture: "arm64" };
  }
  if (haystack.includes("arm") || haystack.includes("aarch64")) {
    return { platform: named("Linux"), architecture: "arm64" };
  }
  if (/\blinux\b/.test(haystack) || haystack.includes("ubuntu")) {
    return { platform: named("Linux"), architecture: "x64" };
  }
  return { platform: label || jobName, architecture: "unknown" };
}

export function summaryFields(payload: unknown): { os: string | null; arch: string | null; claims: string[] | null } {
  const texts: string[] = [];
  walkStrings(payload, texts, 0);
  let os: string | null = null;
  let arch: string | null = null;
  const claims: string[] = [];
  for (const text of texts) {
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      const osMatch = /^(?:-\s*)?OS:\s*(.*)$/.exec(line);
      if (osMatch?.[1]?.trim() && !os) os = osMatch[1].trim();
      const archMatch = /^(?:-\s*)?Architecture:\s*(.*)$/.exec(line);
      if (archMatch?.[1]?.trim() && !arch) arch = archMatch[1].trim();
      const claimMatch = /^(✅|❌)\s+(\S.*)$/.exec(line);
      if (claimMatch?.[1] && claimMatch[2]) claims.push(`${claimMatch[1]} ${claimMatch[2].trim()}`);
    }
  }
  return { os, arch, claims: claims.length > 0 ? claims : null };
}

export type ApiJob = {
  name?: string;
  conclusion?: string | null;
  html_url?: string | null;
  labels?: string[];
  text?: string;
};

export function evidenceFromJob(workflow: WorkflowKind, job: ApiJob): ReportJob {
  const name = job.name?.trim() || "unnamed job";
  const labels = Array.isArray(job.labels) ? job.labels.filter((item): item is string => typeof item === "string") : [];
  const derived = derivePlatform(name, labels);
  const summary = summaryFields(job);
  // Step summary is absent from this payload: derive the OS from the job name and runner label.
  return {
    name,
    conclusion: typeof job.conclusion === "string" ? job.conclusion : null,
    htmlUrl: typeof job.html_url === "string" ? job.html_url.trim() : "",
    platform: summary.os ?? derived.platform,
    architecture: summary.arch ?? derived.architecture,
    checked: summary.claims ?? claimsForJob(workflow, name),
  };
}

export function formatPlatformReport(input: { sha: string; date: string; jobs: readonly ReportJob[] }): {
  markdown: string;
  json: string;
  document: PlatformDocument;
} {
  const rows: PlatformRow[] = input.jobs.map((job) => {
    const runUrl = job.htmlUrl.trim();
    if (!/^https:\/\//.test(runUrl)) {
      throw new Error(`refusing to write a row for ${job.name} without a run URL`);
    }
    return {
      platform: oneLine(job.platform),
      architecture: oneLine(job.architecture),
      checked: job.checked.map((item) => oneLine(item)),
      result: resultOf(job.conclusion),
      conclusion: job.conclusion,
      runUrl,
      job: oneLine(job.name),
    };
  });
  const statement = platformStatement(input.sha, input.date);
  const document: PlatformDocument = {
    sha: oneLine(input.sha),
    date: oneLine(input.date),
    statement,
    osNote: OS_NOTE,
    rows,
  };
  const lines = [
    "# Platforms",
    "",
    statement,
    "",
    OS_NOTE,
    "",
    "| Platform | Architecture | What was checked | Result | Link to the run |",
    "| --- | --- | --- | --- | --- |",
  ];
  for (const row of rows) {
    lines.push(
      `| ${cell(`${row.platform} - ${row.job}`)} | ${cell(row.architecture)} | ${cell(row.checked.join("; "))} | ${row.result} | [run](${row.runUrl}) |`,
    );
  }
  lines.push("");
  return { markdown: `${lines.join("\n")}`, json: `${JSON.stringify(document, null, 2)}\n`, document };
}

function oneLine(value: string): string {
  return value.replace(/[\r\n|]/g, " ").trim();
}

function cell(value: string): string {
  return value.replace(/\|/g, "\\|");
}

function walkStrings(value: unknown, out: string[], depth: number): void {
  if (depth > 8) return;
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) walkStrings(item, out, depth + 1);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) walkStrings(item, out, depth + 1);
  }
}

type WorkflowRun = { id: number; head_sha?: string };

function ghApi(pathname: string): unknown {
  const result = spawnSync("gh", ["api", pathname], {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = `${result.stderr ?? ""}${result.stdout ?? ""}`.trim() || result.error?.message || "no output";
    throw new Error(`gh api ${pathname} exited ${result.status ?? "none"}: ${detail.slice(0, 500)}`);
  }
  if (!result.stdout) throw new Error(`gh api ${pathname} returned an empty body`);
  return JSON.parse(result.stdout) as unknown;
}

function listRuns(workflowFile: string, sha: string): WorkflowRun[] {
  const runs: WorkflowRun[] = [];
  for (let page = 1; page <= 20; page += 1) {
    const body = ghApi(
      `repos/{owner}/{repo}/actions/workflows/${workflowFile}/runs?head_sha=${sha}&per_page=100&page=${page}`,
    ) as { workflow_runs?: WorkflowRun[] };
    const batch = body.workflow_runs ?? [];
    for (const run of batch) {
      if (run.head_sha && run.head_sha !== sha) continue;
      runs.push(run);
    }
    if (batch.length < 100) break;
  }
  return runs;
}

function listJobs(runId: number): ApiJob[] {
  const jobs: ApiJob[] = [];
  for (let page = 1; page <= 20; page += 1) {
    // filter=all keeps a failed attempt when a later attempt of the same run succeeded.
    const body = ghApi(
      `repos/{owner}/{repo}/actions/runs/${runId}/jobs?filter=all&per_page=100&page=${page}`,
    ) as { jobs?: ApiJob[] };
    const batch = body.jobs ?? [];
    jobs.push(...batch);
    if (batch.length < 100) break;
  }
  return jobs;
}

export function loadJobs(sha: string): ReportJob[] {
  const jobs: ReportJob[] = [];
  for (const workflowFile of ["install-e2e.yml", "pack-smoke.yml"] as const) {
    const kind: WorkflowKind = workflowFile === "install-e2e.yml" ? "install-e2e" : "pack-smoke";
    for (const run of listRuns(workflowFile, sha)) {
      for (const job of listJobs(run.id)) {
        const row = evidenceFromJob(kind, job);
        if (!/^https:\/\//.test(row.htmlUrl)) {
          throw new Error(`refusing to drop ${row.name} or to list it without a run URL`);
        }
        jobs.push(row);
      }
    }
  }
  return jobs;
}

function writeReports(sha: string): void {
  const date = new Date().toISOString().slice(0, 10);
  const { markdown, json, document } = formatPlatformReport({ sha, date, jobs: loadJobs(sha) });
  writeFileSync(join(root, "docs", "PLATFORMS.md"), markdown);
  writeFileSync(join(root, "docs", "platforms.json"), json);
  process.stdout.write(
    `platforms:report: ${document.rows.length} row(s) for ${sha} -> docs/PLATFORMS.md docs/platforms.json\n`,
  );
}

const invoked = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const sha = process.argv[2] ?? "";
  if (!/^[0-9a-f]{40}$/i.test(sha)) {
    process.stderr.write("platforms:report: pass the full 40-character commit SHA\n");
    process.exit(1);
  }
  try {
    writeReports(sha);
  } catch (err) {
    process.stderr.write(`platforms:report: ${err instanceof Error ? err.message : "failed"}\n`);
    process.exit(1);
  }
}
