/**
 * Runs every vector in `manifest.json` through `verax verify` with the
 * vector's pinned keys and compares the verdict and the first failing stage
 * with `expected.json`. Exits 1 on any mismatch, including a negative that
 * verifies.
 *
 *   node --experimental-strip-types test-vectors/tools/run.ts [--bin <cli.js>] [--json]
 *
 * `--bin` runs another build of the CLI, for example the published one at
 * node_modules/@verax-ai/body/dist/cli.js. The default is this checkout.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { firstStage } from "./stages.ts";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsRoot = join(here, "..");
const repoRoot = join(vectorsRoot, "..");

type ManifestEntry = { id: string; dir: string; expected_result: "VALID" | "INVALID"; first_failing_stage: string | null };

/** One `verax verify` call: the arguments after `verify`, and what it printed and returned. */
export type Verify = (args: string[]) => Promise<{ status: number | null; stdout: string; stderr: string }>;

export type Outcome = {
  id: string;
  expected: string;
  got: string;
  expectedStage: string | null;
  gotStages: readonly string[] | null;
  firstLine: string | null;
  problems: string[];
  match: boolean;
};

/** A build of the CLI run as a child process, the way someone outside this repository runs it. */
export function spawnVerify(bin: string): Verify {
  return async (args) => {
    const flags = bin.endsWith(".ts") ? ["--experimental-strip-types", "--no-warnings"] : ["--no-warnings"];
    const run = spawnSync(process.execPath, [...flags, bin, "verify", ...args], { encoding: "utf8", windowsHide: true });
    return { status: run.status, stdout: run.stdout, stderr: run.stderr };
  };
}

export async function runVectors(verify: Verify): Promise<Outcome[]> {
  const manifest = JSON.parse(readFileSync(join(vectorsRoot, "manifest.json"), "utf8")) as { vectors: ManifestEntry[] };
  const outcomes: Outcome[] = [];
  for (const v of manifest.vectors) {
    const dir = join(vectorsRoot, v.dir);
    const pins = join(dir, "pins");
    const run = await verify([
      join(dir, "ledger"),
      "--key",
      join(pins, "record-key.pem"),
      "--witness-key",
      join(pins, "witness-key.pem"),
      "--checkpoint-key",
      join(pins, "witness-key.pem"),
      "--operator-credentials",
      join(pins, "operator-credentials.json"),
      "--json",
    ]);
    let report: { ok?: boolean; problems?: string[] } = {};
    try {
      report = JSON.parse(run.stdout) as typeof report;
    } catch {
      report = { ok: false, problems: [`verifier output was not JSON (exit ${run.status}): ${run.stderr.trim()}`] };
    }
    const problems = report.problems ?? [];
    const got = report.ok === true && run.status === 0 ? "VALID" : "INVALID";
    const first = firstStage(problems);
    const stageOk =
      v.first_failing_stage === null ? first === null : first !== null && first.stages.includes(v.first_failing_stage as never);
    outcomes.push({
      id: v.id,
      expected: v.expected_result,
      got,
      expectedStage: v.first_failing_stage,
      gotStages: first?.stages ?? null,
      firstLine: first?.line ?? null,
      problems,
      match: got === v.expected_result && stageOk,
    });
  }
  return outcomes;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const at = process.argv.indexOf("--bin");
  const bin = at >= 0 && at + 1 < process.argv.length ? process.argv[at + 1]! : join(repoRoot, "packages", "body", "src", "cli.ts");
  const outcomes = await runVectors(spawnVerify(bin));
  const failed = outcomes.filter((o) => !o.match);
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ verifier: bin, vectors: outcomes.length, mismatches: failed.length, outcomes }, null, 2));
  } else {
    for (const o of outcomes) {
      const stage = o.expectedStage === null ? "-" : `${o.expectedStage} <- ${o.firstLine ?? "(no mapped problem line)"}`;
      console.log(`${o.match ? "ok  " : "FAIL"} ${o.id.padEnd(34)} ${o.got.padEnd(8)} ${stage}`);
      if (!o.match) for (const p of o.problems) console.log(`       ${p}`);
    }
    console.log(`${outcomes.length - failed.length}/${outcomes.length} as expected`);
  }
  process.exit(failed.length === 0 ? 0 : 1);
}
