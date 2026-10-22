// npm's own CLI, run with this Node. No shell: arguments stay a list,
// so Node 24 does not emit DEP0190 ("arguments are not escaped, only concatenated").
//
// npmCli is process.env.npm_execpath when an npm script launched us, else
// the copy next to this Node — not a workspace node_modules/npm. Windows
// and POSIX use the same join. Missing both is a hard error.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

export type NpmRunResult = { status: number; out: string; stdout: string };

function nextToNode(cli: string): string {
  return join(dirname(process.execPath), "node_modules", "npm", "bin", cli);
}

export function npmCliPath(): string {
  const fromEnv = process.env.npm_execpath;
  if (fromEnv) {
    if (!existsSync(fromEnv)) {
      throw new Error(`npm_execpath is ${fromEnv} but that file does not exist`);
    }
    return fromEnv;
  }
  const nextToThisNode = nextToNode("npm-cli.js");
  if (existsSync(nextToThisNode)) return nextToThisNode;
  throw new Error(
    `cannot find npm-cli.js: npm_execpath is unset and ${nextToThisNode} is not next to this Node`,
  );
}

function runCli(cli: string, args: string[], cwd: string): NpmRunResult {
  const r = spawnSync(process.execPath, [cli, ...args], { cwd, encoding: "utf8", shell: false });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}`, stdout: r.stdout ?? "" };
}

export function runNpm(args: string[], cwd: string): NpmRunResult {
  return runCli(npmCliPath(), args, cwd);
}

export function runNpx(args: string[], cwd: string): NpmRunResult {
  const npxCli = join(dirname(npmCliPath()), "npx-cli.js");
  if (!existsSync(npxCli)) {
    throw new Error(`cannot find npx-cli.js next to npm-cli.js: ${npxCli}`);
  }
  return runCli(npxCli, args, cwd);
}
