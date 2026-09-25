// A real body under concurrent load is SIGKILLed mid-burst, unlocked,
// restarted, and the ledger is checked. The suite builds dist before the
// unit tests, the same way tests that import packages/proxy/dist do.

import { strict as assert } from "node:assert";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "dist", "cli.js");

type Running = { child: ChildProcess; port: number };

function envFrom(stateDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("VERAX_")) delete env[key];
  }
  for (const line of readFileSync(join(stateDir, "verax.env"), "utf8").split(/\r?\n/)) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (m) env[m[1]] = m[2];
  }
  env.VERAX_BIND = "127.0.0.1:0";
  return env;
}

function serve(env: NodeJS.ProcessEnv): Promise<Running> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, "serve"], { env, stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(new Error(`no listen: ${err.slice(0, 400)}`));
    }, 10_000);
    const onExit = (code: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`exit ${code}: ${err.slice(0, 400)}`));
    };
    child.once("exit", onExit);
    child.stderr?.on("data", (chunk: Buffer | string) => {
      err += String(chunk);
      const m = /listening [^\s:]+:(\d+)/.exec(err);
      if (!m || settled) return;
      settled = true;
      clearTimeout(timer);
      child.off("exit", onExit);
      resolve({ child, port: Number(m[1]) });
    });
  });
}

function exitOf(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("exit", () => resolve());
  });
}

/** HTTP status and whether the tool itself succeeded: a 200 whose result is an error is not a write. */
async function call(port: number, token: string, ref: string, id: string): Promise<{ status: number | "net"; toolOk: boolean }> {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: ref,
        method: "tools/call",
        params: {
          name: "memory.put",
          arguments: {
            id,
            body: { n: id },
            source: { kind: "crash" },
            validUntilMs: Date.now() + 60 * 60 * 1000,
            _ref: ref,
          },
        },
      }),
    });
    const text = await res.text();
    const json = text.trimStart().startsWith("{") ? text : (/^data: (.*)$/m.exec(text)?.[1] ?? "");
    let toolOk = false;
    try {
      const parsed = JSON.parse(json) as { result?: { isError?: boolean } };
      toolOk = parsed.result !== undefined && parsed.result.isError !== true;
    } catch {
      toolOk = false;
    }
    return { status: res.status, toolOk };
  } catch {
    return { status: "net", toolOk: false };
  }
}

function jsonl(path: string): { rows: Array<{ claims?: { ref?: string }; row?: { ref?: string } }>; torn: number } {
  if (!existsSync(path)) return { rows: [], torn: 0 };
  let torn = 0;
  const rows: Array<{ claims?: { ref?: string }; row?: { ref?: string } }> = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line.trim() === "") continue;
    try {
      rows.push(JSON.parse(line) as { claims?: { ref?: string }; row?: { ref?: string } });
    } catch {
      torn += 1;
    }
  }
  return { rows, torn };
}

function holdsRef(refs: Set<string>, raw: string): boolean {
  if (refs.has(raw)) return true;
  for (const ref of refs) {
    if (ref.endsWith(`:${raw}`)) return true;
  }
  return false;
}

describe("crash durability", () => {
  it("keeps the ledger after SIGKILL at two points in a burst", { timeout: 90_000 }, async () => {
    assert.equal(existsSync(cli), true, "packages/body/dist/cli.js is missing; the suite builds dist first");
    for (const killAt of [10, 80]) {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-crash-"));
      let body: Running | undefined;
      try {
        const init = spawnSync(process.execPath, [cli, "init", "--local", stateDir], { encoding: "utf8" });
        assert.equal(init.status, 0, init.stderr);
        const env = envFrom(stateDir);
        const token = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
        body = await serve(env);
        let done = 0;
        const refs = Array.from({ length: 150 }, (_, i) => `a-${killAt}-${i}`);
        const burst = refs.map((ref, i) =>
          call(body!.port, token, ref, `n-${killAt}-${i}`).then((answer) => {
            done += 1;
            return { ref, ...answer };
          }),
        );
        const deadline = Date.now() + 12_000;
        while (done < killAt && Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
        assert.ok(done >= killAt, `only ${done} responses before kill at ${killAt}`);
        const dead = exitOf(body.child);
        body.child.kill("SIGKILL");
        await dead;
        body = undefined;
        const statuses = await Promise.all(burst);

        const unlock = spawnSync(process.execPath, [cli, "unlock", stateDir], { encoding: "utf8", env });
        assert.equal(unlock.status, 0, `${unlock.stdout} ${unlock.stderr}`);

        body = await serve(env);
        const afterRefs = Array.from({ length: 20 }, (_, i) => `b-${killAt}-${i}`);
        const after = await Promise.all(afterRefs.map((ref, i) => call(body!.port, token, ref, `m-${killAt}-${i}`)));
        const stopped = exitOf(body.child);
        body.child.kill("SIGTERM");
        await stopped;
        body = undefined;

        let torn = 0;
        const decisionRefs = new Set<string>();
        const effectRefs: string[] = [];
        for (const name of readdirSync(stateDir)) {
          if (!name.endsWith(".jsonl")) continue;
          const parsed = jsonl(join(stateDir, name));
          torn += parsed.torn;
          if (name === "decisions.jsonl") {
            for (const row of parsed.rows) {
              if (typeof row.claims?.ref === "string") decisionRefs.add(row.claims.ref);
            }
          }
          if (name === "effects.jsonl") {
            for (const row of parsed.rows) {
              if (typeof row.row?.ref === "string") effectRefs.push(row.row.ref);
            }
          }
        }
        assert.equal(torn, 0, `torn JSONL lines after kill at ${killAt}`);
        const orphans = effectRefs.filter((ref) => !decisionRefs.has(ref));
        assert.deepEqual(orphans, [], `effects without a decision after kill at ${killAt}`);
        const answered = statuses.filter((item) => item.status === 200).map((item) => item.ref);
        const missing = answered.filter((ref) => !holdsRef(decisionRefs, ref));
        assert.deepEqual(missing, [], `200 responses with no decision after kill at ${killAt}`);
        assert.deepEqual(
          after.filter((answer) => answer.status !== 200 || !answer.toolOk),
          [],
          `after-restart calls that did not write after kill at ${killAt}`,
        );
        const failedWrites = statuses.filter((item) => item.status === 200 && !item.toolOk).map((item) => item.ref);
        assert.deepEqual(failedWrites, [], `200 answers whose memory.put failed before kill at ${killAt}`);

        const verified = spawnSync(process.execPath, [cli, "verify", stateDir, "--json"], { encoding: "utf8" });
        const verdict = JSON.parse(verified.stdout) as { ok?: boolean };
        assert.equal(verified.status, 0, verified.stderr);
        assert.equal(verdict.ok, true, verified.stdout);
      } finally {
        if (body) {
          const stopped = exitOf(body.child);
          body.child.kill("SIGKILL");
          await stopped;
        }
        rmSync(stateDir, { recursive: true, force: true });
      }
    }
  });
});
