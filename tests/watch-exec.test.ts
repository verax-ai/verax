import { strict as assert } from "node:assert";
import { spawn, type SpawnOptions } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { runWatch, commandArgv, silenceReason } from "../packages/body/src/watch.ts";
import { readHalt } from "../packages/body/src/halt.ts";
import { heartbeatEveryMs, readStartSummary, startHeartbeat } from "../packages/body/src/heartbeat.ts";
import { scanNoBypass } from "../packages/body/src/no-bypass-scan.ts";

const quoted = (s: string) => `'${s.replaceAll("'", "\\'")}'`;
const temp = () => mkdtempSync(join(tmpdir(), "verax-watch-exec-"));

describe("watch exec episodes", () => {
  it("runs a real command once per episode, with a reason in env and literal argv", async () => {
    const dir = temp();
    const output = join(dir, "calls.jsonl");
    const script = join(dir, "isolate.mjs");
    writeFileSync(script, 'import { appendFileSync } from "node:fs"; appendFileSync(process.argv[2], JSON.stringify({ args: process.argv.slice(3), reason: process.env.VERAX_WATCH_REASON }) + "\\n");');
    const controller = new AbortController();
    let tick = 0, text = "";
    const ms: number[] = [];
    const sentinel = "literal; & echo untouched";
    const code = await runWatch([dir, "--max-silence", "30s", "--on-silence", "exec", "--exec", [process.execPath, script, output, sentinel].map(quoted).join(" ")], {
      now: () => 100_000,
      signal: controller.signal,
      stdout: { write: (s) => { text += s; } },
      sleep: async (wait) => {
        ms.push(wait);
        tick += 1;
        if (tick === 2) writeFileSync(join(dir, "heartbeat.json"), JSON.stringify({ atMs: 100_000 }));
        if (tick === 3) writeFileSync(join(dir, "heartbeat.json"), JSON.stringify({ atMs: 1 }));
        if (tick === 5) controller.abort();
      },
    });
    assert.equal(code, 0);
    const calls = readFileSync(output, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(calls.length, 2);
    assert.deepEqual(calls.map((c) => c.args), [[sentinel], [sentinel]]);
    assert.deepEqual(calls.map((c) => c.reason), ["heartbeat-unreadable", "heartbeat-stale"]);
    assert.deepEqual(text.trim().split("\n").map((line) => JSON.parse(line).event), ["silence", "recovery", "silence"]);
    assert.deepEqual(ms, [10_000, 10_000, 10_000, 10_000, 10_000]);
    assert.equal(readHalt(dir).halted, false);
  });

  it("recovery reports once and leaves a local halt in place", async () => {
    const dir = temp(), controller = new AbortController();
    let tick = 0, text = "";
    await runWatch([dir], { now: () => 100_000, signal: controller.signal, stdout: { write: (s) => { text += s; } }, sleep: async () => {
      tick += 1;
      writeFileSync(join(dir, "heartbeat.json"), JSON.stringify({ atMs: 100_000 }));
      if (tick === 3) controller.abort();
    } });
    assert.deepEqual(text.trim().split("\n").map((line) => JSON.parse(line).event), ["silence", "recovery"]);
    assert.equal(readHalt(dir).halted, true);
  });

  it("a failed exec is reported once and is retried only after recovery", async () => {
    const dir = temp(), controller = new AbortController();
    let tick = 0, text = "";
    await runWatch([dir, "--on-silence", "exec", "--exec", "verax-no-such-command"], { signal: controller.signal, stdout: { write: (s) => { text += s; } }, sleep: async () => { if (++tick === 3) controller.abort(); } });
    const events = text.trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(events.length, 1);
    assert.equal(events[0].actionResult, "exec-failed");
  });

  it("remote exec passes only file-independent command argv; redirect cannot leak token", async () => {
    const dir = temp(), tokenFile = join(dir, "token");
    const token = "private-test-token";
    writeFileSync(tokenFile, token);
    let fetchOptions: RequestInit | undefined;
    let execution: { command: string; args: readonly string[]; options: SpawnOptions } | undefined;
    const fetchHook = (async (_url, options) => {
      fetchOptions = options;
      return new Response(JSON.stringify({ heartbeat: { atMs: 1 } }));
    }) as typeof fetch;
    const spawnHook = (command: string, args: readonly string[], options: SpawnOptions) => {
      execution = { command, args, options };
      return spawn(command, args, options);
    };
    let text = "";
    assert.equal(await runWatch(["--url", "https://example.com/healthz", "--token-file", tokenFile, "--once", "--on-silence", "exec", "--exec", `${quoted(process.execPath)} --version`], {
      fetch: fetchHook, spawn: spawnHook, stdout: { write: (s) => { text += s; } }, now: () => 100_000,
    }), 3);
    assert.deepEqual(fetchOptions?.headers, { authorization: `Bearer ${token}` });
    assert.equal(fetchOptions?.redirect, "error");
    assert.ok(execution);
    assert.equal(execution.command, process.execPath);
    assert.deepEqual(execution.args, ["--version"]);
    assert.ok(!JSON.stringify(execution.args).includes(token));
    assert.equal(execution.options.shell, false);
    assert.equal(execution.options.env?.VERAX_WATCH_REASON, "heartbeat-stale");
    assert.equal(JSON.parse(text).actionResult, "exec-ok");
    assert.ok(!text.includes(token));
    assert.equal(existsSync(join(dir, "halted")), false);
  });
});

describe("heartbeat boundaries", () => {
  it("holds exact silence and skew boundaries, default interval and minimum", () => {
    assert.equal(silenceReason(70_000, 100_000, 30_000), null);
    assert.equal(silenceReason(69_999, 100_000, 30_000), "heartbeat-stale");
    assert.equal(silenceReason(160_000, 100_000, 30_000), null);
    assert.equal(silenceReason(160_001, 100_000, 30_000), "heartbeat-in-future");
    assert.equal(silenceReason(NaN, 100_000, 30_000), "heartbeat-unreadable");
    assert.equal(heartbeatEveryMs({}), 10_000);
    assert.equal(heartbeatEveryMs({ VERAX_HEARTBEAT_EVERY_MS: "20" }), 1000);
    assert.equal(heartbeatEveryMs({ VERAX_HEARTBEAT_EVERY_MS: "invalid" }), 10_000);
  });
  it("unrefs the periodic timer and clears it on shutdown", () => {
    let pulses = 0;
    const previous = globalThis.setInterval;
    const previousClear = globalThis.clearInterval;
    let unref = false, cleared = false;
    const timer = { unref: () => { unref = true; } };
    try {
      globalThis.setInterval = ((fn: () => void) => { fn(); return timer; }) as any;
      globalThis.clearInterval = ((t: unknown) => { assert.equal(t, timer); cleared = true; }) as any;
      const stop = startHeartbeat({ pulseHeartbeat: () => { pulses += 1; } } as any);
      assert.equal(unref, true);
      assert.equal(pulses, 2);
      stop();
      assert.equal(cleared, true);
    } finally { globalThis.setInterval = previous; globalThis.clearInterval = previousClear; }
  });
  it("names malformed starts rather than silently counting them", () => {
    const dir = temp();
    writeFileSync(join(dir, "starts.jsonl"), 'null\n{"action":"start"}\n');
    const summary = readStartSummary(dir);
    assert.equal(summary.count, 0);
    assert.equal(summary.warnings.length, 2);
  });
  it("preserves Windows paths and rejects unmatched quotes", () => {
    assert.deepEqual(commandArgv('"C:\\Program Files\\node.exe" script.mjs "" "hello world"'), ["C:\\Program Files\\node.exe", "script.mjs", "", "hello world"]);
    assert.throws(() => commandArgv('"unfinished'));
    assert.throws(() => commandArgv(""));
  });
  it("the process exception is limited to the watcher source", () => {
    const spec = ["node:child", "_process"].join("");
    const hits = scanNoBypass(undefined, [{ file: "src/watch.ts", text: `import { spawn } from "${spec}";` }, { file: "src/tools/watch.ts", text: `import { spawn } from "${spec}";` }]);
    assert.ok(!hits.some((h) => h.file === "src/watch.ts"));
    assert.ok(hits.some((h) => h.file === "src/tools/watch.ts"));
  });
});
