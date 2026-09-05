import { strict as assert } from "node:assert";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
// @ts-expect-error measure.mjs is an untyped script
import { stopPreview } from "../apps/panel/perf/measure.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const measure = join(root, "apps", "panel", "perf", "measure.mjs");
const check = join(root, "apps", "panel", "perf", "check-baseline.mjs");

function spawnScript(
  script: string,
  env: NodeJS.ProcessEnv,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (buf: Buffer) => {
      stdout += String(buf);
    });
    child.stderr.on("data", (buf: Buffer) => {
      stderr += String(buf);
    });
    child.on("close", (exit) => resolve({ code: exit ?? 1, stdout, stderr }));
  });
}

describe("panel-perf", () => {
  it("fake frames under 30 fail render-failed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-perf-few-"));
    const last = join(dir, "last.json");
    const result = await spawnScript(measure, {
      VERAX_PERF_FAKE_FRAMES: "10",
      VERAX_PERF_MIN_FRAMES: "30",
      VERAX_PERF_LAST: last,
    });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /render-failed/);
  });

  it("fake frames at 40 write p95 and pass", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-perf-ok-"));
    const last = join(dir, "last.json");
    const result = await spawnScript(measure, {
      VERAX_PERF_FAKE_FRAMES: "40",
      VERAX_PERF_LAST: last,
    });
    assert.equal(result.code, 0);
    const record = JSON.parse(readFileSync(last, "utf8")) as {
      frames?: number;
      p95?: number;
    };
    assert.equal(record.frames, 40);
    assert.equal(typeof record.p95, "number");
  });

  it("check-baseline records and passes when the key is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-perf-none-"));
    const last = join(dir, "last.json");
    const baseline = join(dir, "baseline.json");
    writeFileSync(
      last,
      `${JSON.stringify({ p95: 80, frames: 40, gl: "swiftshader" })}\n`,
      { encoding: "utf8" },
    );
    writeFileSync(baseline, "{}\n", { encoding: "utf8" });
    const result = await spawnScript(check, {
      VERAX_PERF_LAST: last,
      VERAX_PERF_BASELINE: baseline,
      GITHUB_ACTIONS: "",
    });
    assert.equal(result.code, 0);
    assert.match(result.stdout, /no baseline for .*; recorded/);
  });

  it("check-baseline fails when p95 exceeds baseline x 1.3", async () => {
    const dir = mkdtempSync(join(tmpdir(), "verax-perf-over-"));
    const last = join(dir, "last.json");
    const baseline = join(dir, "baseline.json");
    const key = `${process.platform}/swiftshader/local`;
    writeFileSync(
      last,
      `${JSON.stringify({ p95: 20, frames: 40, gl: "swiftshader" })}\n`,
      { encoding: "utf8" },
    );
    writeFileSync(
      baseline,
      `${JSON.stringify({ [key]: { p95: 10, frames: 40, at: "2026-09-05T00:00:00.000Z" } })}\n`,
      { encoding: "utf8" },
    );
    const result = await spawnScript(check, {
      VERAX_PERF_LAST: last,
      VERAX_PERF_BASELINE: baseline,
      GITHUB_ACTIONS: "",
    });
    assert.equal(result.code, 1);
  });

  it("occupied port exits preview-port-busy", async () => {
    const server = createServer((_req, res) => {
      res.statusCode = 500;
      res.end("zombie");
    });
    const port = await new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (typeof addr === "object" && addr) {
          resolve(addr.port);
          return;
        }
        reject(new Error("no-port"));
      });
    });
    try {
      const result = await spawnScript(measure, {
        VERAX_PERF_PORT: String(port),
      });
      assert.equal(result.code, 1);
      assert.match(result.stderr, /preview-port-busy/);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  });

  it("stopPreview leaves the child pid dead", async () => {
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1e9)"], {
      stdio: "ignore",
      windowsHide: true,
    });
    const pid = child.pid;
    if (typeof pid !== "number") {
      assert.fail("no-pid");
    }
    process.kill(pid, 0);
    stopPreview(child);
    const deadline = Date.now() + 2000;
    let dead = false;
    while (Date.now() < deadline) {
      try {
        process.kill(pid, 0);
      } catch (err) {
        assert.equal((err as NodeJS.ErrnoException).code, "ESRCH");
        dead = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(dead, true);
  });
});

describe("preview readiness", () => {
  it("parses the Local: URL even when vite colours it", async () => {
    // @ts-expect-error measure.mjs is an untyped script
    const mod = await import("../apps/panel/perf/measure.mjs");
    const parse = (mod as { parseLocalUrl?: (text: string) => string | null }).parseLocalUrl;
    assert.equal(typeof parse, "function", "parseLocalUrl export missing");
    const esc = String.fromCharCode(27);
    const coloured = `  ${esc}[32m>${esc}[39m  ${esc}[1mLocal${esc}[22m:   ${esc}[36mhttp://127.0.0.1:${esc}[1m4199${esc}[22m/${esc}[39m\n`;
    assert.equal(parse!(coloured), "http://127.0.0.1:4199/");
    assert.equal(parse!("  Local:   http://127.0.0.1:4173/\n"), "http://127.0.0.1:4173/");
    assert.equal(parse!("starting...\n"), null);
  });
});
