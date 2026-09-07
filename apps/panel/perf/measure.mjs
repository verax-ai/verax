#!/usr/bin/env node
// Relative frame-time probe. Software GL; the number is not an absolute fps claim.

import { spawn, spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outPath = process.env.VERAX_PERF_LAST ?? join(root, "perf", "last.json");
const tier = Number(process.env.VERAX_PERF_TIER ?? "15000");
const gha = Boolean(process.env.GITHUB_ACTIONS);
const headed = Boolean(process.env.VERAX_PERF_HEADED);
const framesWanted = 300;
const budgetMs = Number(process.env.VERAX_PERF_BUDGET_MS ?? (gha ? 40_000 : 20_000));
const minFrames = Number(process.env.VERAX_PERF_MIN_FRAMES ?? (gha ? 10 : 30));
const gl = headed ? "gpu" : "swiftshader";
const viteJs = join(root, "..", "..", "node_modules", "vite", "bin", "vite.js");

/** `--url` probes an already-running page; default is the panel preview. */
export function readUrlArg(argv = process.argv) {
  const i = argv.indexOf("--url");
  if (i === -1) return null;
  const value = argv[i + 1];
  if (!value || value.startsWith("-")) throw new Error("url-missing");
  return value;
}

export function withTier(url, n) {
  const u = new URL(url);
  u.searchParams.set("tier", String(n));
  u.searchParams.set("tab", "anatomy");
  // This harness measures frames, not the session: without `demo` the panel starts
  // the code flow and navigates away from the page being measured.
  u.searchParams.set("demo", "1");
  if (process.env.VERAX_PERF_BLOOM === "1") {
    u.searchParams.set("bloom", "1");
  }
  return u.href;
}

function envKey() {
  const envTag = process.env.GITHUB_ACTIONS
    ? `gha-${process.env.RUNNER_OS ?? "unknown"}`
    : "local";
  return `${process.platform}/${gl}/${envTag}`;
}

function p95Of(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(0.95 * sorted.length) - 1)] ?? 0;
}

function finish(samples) {
  const record = {
    key: envKey(),
    platform: process.platform,
    tier,
    frames: samples.length,
    p95: p95Of(samples),
    gl,
    at: new Date().toISOString(),
  };
  writeFileSync(outPath, `${JSON.stringify(record, null, 2)}\n`);
  if (samples.length < minFrames) {
    process.stderr.write(`render-failed:${samples.length}\n`);
    process.exitCode = 1;
    return record;
  }
  process.stdout.write(`${JSON.stringify(record)}\n`);
  process.exitCode = 0;
  return record;
}

export function probePort(port) {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", (err) => {
      if (err && err.code === "EADDRINUSE") {
        reject(new Error("preview-port-busy"));
        return;
      }
      reject(err);
    });
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const bound = typeof addr === "object" && addr ? addr.port : port;
      server.close((closeErr) => {
        if (closeErr) {
          reject(closeErr);
          return;
        }
        resolve(bound);
      });
    });
  });
}

export async function resolvePort() {
  const raw = process.env.VERAX_PERF_PORT;
  if (raw !== undefined && raw !== "") {
    const port = Number(raw);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new Error("preview-port-busy");
    }
    await probePort(port);
    return port;
  }
  return probePort(0);
}

export function startPreview(port) {
  return spawn(
    process.execPath,
    [viteJs, "preview", "--host", "127.0.0.1", "--port", String(port), "--strictPort"],
    {
      cwd: root,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      // vite colours its banner on win32 and under CI regardless of a tty;
      // the readiness parser strips escapes too, this just keeps logs plain.
      env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" },
    },
  );
}

const ANSI = /\u001b\[[0-9;]*[A-Za-z]/g;

/** The Local: URL from vite's banner, with terminal colour codes removed. */
export function parseLocalUrl(text) {
  const plain = String(text).replace(ANSI, "");
  const match = plain.match(/Local:\s+(http:\/\/127\.0\.0\.1:\d+\/)/);
  return match ? match[1] : null;
}

export function waitReady(child) {
  return new Promise((resolve, reject) => {
    let buf = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("preview-timeout"));
    }, 30_000);
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    };
    const onData = (chunk) => {
      if (settled) return;
      buf += String(chunk);
      if (/Port .+ is already in use/i.test(buf)) {
        fail(new Error("preview-port-busy"));
        return;
      }
      const url = parseLocalUrl(buf);
      if (url) {
        settled = true;
        clearTimeout(timer);
        resolve(url);
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("error", fail);
    child.on("exit", (code) => {
      if (settled) return;
      fail(new Error(`preview-exit:${code}`));
    });
  });
}

export function stopPreview(child) {
  if (!child || child.pid == null) return;
  const pid = child.pid;
  try {
    child.kill();
  } catch {
    // already gone
  }
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
      windowsHide: true,
      stdio: "ignore",
    });
    return;
  }
  try {
    child.kill("SIGTERM");
  } catch {
    // already gone
  }
}

async function closeBrowser(browser) {
  if (!browser) return;
  try {
    await browser.close();
  } catch {
    // already closed
  }
}

export async function runMeasure(hooks = {}) {
  const start = hooks.startPreview ?? startPreview;
  let browser;
  let child;
  try {
    const given = readUrlArg(process.argv);
    let url;
    if (given) {
      url = given;
    } else {
      const port = await resolvePort();
      child = start(port);
      process.stderr.write(`preview-pid:${child.pid}\n`);
      if (hooks.afterPreview) await hooks.afterPreview(child);
      url = await waitReady(child);
    }
    const { chromium } = await import("playwright");
    browser = await chromium.launch({
      headless: !headed,
      args: headed ? [] : ["--use-gl=swiftshader", "--use-angle=swiftshader"],
    });
    const page = await browser.newPage();
    await page.goto(withTier(url, tier), { waitUntil: "networkidle" });
    await page.waitForTimeout(4500);
    const samples = await page.evaluate(
      async ({ n, ms }) => {
        const got = [];
        await new Promise((resolve) => {
          const timer = setTimeout(() => resolve(undefined), ms);
          const push = (frameMs) => {
            got.push(frameMs);
            if (got.length >= n) {
              clearTimeout(timer);
              resolve(undefined);
            }
          };
          const prev = window.__veraxPushFrame;
          window.__veraxPushFrame = (frameMs) => {
            prev?.(frameMs);
            push(frameMs);
          };
        });
        return got;
      },
      { n: framesWanted, ms: budgetMs },
    );
    finish(samples);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  } finally {
    await closeBrowser(browser);
    stopPreview(child);
  }
}

async function main() {
  const fakeRaw = process.env.VERAX_PERF_FAKE_FRAMES;
  if (fakeRaw !== undefined && fakeRaw !== "") {
    const n = Number(fakeRaw);
    const count = Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
    finish(Array.from({ length: count }, () => 16.7));
    process.exit(process.exitCode ?? 0);
  }

  await runMeasure();
  process.exit(process.exitCode ?? 0);
}

const invoked =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  await main();
}
