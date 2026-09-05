#!/usr/bin/env node
// Relative frame-time probe. Software GL; the number is not an absolute fps claim.

import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outPath = process.env.VERAX_PERF_LAST ?? join(root, "perf", "last.json");
const tier = Number(process.env.VERAX_PERF_TIER ?? "15000");
const framesWanted = 300;
const budgetMs = 20_000;
const minFrames = 30;
const gl = "swiftshader";

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
    process.exit(1);
  }
  process.stdout.write(`${JSON.stringify(record)}\n`);
  process.exit(0);
}

const fakeRaw = process.env.VERAX_PERF_FAKE_FRAMES;
if (fakeRaw !== undefined && fakeRaw !== "") {
  const n = Number(fakeRaw);
  const count = Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  finish(Array.from({ length: count }, () => 16.7));
}

function startPreview() {
  const child = spawn("npm", ["run", "preview", "--", "--host", "127.0.0.1", "--port", "4173"], {
    cwd: root,
    shell: true,
    stdio: "pipe",
  });
  return child;
}

const { chromium } = await import("playwright");

const preview = startPreview();
await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("preview-timeout")), 30_000);
  const onData = (buf) => {
    const text = String(buf);
    if (text.includes("4173") || text.includes("Local:")) {
      clearTimeout(timer);
      resolve(undefined);
    }
  };
  preview.stdout.on("data", onData);
  preview.stderr.on("data", onData);
  preview.on("exit", (code) => reject(new Error(`preview-exit:${code}`)));
});

const browser = await chromium.launch({
  args: ["--use-gl=swiftshader", "--use-angle=swiftshader"],
});
const page = await browser.newPage();
await page.goto(`http://127.0.0.1:4173/?tier=${tier}`, { waitUntil: "networkidle" });
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

await browser.close();
preview.kill();
finish(samples);
