#!/usr/bin/env node
// Relative frame-time probe. Software GL; the number is not an absolute fps claim.

import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const workspace = join(root, "..", "..");
const outPath = join(root, "perf", "last.json");
const tier = Number(process.env.VERAX_PERF_TIER ?? "15000");
const framesWanted = 300;

function startPreview() {
  const child = spawn("npm", ["run", "preview", "--", "--host", "127.0.0.1", "--port", "4173"], {
    cwd: root,
    shell: true,
    stdio: "pipe",
  });
  return child;
}

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
const samples = await page.evaluate(async (n) => {
  const got = [];
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`frames-timeout:${got.length}`)), 20_000);
    const push = (ms) => {
      got.push(ms);
      if (got.length >= n) {
        clearTimeout(timer);
        resolve(undefined);
      }
    };
    const prev = window.__veraxPushFrame;
    window.__veraxPushFrame = (ms) => {
      prev?.(ms);
      push(ms);
    };
  });
  return got;
}, framesWanted);

const sorted = [...samples].sort((a, b) => a - b);
const p95 = sorted[Math.min(sorted.length - 1, Math.ceil(0.95 * sorted.length) - 1)] ?? 0;
const record = {
  tier,
  frames: samples.length,
  p95,
  gl: "swiftshader",
  at: new Date().toISOString(),
};
writeFileSync(outPath, `${JSON.stringify(record, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(record)}\n`);
await browser.close();
preview.kill();
process.exit(0);
