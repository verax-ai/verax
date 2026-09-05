#!/usr/bin/env node
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const url = process.argv[2];
if (!url) {
  process.stderr.write("og: pass the page URL\n");
  process.exit(2);
}
const out = process.argv[3] ?? join(root, "apps", "body-map", "dist", "og.png");
mkdirSync(dirname(out), { recursive: true });
const { chromium } = await import("playwright");
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await page.goto(url, { waitUntil: "networkidle" });
await page.waitForTimeout(4500);
await page.screenshot({ path: out, type: "png" });
await browser.close();
process.stdout.write(`${out}\n`);
