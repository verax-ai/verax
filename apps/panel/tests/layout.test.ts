import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const viteJs = join(root, "..", "..", "node_modules", "vite", "bin", "vite.js");
const shotDir = join(homedir(), "Desktop", "Work", "VERAX_GOZLEMEVI_20260906");

// 1360x880 is the window `verax desktop` opens. A gate that never runs the
// product's own size measured everything except what the operator sees.
const VIEWS = [
  { name: "1360", width: 1360, height: 880 },
  { name: "1440", width: 1440, height: 900 },
  { name: "1920", width: 1920, height: 1080 },
  { name: "390", width: 390, height: 844 },
] as const;

const TABS = ["Kayıtlar", "Galaksi", "Genel durum"] as const;
const TAB_FILES = ["records", "galaxy", "status"] as const;

describe("observatory layout", () => {
  it("keeps three tabs, detail and timeline on screen; no overflow; 0 console errors", { timeout: 180_000 }, async () => {
    mkdirSync(shotDir, { recursive: true });
    const child = spawn(process.execPath, [viteJs, "--host", "127.0.0.1", "--port", "4189", "--strictPort"], {
      cwd: root,
      env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const fails: string[] = [];
    try {
      const ready = await new Promise<string>((resolve, reject) => {
        let buf = "";
        const timer = setTimeout(() => reject(new Error(`preview-timeout:${buf.slice(-400)}`)), 90_000);
        const onData = (chunk: Buffer) => {
          buf += String(chunk);
          if (buf.includes("http://127.0.0.1:4189/")) {
            clearTimeout(timer);
            resolve("http://127.0.0.1:4189/?demo=1");
          }
        };
        child.stdout.on("data", onData);
        child.stderr.on("data", onData);
        child.on("exit", (code) => reject(new Error(`preview-exit:${code}:${buf.slice(-400)}`)));
      });
      const { chromium } = await import("playwright");
      const browser = await chromium.launch({ args: ["--use-gl=swiftshader"] });
      try {
        for (const view of VIEWS) {
          const page = await browser.newPage({ viewport: { width: view.width, height: view.height } });
          const pageErrors: string[] = [];
          const consoleErrors: string[] = [];
          page.on("pageerror", (err) => pageErrors.push(String(err)));
          page.on("console", (msg) => {
            if (msg.type() !== "error") return;
            const text = msg.text();
            const url = msg.location().url ?? "";
            if (/\/api\/|\/healthz|reconcile-report/.test(`${text} ${url}`)) return;
            if (/Failed to load resource: the server responded with a status of 500/.test(text)) return;
            consoleErrors.push(`${url} ${text}`.trim());
          });
          await page.goto(ready, { waitUntil: "domcontentloaded" });
          await page.getByRole("tab", { name: "Genel durum" }).waitFor({ state: "visible", timeout: 30_000 });
          await page.locator(".obs-detail").waitFor({ state: "visible", timeout: 30_000 });
          await page.locator(".obs-timeline").waitFor({ state: "visible", timeout: 30_000 });
          const labels = await page.locator("[role=tab]").allTextContents();
          if (JSON.stringify(labels) !== JSON.stringify([...TABS])) {
            fails.push(`${view.name}: tabs ${JSON.stringify(labels)}`);
          }
          const metrics = await page.evaluate(() => {
            const rootEl = document.documentElement;
            const detail = document.querySelector(".obs-detail");
            const time = document.querySelector(".obs-timeline");
            const box = (el: Element | null) => {
              if (!el) return null;
              const r = el.getBoundingClientRect();
              return { top: r.top, bottom: r.bottom, left: r.left, right: r.right };
            };
            return {
              scrollWidth: rootEl.scrollWidth,
              clientWidth: rootEl.clientWidth,
              scrollHeight: rootEl.scrollHeight,
              clientHeight: rootEl.clientHeight,
              detail: box(detail),
              time: box(time),
            };
          });
          if (metrics.scrollWidth > metrics.clientWidth + 1) {
            fails.push(`${view.name}: overflow ${metrics.scrollWidth} > ${metrics.clientWidth}`);
          }
          if (view.width > 800) {
            if (!metrics.detail || metrics.detail.top > view.height) {
              fails.push(`${view.name}: detail not on first screen`);
            }
            // The strip has to be readable, not merely started: a timeline
            // whose top is on screen and whose bottom is not is a strip the
            // operator has to scroll for, which is what "on screen" meant.
            if (!metrics.time || metrics.time.bottom > view.height + 1) {
              fails.push(
                `${view.name}: timeline bottom ${metrics.time?.bottom ?? "none"} past ${view.height}`,
              );
            }
            if (metrics.scrollHeight > metrics.clientHeight + 1) {
              fails.push(
                `${view.name}: page scrolls ${metrics.scrollHeight} > ${metrics.clientHeight}`,
              );
            }
          }
          if (pageErrors.length) fails.push(`${view.name}: pageerror ${pageErrors.join(" | ")}`);
          if (consoleErrors.length) fails.push(`${view.name}: console ${consoleErrors.join(" | ")}`);
          for (let t = 0; t < TABS.length; t += 1) {
            await page.getByRole("tab", { name: TABS[t] }).click();
            await page.waitForTimeout(200);
            await page.screenshot({
              path: join(shotDir, `${view.name}-${TAB_FILES[t]}.png`),
              fullPage: false,
            });
          }
          await page.screenshot({ path: join(shotDir, `${view.name}.png`), fullPage: false });
          await page.close();
        }
      } finally {
        await browser.close();
      }
    } finally {
      child.kill();
    }
    if (fails.length) assert.fail(fails.join("\n"));
  });
});
