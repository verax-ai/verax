import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
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

// The panel opens in English, so the gate opens it that way. A gate that
// asked for another language would be measuring a screen no one gets by
// default -- the same fault as measuring a window size the product never
// opens at.
const TABS = ["Records", "Galaxy", "Status"] as const;

/**
 * Turkish strings that are not also the English ones. A Turkish word made
 * only of letters English shares -- kilit, karar, etki -- is invisible to a
 * character check, so the gate compares against the table itself. Anything
 * shorter than four characters is dropped: a two-letter value collides with
 * ordinary English text and would report a leftover that is not there.
 */
const copyDir = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "copy");
const enCopy = JSON.parse(readFileSync(join(copyDir, "en.json"), "utf8")) as Record<string, string>;
const trCopy = JSON.parse(readFileSync(join(copyDir, "tr.json"), "utf8")) as Record<string, string>;
const TURKISH_ONLY = Object.keys(trCopy)
  .filter((k) => trCopy[k] !== enCopy[k])
  .map((k) => trCopy[k] as string)
  .filter((v) => v.length >= 4 && !v.includes("{"));

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
          await page.getByRole("tab", { name: TABS[2] }).waitFor({ state: "visible", timeout: 30_000 });
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
            // Every question the pane asks has to be inside the pane the
            // operator sees. A question found only by scrolling is a question
            // the reader does not know was asked, and the one with no answer
            // yet is on the page precisely to be seen.
            const paneBox = detail?.getBoundingClientRect() ?? null;
            const questions = [...document.querySelectorAll(".detail-pane h3")].map((h) => ({
              text: (h.textContent ?? "").slice(0, 40),
              top: h.getBoundingClientRect().top,
              bottom: h.getBoundingClientRect().bottom,
            }));
            return {
              scrollWidth: rootEl.scrollWidth,
              clientWidth: rootEl.clientWidth,
              scrollHeight: rootEl.scrollHeight,
              clientHeight: rootEl.clientHeight,
              detail: box(detail),
              time: box(time),
              paneBottom: paneBox ? paneBox.bottom : null,
              questions,
              // The strip is measured the way the galaxy crowd rule is: by the
              // boxes, not by the dots. Two stamps that print on top of each
              // other, or a stamp clipped by the track, hide a record on a
              // screen whose whole claim is that it hides nothing.
              timeline: (() => {
                const track = document.querySelector(".timeline-track");
                if (!track) return null;
                const t = track.getBoundingClientRect();
                const marks = [...track.querySelectorAll(".timeline-mark")]
                  .map((m) => {
                    const r = m.getBoundingClientRect();
                    return { text: (m.textContent ?? "").trim().slice(0, 24), left: r.left, right: r.right };
                  })
                  .sort((a, b) => a.left - b.left);
                let overlaps = 0;
                for (let i = 1; i < marks.length; i += 1) {
                  if (marks[i].left < marks[i - 1].right - 0.5) overlaps += 1;
                }
                const clipped = marks.filter((m) => m.left < t.left - 0.5 || m.right > t.right + 0.5).length;
                return { count: marks.length, overlaps, clipped };
              })(),
              spendText: document.querySelector("[data-testid=spend-fields]")?.textContent ?? null,
              pairText: document.querySelector("[data-testid=explain-pair]")?.textContent ?? null,
              detailScroll: detail?.scrollHeight ?? null,
              detailClient: detail?.clientHeight ?? null,
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
            if (metrics.timeline === null) {
              fails.push(`${view.name}: no timeline track`);
            } else {
              if (metrics.timeline.overlaps > 0) {
                fails.push(
                  `${view.name}: ${metrics.timeline.overlaps} timeline stamps print on top of another (of ${metrics.timeline.count})`,
                );
              }
              if (metrics.timeline.clipped > 0) {
                fails.push(
                  `${view.name}: ${metrics.timeline.clipped} timeline stamps hang outside the track`,
                );
              }
            }
            if (metrics.questions.length === 0) {
              fails.push(`${view.name}: the detail pane asks nothing`);
            }
            for (const q of metrics.questions) {
              if (metrics.paneBottom !== null && q.bottom > metrics.paneBottom + 1) {
                fails.push(
                  `${view.name}: "${q.text}" sits below the pane (${Math.round(q.bottom)} > ${Math.round(metrics.paneBottom)})`,
                );
              }
            }
            // 1360x880 is the product window. Presence alone is not the load:
            // a spend subject still renders the section when approvals are
            // empty, with "not measured" in every field. The gate has to see
            // the amount and the payee or it is measuring the thin pane again.
            // A question inside the pane but below its fold is still a
            // question the reader has to go looking for. The pane is only
            // honest about asking five things if all five fit in it at the
            // size the product opens at.
            if (
              metrics.detailScroll !== null &&
              metrics.detailClient !== null &&
              metrics.detailScroll > metrics.detailClient + 1
            ) {
              fails.push(
                `${view.name}: detail pane scrolls inside itself (${metrics.detailScroll} > ${metrics.detailClient})`,
              );
            }
            if (view.name === "1360") {
              process.stdout.write(
                `layout-f9: .obs-detail scrollHeight=${metrics.detailScroll} clientHeight=${metrics.detailClient}` +
                  ` width=${metrics.detail ? Math.round(metrics.detail.right - metrics.detail.left) : "none"}\n`,
              );
              if (!metrics.spendText) {
                fails.push(`${view.name}: spend-fields missing`);
              } else if (!/10[.,]00/.test(metrics.spendText) || !/example-payee/.test(metrics.spendText)) {
                fails.push(`${view.name}: spend-fields thin (${metrics.spendText.slice(0, 80)})`);
              }
              if (!metrics.pairText) {
                fails.push(`${view.name}: explain-pair missing`);
              }
            }
          }
          if (pageErrors.length) fails.push(`${view.name}: pageerror ${pageErrors.join(" | ")}`);
          if (consoleErrors.length) fails.push(`${view.name}: console ${consoleErrors.join(" | ")}`);
          for (let t = 0; t < TABS.length; t += 1) {
            await page.getByRole("tab", { name: TABS[t] }).click();
            await page.waitForTimeout(200);
            // Every tab, not just the one the panel opens on: the first
            // version of this check read the records tab alone and missed a
            // Turkish word sitting on the status tab.
            const leftover = await page.evaluate((needles: string[]) => {
              // No exemptions any more. The one screen that carried two
              // languages on purpose was a glossary of body-part names that
              // measured nothing, and it is gone; an English screen now has
              // to be English all the way down.
              const text = document.body.innerText ?? document.body.textContent ?? "";
              const hit = needles.find((n) => text.includes(n));
              return hit === undefined ? "" : hit.slice(0, 60);
            }, TURKISH_ONLY);
            if (leftover !== "") {
              fails.push(
                `${view.name}/${TAB_FILES[t]}: Turkish on the English screen: "${leftover}"`,
              );
            }
            // The rail is a way into a record from the two tabs that have no
            // list of their own. On the records tab it is neither that nor a
            // full column of anything else, so it is not drawn there at all.
            const rail = await page.evaluate(() => document.querySelector(".obs-left") !== null);
            if (TAB_FILES[t] === "records" && rail) {
              fails.push(`${view.name}/${TAB_FILES[t]}: the rail is drawn on the records tab`);
            }
            if (TAB_FILES[t] !== "records" && !rail) {
              fails.push(`${view.name}/${TAB_FILES[t]}: no rail, and no other way into a record`);
            }
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
