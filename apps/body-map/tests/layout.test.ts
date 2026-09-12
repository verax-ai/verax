import { strict as assert } from "node:assert";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { killStragglers, launchBrowser, startPreview } from "../../../scripts/test-preview.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const viteJs = join(root, "..", "..", "node_modules", "vite", "bin", "vite.js");

const IDS = ["head", "face", "core", "left-hand", "right-hand", "torso", "ground"] as const;
const HANDS = new Set(["left-hand", "right-hand"]);

const VIEWS = [
  { name: "1440", width: 1440, height: 900 },
  { name: "1920", width: 1920, height: 1080 },
  { name: "390", width: 390, height: 844 },
] as const;

type Anchor = { x: number; y: number };
type Box = { x: number; y: number; w: number; h: number; top: number; bottom: number; left: number; right: number };

type Shot = {
  name: string;
  width: number;
  height: number;
  canvas: { w: number; h: number } | null;
  rain: boolean;
  anchors: Record<string, Anchor> | null;
  labels: Record<string, { cx: number; cy: number }> | null;
  card: Box | null;
  cta: Box | null;
  intro: Box | null;
  stage: Box | null;
  scrollHeight: number;
  pageErrors: string[];
  consoleErrors: string[];
};

function boxOf(r: { x: number; y: number; width: number; height: number } | null): Box | null {
  if (!r) return null;
  return {
    x: r.x,
    y: r.y,
    w: r.width,
    h: r.height,
    top: r.y,
    bottom: r.y + r.height,
    left: r.x,
    right: r.x + r.width,
  };
}

function insideWindow(b: Box, w: number, h: number): boolean {
  return b.left >= -0.5 && b.top >= -0.5 && b.right <= w + 0.5 && b.bottom <= h + 0.5;
}

after(killStragglers);

describe("body-map layout", () => {
  it("keeps the stage, rain, anchors, labels, card and CTA on the first screen", { timeout: 120_000 }, async () => {
    const preview = await startPreview({ viteJs, cwd: root, port: 4188, label: "body-map-layout" });
    const ready = `${preview.base}/verax/`;
    const fails: string[] = [];
    try {
      const { browser, stopBrowser } = await launchBrowser(["--use-gl=swiftshader"]);
      const shots: Shot[] = [];
      for (const view of VIEWS) {
        const page = await browser.newPage({ viewport: { width: view.width, height: view.height } });
        const pageErrors: string[] = [];
        const consoleErrors: string[] = [];
        page.on("pageerror", (err) => pageErrors.push(String(err)));
        page.on("console", (msg) => {
          if (msg.type() === "error") consoleErrors.push(msg.text());
        });
        await page.goto(ready, { waitUntil: "networkidle" });
        await page.locator("button.label").first().waitFor({ state: "visible", timeout: 30_000 });
        await page.waitForTimeout(2500);
        await page.waitForFunction(
          () => {
            const w = window as Window & { __veraxAnchors?: Record<string, { x: number; y: number }> };
            const a = w.__veraxAnchors;
            return Boolean(a && a.head && a.ground);
          },
          { timeout: 15_000 },
        ).catch(() => undefined);
        const shot = (await page.evaluate((ids) => {
          const w = window as Window & { __veraxAnchors?: Record<string, { x: number; y: number }> };
          const canvas = document.querySelector(".figure-wrap canvas") as HTMLCanvasElement | null;
          const rain = document.querySelector("canvas.matrix") as HTMLCanvasElement | null;
          const labels: Record<string, { cx: number; cy: number }> = {};
          for (const id of ids) {
            const el = document.querySelector(`[data-anchor="${id}"]`);
            if (!el) continue;
            const r = el.getBoundingClientRect();
            labels[id] = { cx: r.left + r.width / 2, cy: r.top + r.height / 2 };
          }
          const rect = (sel: string) => {
            const el = document.querySelector(sel);
            if (!el) return null;
            const r = el.getBoundingClientRect();
            return { x: r.x, y: r.y, width: r.width, height: r.height };
          };
          return {
            canvas: canvas ? { w: canvas.getBoundingClientRect().width, h: canvas.getBoundingClientRect().height } : null,
            rain: Boolean(rain),
            anchors: w.__veraxAnchors ?? null,
            labels: Object.keys(labels).length ? labels : null,
            card: rect(".card"),
            cta: rect(".cta"),
            intro: rect(".intro"),
            stage: rect(".stage"),
            scrollHeight: document.documentElement.scrollHeight,
          };
        }, [...IDS])) as Omit<Shot, "name" | "width" | "height" | "pageErrors" | "consoleErrors" | "card" | "cta" | "intro" | "stage"> & {
          card: { x: number; y: number; width: number; height: number } | null;
          cta: { x: number; y: number; width: number; height: number } | null;
          intro: { x: number; y: number; width: number; height: number } | null;
          stage: { x: number; y: number; width: number; height: number } | null;
        };
        shots.push({
          name: view.name,
          width: view.width,
          height: view.height,
          canvas: shot.canvas,
          rain: shot.rain,
          anchors: shot.anchors,
          labels: shot.labels,
          card: boxOf(shot.card),
          cta: boxOf(shot.cta),
          intro: boxOf(shot.intro),
          stage: boxOf(shot.stage),
          scrollHeight: shot.scrollHeight,
          pageErrors,
          consoleErrors,
        });
        await page.close();
      }
      await browser.close();
      stopBrowser();

      for (const s of shots) {
        const desktop = s.width > 800;
        if (!s.canvas) fails.push(`${s.name}:1 missing .figure-wrap canvas`);
        else {
          if (s.canvas.h > s.height) fails.push(`${s.name}:1 canvas height ${s.canvas.h} > window ${s.height}`);
          if (Math.abs(s.canvas.w - s.width) > 1) fails.push(`${s.name}:1 canvas width ${s.canvas.w} != window ${s.width}`);
        }
        if (s.rain) fails.push(`${s.name}:2 canvas.matrix present; the page has no rain`);
        if (!s.anchors) fails.push(`${s.name}:3 missing window.__veraxAnchors`);
        else {
          for (const id of IDS) {
            const a = s.anchors[id];
            if (!a) {
              fails.push(`${s.name}:3 missing anchor ${id}`);
              continue;
            }
            if (a.x < 16 || a.x > s.width - 16 || a.y < 16 || a.y > s.height - 16) {
              fails.push(`${s.name}:3 ${id} at ${a.x.toFixed(1)},${a.y.toFixed(1)} not ≥16px inside window`);
            }
          }
        }
        if (desktop) {
          if (!s.labels || !s.anchors) fails.push(`${s.name}:4 missing labels or anchors`);
          else {
            for (const id of IDS) {
              const lab = s.labels[id];
              const a = s.anchors[id];
              if (!lab) {
                fails.push(`${s.name}:4 missing label ${id}`);
                continue;
              }
              if (HANDS.has(id)) {
                const left = s.anchors["left-hand"];
                const right = s.anchors["right-hand"];
                const dLeft = left ? Math.abs(lab.cy - left.y) : Infinity;
                const dRight = right ? Math.abs(lab.cy - right.y) : Infinity;
                if (Math.min(dLeft, dRight) > 24) {
                  fails.push(`${s.name}:4 hands ${id} cy ${lab.cy.toFixed(1)} far from both anchors`);
                }
              } else if (!a || Math.abs(lab.cy - a.y) > 24) {
                fails.push(`${s.name}:4 ${id} label cy ${lab.cy.toFixed(1)} vs anchor ${a ? a.y.toFixed(1) : "?"}`);
              }
            }
          }
          if (!s.card) fails.push(`${s.name}:5 missing .card`);
          else if (!insideWindow(s.card, s.width, s.height)) {
            fails.push(`${s.name}:5 card ${s.card.top.toFixed(0)}–${s.card.bottom.toFixed(0)} outside window`);
          }
          if (!s.cta) fails.push(`${s.name}:5 missing .cta`);
          else if (!insideWindow(s.cta, s.width, s.height)) {
            fails.push(`${s.name}:5 cta ${s.cta.top.toFixed(0)}–${s.cta.bottom.toFixed(0)} outside window`);
          }
          if (s.scrollHeight > s.height + 1) {
            fails.push(`${s.name}:5 scrollHeight ${s.scrollHeight} > window ${s.height}`);
          }
        }
        if (!desktop) {
          if (!s.intro || !s.stage) fails.push(`${s.name}:6 missing .intro or .stage`);
          else if (s.intro.bottom > s.stage.top + 0.5) {
            fails.push(`${s.name}:6 intro bottom ${s.intro.bottom.toFixed(1)} >= stage top ${s.stage.top.toFixed(1)}`);
          }
          const head = s.anchors?.head;
          if (!s.stage || !head) fails.push(`${s.name}:6 missing stage or head anchor`);
          else if (head.y < s.stage.top || head.y > s.stage.bottom) {
            fails.push(`${s.name}:6 head ${head.y.toFixed(1)} not inside stage ${s.stage.top.toFixed(1)}–${s.stage.bottom.toFixed(1)}`);
          }
        }
        if (s.pageErrors.length) fails.push(`${s.name}:7 pageerror ${s.pageErrors.join(" | ")}`);
        if (s.consoleErrors.length) fails.push(`${s.name}:7 console ${s.consoleErrors.join(" | ")}`);
      }
      if (fails.length) {
        assert.fail(fails.join("\n"));
      }
    } finally {
      preview.stop();
    }
  });
});
