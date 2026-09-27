#!/usr/bin/env node
// Scale probe for the panel. Starts the body on a ledger that ledger-scale.ts
// built, serves the built panel with vite preview in front of it, opens it in
// headless Chromium through the issuer's code flow, and measures what a person
// would feel: time until the record list is on screen, size and duration of
// the /api/ledger fetch, DOM node count, JS heap, and the longest frame gap
// over two polling rounds (the panel refetches every five seconds).
// The panel's code flow without a passkey no longer carries verax:audit, so
// this headless run sees 403 on /api/ledger until it drives a passkey sign-in.
//
// VERAX_SCALE_N      which ledger (default 10000)
// VERAX_SCALE_DIR    state directory (default <tmp>/verax-scale-<N>)
// VERAX_SCALE_OUT    directory for last-panel-<N>.json (default the state dir)
// VERAX_SCALE_RENDER_TIMEOUT_MS  give up waiting for the list (default 180000)

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { killStragglers, launchBrowser, startPreview } from "../../../scripts/test-preview.ts";
import { bootBody, repoRoot, rssMb } from "./boot.ts";

const N = Number(process.env.VERAX_SCALE_N ?? "10000");
const dir = process.env.VERAX_SCALE_DIR ?? join(tmpdir(), `verax-scale-${N}`);
const outDir = process.env.VERAX_SCALE_OUT ?? dir;
const RENDER_TIMEOUT_MS = Number(process.env.VERAX_SCALE_RENDER_TIMEOUT_MS ?? "180000");
const ISSUER_PORT = Number(process.env.VERAX_SCALE_ISSUER_PORT ?? "8794");
const BODY_PORT = Number(process.env.VERAX_SCALE_BODY_PORT ?? "8795");
const PREVIEW_PORT = Number(process.env.VERAX_SCALE_PREVIEW_PORT ?? "4193");
const POLL_WINDOW_MS = 11_000;

const log = (s: string) => process.stderr.write(`panel-scale: ${s}\n`);

type ResourceRow = { name: string; durationMs: number; decodedBytes: number; startMs: number };

async function run(): Promise<void> {
  if (!existsSync(join(dir, "decisions.jsonl"))) throw new Error(`no ledger in ${dir}; run ledger-scale.ts first`);
  const panelRoot = join(repoRoot, "apps", "panel");
  if (!existsSync(join(panelRoot, "dist", "index.html"))) throw new Error("apps/panel/dist missing; build the panel first");
  const viteJs = join(repoRoot, "node_modules", "vite", "bin", "vite.js");
  const previewUrl = `http://127.0.0.1:${PREVIEW_PORT}/`;

  log("starting issuer + body");
  const booted = await bootBody({
    stateDir: dir,
    policyFile: join(dir, "policy.json"),
    issuerPort: ISSUER_PORT,
    bodyPort: BODY_PORT,
    redirectUris: ["http://127.0.0.1:8791/callback", previewUrl],
    quiet: true,
  });
  let preview: { base: string; stop: () => void } | null = null;
  let stopBrowser: (() => void) | null = null;
  try {
    log(`body up in ${booted.bodyStartMs} ms`);
    preview = await startPreview({
      viteJs,
      cwd: panelRoot,
      port: PREVIEW_PORT,
      label: "panel-scale",
      env: { VERAX_BODY_URL: booted.bodyUrl },
      command: "preview",
    });
    const launched = await launchBrowser([]);
    stopBrowser = launched.stopBrowser;
    const context = await launched.browser.newContext({ viewport: { width: 1280, height: 900 } });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("Performance.enable");
    let crashed: string | null = null;
    page.on("crash", () => {
      crashed = "page crashed";
    });
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text().slice(0, 200));
    });

    const t0 = performance.now();
    await page.goto(`${preview.base}/`, { waitUntil: "domcontentloaded" });
    let renderedMs: number | null = null;
    let renderError: string | null = null;
    try {
      await page.waitForSelector('[data-testid="record-list"] li', { timeout: RENDER_TIMEOUT_MS });
      renderedMs = Math.round(performance.now() - t0);
    } catch (err) {
      renderError = crashed ?? (err as Error).message.split("\n")[0]!;
    }
    log(renderedMs === null ? `list not rendered: ${renderError}` : `list rendered in ${renderedMs} ms`);

    const metricsOf = async () => {
      const m = await cdp.send("Performance.getMetrics");
      const pick = (name: string) => m.metrics.find((x: { name: string; value: number }) => x.name === name)?.value ?? null;
      return {
        jsHeapUsedMb: pick("JSHeapUsedSize") === null ? null : Math.round((pick("JSHeapUsedSize") as number) / 1_048_576),
        jsHeapTotalMb: pick("JSHeapTotalSize") === null ? null : Math.round((pick("JSHeapTotalSize") as number) / 1_048_576),
        domNodes: pick("Nodes"),
        layoutCount: pick("LayoutCount"),
        taskDurationS: pick("TaskDuration") === null ? null : Number((pick("TaskDuration") as number).toFixed(1)),
      };
    };
    const resourcesOf = async (): Promise<ResourceRow[]> =>
      page.evaluate(() =>
        performance
          .getEntriesByType("resource")
          .filter((e) => e.name.includes("/api/ledger"))
          .map((e) => ({
            name: new URL(e.name).search.slice(0, 40),
            durationMs: Math.round(e.duration),
            decodedBytes: (e as PerformanceResourceTiming).decodedBodySize,
            startMs: Math.round(e.startTime),
          })),
      );

    let afterRender: Awaited<ReturnType<typeof metricsOf>> | null = null;
    let listItems: number | null = null;
    let firstFetch: ResourceRow[] = [];
    let frames: { maxGapMs: number; frames: number; gapsOver100ms: number } | null = null;
    let afterPolls: Awaited<ReturnType<typeof metricsOf>> | null = null;
    let allFetches: ResourceRow[] = [];
    if (renderedMs !== null || crashed === null) {
      try {
        afterRender = await metricsOf();
        listItems = await page.evaluate(() => document.querySelectorAll('[data-testid="record-list"] li').length);
        firstFetch = await resourcesOf();
        // Two more polls land inside this window; the longest gap between
        // animation frames is the longest the page stood still.
        frames = await page.evaluate(
          (windowMs) =>
            new Promise<{ maxGapMs: number; frames: number; gapsOver100ms: number }>((resolve) => {
              let last = performance.now();
              const end = last + windowMs;
              let maxGap = 0;
              let count = 0;
              let over = 0;
              const tick = () => {
                const now = performance.now();
                const gap = now - last;
                if (gap > maxGap) maxGap = gap;
                if (gap > 100) over += 1;
                last = now;
                count += 1;
                if (now < end) requestAnimationFrame(tick);
                else resolve({ maxGapMs: Math.round(maxGap), frames: count, gapsOver100ms: over });
              };
              requestAnimationFrame(tick);
            }),
          POLL_WINDOW_MS,
        );
        afterPolls = await metricsOf();
        allFetches = await resourcesOf();
      } catch (err) {
        renderError = renderError ?? `after render: ${(err as Error).message.split("\n")[0]}`;
      }
    }
    const result = {
      probe: "panel-scale",
      at: new Date().toISOString(),
      platform: `${process.platform}/${process.arch}/node${process.versions.node}`,
      n: N,
      stateDir: dir,
      body: { startMs: booted.bodyStartMs, rssMb: rssMb(booted.bodyPid) },
      renderedMs,
      renderError,
      listItems,
      firstLedgerFetch: firstFetch[0] ?? null,
      afterRender,
      pollWindowMs: POLL_WINDOW_MS,
      frames,
      ledgerFetches: allFetches.length,
      ledgerFetchMedianMs: allFetches.length ? [...allFetches].sort((a, b) => a.durationMs - b.durationMs)[Math.floor((allFetches.length - 1) / 2)]!.durationMs : null,
      afterPolls,
      consoleErrors: consoleErrors.slice(0, 5),
    };
    mkdirSync(outDir, { recursive: true });
    const outPath = join(outDir, `last-panel-${N}.json`);
    writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
    process.stdout.write(`${JSON.stringify(result)}\n`);
    log(`wrote ${outPath}`);
    await context.close().catch(() => undefined);
  } finally {
    stopBrowser?.();
    preview?.stop();
    booted.stop();
    killStragglers();
  }
}

await run();
