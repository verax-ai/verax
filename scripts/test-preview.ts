#!/usr/bin/env node
// A preview server and a browser that a stuck test cannot leave behind.
//
// The browser suites spawn vite and launch Chromium inside the test body and
// clean up in `finally`. That cleanup runs only if the body reaches it. It did
// not in `body-map/tests/page.test.ts`, where the wait for the server sat
// outside the `try`: when the preview never announced itself the test failed
// at once and the vite child stayed alive. A live child keeps the runner's
// handles open, so `node --test` cannot exit - it prints nothing more and the
// CI job sits until its cap. That is what a 12-minute `windows-full`
// cancellation with ten minutes of silence looks like from the outside.
//
// Measured on 11 Sep 2026: with the leak, a test that failed in 3 s left the
// runner alive past 60 s and had to be killed from outside (exit 124). With
// `killStragglers()` in an `after()` hook it exits in about 3 s, red.
//
// Everything started through here is registered process-wide. node:test runs
// after-hooks even when a test times out, so the kill does not depend on the
// test body settling.
//
// This file never asserts. It only starts things and guarantees they die.

import { spawn } from "node:child_process";
import type { Browser } from "playwright";

/** Anything holding a handle open: a spawned server, a browser process. */
export type Straggler = { kill: () => void };

const live = new Set<Straggler>();

/**
 * Register something to be killed by `killStragglers()`. Returns a function
 * that kills it now and forgets it, for the ordinary path where the test
 * finishes and wants its port back before the next one.
 */
export function trackStraggler(straggler: Straggler): () => void {
  live.add(straggler);
  return () => {
    live.delete(straggler);
    // Killing a process that already exited returns false; it does not throw.
    // Whatever does throw here is a broken kill, and hiding it is how a
    // browser that was never killed looked like one that was.
    straggler.kill();
  };
}

/**
 * Launch Chromium as a server this process owns, and connect to it.
 *
 * A browser is tracked by its process, not by `close()`: closing is
 * asynchronous and can itself hang, and an after-hook that awaits a hung close
 * is the same trap one level up. `chromium.launch()` gives no handle on the
 * process. The helper this replaces called `browser.process()`, which a
 * Browser does not have; the TypeError fell into an empty catch, so a test
 * that failed with its browser open left Chromium running and the runner
 * waiting on it until the CI cap. `launchServer()` returns the process itself.
 *
 * `browser.close()` on a connected browser only disconnects. Call
 * `stopBrowser()` after it to end the process.
 */
export async function launchBrowser(args: string[] = []): Promise<{ browser: Browser; stopBrowser: () => void }> {
  const { chromium } = await import("playwright");
  const server = await chromium.launchServer({ args });
  const stopBrowser = trackStraggler({
    kill: () => {
      server.process().kill();
    },
  });
  try {
    const browser = await chromium.connect(server.wsEndpoint());
    return { browser, stopBrowser };
  } catch (err) {
    stopBrowser();
    throw err;
  }
}

/**
 * Kill everything still registered. Safe to call more than once. Every entry
 * is attempted before a failure is reported, so one broken kill cannot leave
 * the rest alive.
 */
export function killStragglers(): void {
  const failures: unknown[] = [];
  for (const straggler of live) {
    try {
      straggler.kill();
    } catch (err) {
      failures.push(err);
    }
  }
  live.clear();
  if (failures.length > 0) throw new AggregateError(failures, "straggler-kill-failed");
}

export type Preview = {
  /** Origin only, e.g. `http://127.0.0.1:4189`. Callers add their own path. */
  base: string;
  /** Kill this preview now and stop tracking it. */
  stop: () => void;
};

/**
 * Start a vite preview and wait until it announces its own address.
 *
 * `label` is printed when the server goes up. A suite that hangs anyway should
 * at least say which preview it got as far as: the CI log that started this
 * work ended mid-run with no way to tell which test was still open.
 */
export async function startPreview(opts: {
  viteJs: string;
  cwd: string;
  port: number;
  label: string;
  readyTimeoutMs?: number;
  /** Extra env for the child. Overlay, not a replacement. */
  env?: NodeJS.ProcessEnv;
  /**
   * `preview` is what `verax desktop` runs. The default stays the vite
   * dev server so the layout gates keep the path they already measure.
   */
  command?: "dev" | "preview";
}): Promise<Preview> {
  const base = `http://127.0.0.1:${opts.port}`;
  const argv =
    opts.command === "preview"
      ? [opts.viteJs, "preview", "--host", "127.0.0.1", "--port", String(opts.port), "--strictPort"]
      : [opts.viteJs, "--host", "127.0.0.1", "--port", String(opts.port), "--strictPort"];
  const child = spawn(process.execPath, argv, {
    cwd: opts.cwd,
    env: { ...process.env, ...opts.env, NO_COLOR: "1", FORCE_COLOR: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  // Tracked before the first await: a rejection from here on cannot orphan it.
  const stop = trackStraggler(child);
  const startedAt = Date.now();
  process.stdout.write(`preview ${opts.label}: starting on ${base}\n`);
  try {
    await new Promise<void>((resolve, reject) => {
      let buf = "";
      const timer = setTimeout(
        () => reject(new Error(`preview-timeout:${opts.label}:${buf.slice(-400)}`)),
        opts.readyTimeoutMs ?? 90_000,
      );
      const onData = (chunk: Buffer) => {
        buf += String(chunk);
        if (buf.includes(`${base}/`)) {
          clearTimeout(timer);
          resolve();
        }
      };
      child.stdout.on("data", onData);
      child.stderr.on("data", onData);
      child.on("exit", (code) => {
        clearTimeout(timer);
        reject(new Error(`preview-exit:${opts.label}:${code}:${buf.slice(-400)}`));
      });
    });
  } catch (err) {
    stop();
    throw err;
  }
  process.stdout.write(`preview ${opts.label}: up in ${Date.now() - startedAt}ms\n`);
  return { base, stop };
}
