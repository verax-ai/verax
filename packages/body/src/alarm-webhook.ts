import { listAlarmOutbox, markAlarmDelivered } from "./alarm-outbox.ts";
import { ALARM_WEBHOOK_URL_ERROR, isAllowedAlarmWebhookUrl } from "./config.ts";

export const ALARM_POST_TIMEOUT_MS = 10_000;

export function assertAlarmWebhookUrl(url: string): void {
  if (!isAllowedAlarmWebhookUrl(url)) throw new Error(ALARM_WEBHOOK_URL_ERROR);
}

function oneLine(err: unknown): string {
  const text = err instanceof Error ? err.message : String(err);
  return text.replace(/[\r\n]+/g, " ").slice(0, 300);
}

/**
 * POST the signed envelope. Redirects are not followed. A 2xx status is
 * acceptance; the body is not read. Anything else, including a 302, is not
 * delivery.
 */
export async function postAlarmWebhook(
  url: string,
  envelope: unknown,
  signal?: AbortSignal,
): Promise<boolean> {
  const ac = new AbortController();
  const onAbort = (): void => ac.abort();
  if (signal) {
    if (signal.aborted) ac.abort();
    else signal.addEventListener("abort", onAbort, { once: true });
  }
  const timer = setTimeout(() => ac.abort(), ALARM_POST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
      redirect: "manual",
      signal: ac.signal,
    });
    const body = res.body;
    if (body) {
      try {
        body.cancel();
      } catch {
        // Closing an unread body is enough; a cancel that throws is not delivery.
      }
    }
    return res.status >= 200 && res.status < 300;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

const pokers = new Map<string, () => void>();

/** Retry pending outbox files until each receiver answers 2xx. Same eventId every time. */
export function startAlarmDelivery(opts: { stateDir: string; url: string; retryMs: number }): () => Promise<void> {
  assertAlarmWebhookUrl(opts.url);
  let stopped = false;
  let inFlight = false;
  let running: Promise<void> = Promise.resolve();
  const abort = new AbortController();

  const tick = (): void => {
    if (stopped || inFlight) return;
    inFlight = true;
    running = (async () => {
      try {
        for (const envelope of listAlarmOutbox(opts.stateDir)) {
          if (stopped) break;
          const ok = await postAlarmWebhook(opts.url, envelope, abort.signal);
          if (stopped) break;
          if (ok) markAlarmDelivered(opts.stateDir, envelope);
        }
      } catch (err) {
        process.stderr.write(`verax: alarm-delivery: ${oneLine(err)}\n`);
      } finally {
        inFlight = false;
      }
    })();
  };

  pokers.set(opts.stateDir, tick);
  tick();
  const timer = setInterval(tick, opts.retryMs);
  timer.unref();
  return async () => {
    stopped = true;
    abort.abort();
    pokers.delete(opts.stateDir);
    clearInterval(timer);
    await running;
  };
}

export function pokeAlarmDelivery(stateDir: string): void {
  pokers.get(stateDir)?.();
}
