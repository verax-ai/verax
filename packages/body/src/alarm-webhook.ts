import { listAlarmOutbox, markAlarmDelivered } from "./alarm-outbox.ts";
import { ALARM_WEBHOOK_URL_ERROR, isAllowedAlarmWebhookUrl } from "./config.ts";

export const ALARM_POST_TIMEOUT_MS = 10_000;

export function assertAlarmWebhookUrl(url: string): void {
  if (!isAllowedAlarmWebhookUrl(url)) throw new Error(ALARM_WEBHOOK_URL_ERROR);
}

/**
 * POST the signed envelope. Redirects are not followed. A 2xx status is
 * acceptance; the body is not read. Anything else, including a 302, is not
 * delivery.
 */
export async function postAlarmWebhook(url: string, envelope: unknown): Promise<boolean> {
  const ac = new AbortController();
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
  }
}

const pokers = new Map<string, () => void>();

/** Retry pending outbox files until each receiver answers 2xx. Same eventId every time. */
export function startAlarmDelivery(opts: { stateDir: string; url: string; retryMs: number }): () => void {
  assertAlarmWebhookUrl(opts.url);
  let stopped = false;
  let inFlight = false;

  const tick = (): void => {
    if (stopped || inFlight) return;
    inFlight = true;
    void (async () => {
      try {
        for (const envelope of listAlarmOutbox(opts.stateDir)) {
          if (stopped) break;
          const ok = await postAlarmWebhook(opts.url, envelope);
          if (ok) markAlarmDelivered(opts.stateDir, envelope);
        }
      } finally {
        inFlight = false;
      }
    })();
  };

  pokers.set(opts.stateDir, tick);
  tick();
  const timer = setInterval(tick, opts.retryMs);
  timer.unref();
  return () => {
    stopped = true;
    pokers.delete(opts.stateDir);
    clearInterval(timer);
  };
}

export function pokeAlarmDelivery(stateDir: string): void {
  pokers.get(stateDir)?.();
}
