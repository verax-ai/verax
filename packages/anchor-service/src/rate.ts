/** Sliding one-minute window of successful authenticated requests per owner. */

export class RateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly limit: number;
  private readonly windowMs: number;

  constructor(limit: number, windowMs = 60_000) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** True when this owner is already at the limit for the current window. */
  overLimit(ownerId: string, nowMs: number = Date.now()): boolean {
    const cutoff = nowMs - this.windowMs;
    const prev = (this.hits.get(ownerId) ?? []).filter((t) => t > cutoff);
    this.hits.set(ownerId, prev);
    return prev.length >= this.limit;
  }

  record(ownerId: string, nowMs: number = Date.now()): void {
    const cutoff = nowMs - this.windowMs;
    const prev = (this.hits.get(ownerId) ?? []).filter((t) => t > cutoff);
    prev.push(nowMs);
    this.hits.set(ownerId, prev);
  }
}
