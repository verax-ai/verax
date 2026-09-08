import { hashPoint, type Point3 } from "./address.ts";

/** Closed-sphere radius. Records park here until the scene opens. */
export const CLOSED_RADIUS = 2.55;
export const OPEN_MS = 1400;
export const REDUCED_OPEN_MS = 300;

export function mix3(a: Point3, b: Point3, t: number): Point3 {
  const u = Math.max(0, Math.min(1, t));
  return {
    x: a.x + (b.x - a.x) * u,
    y: a.y + (b.y - a.y) * u,
    z: a.z + (b.z - a.z) * u,
  };
}

/** Deterministic park on the closed sphere. Same id → same seat. */
export function parkPoint(id: string, radius = CLOSED_RADIUS): Point3 {
  return hashPoint(`park:${id}`, radius);
}

/** Spatial ease. Reduced motion stays linear (plain 0.3 s). */
export function easeOpen(t: number, reducedMotion = false): number {
  const x = Math.max(0, Math.min(1, t));
  if (reducedMotion) return x;
  return x * x * (3 - 2 * x);
}

export function openDurationMs(reducedMotion: boolean): number {
  return reducedMotion ? REDUCED_OPEN_MS : OPEN_MS;
}

/** Advance 0..1 toward `target`. Duration is 300 ms when reduced. */
export function stepOpen(
  current: number,
  target: number,
  dtMs: number,
  reducedMotion: boolean,
): number {
  const dur = openDurationMs(reducedMotion);
  const delta = target - current;
  if (Math.abs(delta) < 1e-4) return target;
  const next = current + (dtMs / Math.max(1, dur)) * Math.sign(delta);
  if ((delta > 0 && next >= target) || (delta < 0 && next <= target)) return target;
  return Math.max(0, Math.min(1, next));
}

export function readOpenQuery(search: string): number | null {
  const q = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search).get("open");
  if (q === "1" || q === "true") return 1;
  if (q === "0" || q === "false") return 0;
  return null;
}
