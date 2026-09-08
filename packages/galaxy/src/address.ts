export type Point3 = { readonly x: number; readonly y: number; readonly z: number };

/** FNV-1a folded to 0..1. Same string always lands on the same fraction. */
export function hash01(seed: string): number {
  const s = String(seed ?? "");
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967296;
}

/**
 * Permanent 3D address for a record id. FNV-1a on `:u`/`:v`/`:w`,
 * cube-root radius, flattened Y. Cluster order and array index are not inputs.
 */
export function hashPoint(seed: string, radius: number): Point3 {
  const u = hash01(`${seed}:u`);
  const v = hash01(`${seed}:v`);
  const w = hash01(`${seed}:w`);
  const theta = u * Math.PI * 2;
  const phi = Math.acos(Math.min(1, Math.max(-1, 2 * v - 1)));
  const r = radius * Math.cbrt(w);
  return {
    x: r * Math.sin(phi) * Math.cos(theta),
    y: r * Math.cos(phi) * 0.55,
    z: r * Math.sin(phi) * Math.sin(theta),
  };
}
