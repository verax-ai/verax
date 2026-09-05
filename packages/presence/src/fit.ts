export const FIT_EDGE = 4.2;

export type Box3 = { min: [number, number, number]; max: [number, number, number] };

/** Centre the mesh; scale the longest edge to FIT_EDGE. */
export function fitFromBox(box: Box3): { position: [number, number, number]; scale: number } {
  const cx = (box.min[0] + box.max[0]) / 2;
  const cy = (box.min[1] + box.max[1]) / 2;
  const cz = (box.min[2] + box.max[2]) / 2;
  const sx = box.max[0] - box.min[0];
  const sy = box.max[1] - box.min[1];
  const sz = box.max[2] - box.min[2];
  const scale = FIT_EDGE / Math.max(sx, sy, sz, 1e-6);
  return { position: [-cx * scale, -cy * scale, -cz * scale], scale };
}

export function chestLocal(box: Box3): [number, number, number] {
  return [0, box.min[1] + (box.max[1] - box.min[1]) * 0.76, 0];
}

export function lerpColor(
  current: [number, number, number],
  target: readonly [number, number, number],
  t = 0.04,
): [number, number, number] {
  return [
    current[0] + (target[0] - current[0]) * t,
    current[1] + (target[1] - current[1]) * t,
    current[2] + (target[2] - current[2]) * t,
  ];
}
