export type LabelKind = "planet" | "agent" | "star";

/**
 * Label LOD. Distance is camera-to-origin. Thresholds scale with scene radius
 * so a bigger sky does not silently hide every name.
 */
export function labelVisible(kind: LabelKind, cameraDistance: number, sceneRadius: number): boolean {
  if (!(sceneRadius > 0) || !(cameraDistance > 0)) return false;
  const u = cameraDistance / sceneRadius;
  if (kind === "planet") return u < 12;
  if (kind === "agent") return u < 6;
  return u < 3.5;
}
