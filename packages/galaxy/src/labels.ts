export type LabelKind = "planet" | "agent";

/**
 * Label LOD. Distance is camera-to-origin. Thresholds scale with scene radius
 * so a bigger sky does not silently hide every name.
 */
export function labelVisible(kind: LabelKind, cameraDistance: number, sceneRadius: number): boolean {
  if (!(sceneRadius > 0) || !(cameraDistance > 0)) return false;
  const u = cameraDistance / sceneRadius;
  if (kind === "planet") return u < 12;
  return u < 6;
}

/** The text a label may show, or null when the record carries no name. */
export function labelText(name: string | undefined): string | null {
  const text = (name ?? "").trim();
  return text.length > 0 ? text : null;
}

const LABEL_FONT_PX = 48;
const LABEL_PAD_PX = 16;

/**
 * Paints the name onto a canvas the caller turns into a texture. Returns false
 * when the page gives no 2d context, and the caller then mounts no sprite: a
 * label with no readable name is a coloured box pretending to be one.
 */
export function paintLabel(canvas: HTMLCanvasElement, text: string): boolean {
  const ctx = canvas.getContext("2d");
  if (!ctx) return false;
  const font = `${LABEL_FONT_PX}px system-ui, sans-serif`;
  ctx.font = font;
  const width = Math.ceil(ctx.measureText(text).width) + LABEL_PAD_PX * 2;
  const height = LABEL_FONT_PX + LABEL_PAD_PX * 2;
  // Resizing clears the context, so the font is set again after the resize.
  canvas.width = width;
  canvas.height = height;
  ctx.clearRect(0, 0, width, height);
  ctx.font = font;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillStyle = "rgba(234, 242, 248, 0.92)";
  ctx.fillText(text, width / 2, height / 2);
  return true;
}

/** Aspect ratio of a painted label, so the sprite is not stretched. */
export function labelAspect(canvas: { width: number; height: number }): number {
  return canvas.height > 0 ? canvas.width / canvas.height : 1;
}
