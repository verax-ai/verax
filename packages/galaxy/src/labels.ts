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

/**
 * Screen-space height of an agent name (NDC; 2 is the whole viewport).
 * Matches the sprite scale in Galaxy.tsx. A short English name is about
 * four times wider than it is tall, so one glyph box is this times four.
 */
export const AGENT_LABEL_NDC_HEIGHT = 0.036;

/** Canvas fov in Galaxy.tsx. Used only to turn world distance into NDC. */
export const LABEL_FOV_DEG = 46;

/**
 * One name needs a neighbour-sized gap or two labels fuse into a white
 * smear: the defect measured on a 500-agent inventory at opening
 * distance 85, scene radius 48, fov 46°: the GPU was fine (p95 5.9 on
 * hardware); the names were not readable. Area, not a head-count cap:
 * showing 8 of 500 would leak a count through which names remain.
 */
const LABEL_BOX_NDC = AGENT_LABEL_NDC_HEIGHT * AGENT_LABEL_NDC_HEIGHT * 4;
const NEIGHBOUR_CLEARANCE = 4;
const MIN_MEAN_NDC_AREA = LABEL_BOX_NDC * NEIGHBOUR_CLEARANCE;
const FOV_HALF_TAN = Math.tan((LABEL_FOV_DEG * Math.PI) / 360);

/**
 * How many names stay readable at this distance. The set is shown as a
 * whole or not at all: a half-shown crowd is the smear again. Callers
 * apply this on top of labelVisible and give planets the first claim on
 * the budget (evaluate planets on their own count, agents on both).
 */
export function labelBudget(
  count: number,
  cameraDistance: number,
  sceneRadius: number,
): { show: boolean; hidden: number } {
  if (!(count > 0)) return { show: true, hidden: 0 };
  if (!(sceneRadius > 0) || !(cameraDistance > 0)) return { show: false, hidden: count };
  const projectedR = sceneRadius / cameraDistance / FOV_HALF_TAN;
  const meanArea = (Math.PI * projectedR * projectedR) / count;
  if (meanArea >= MIN_MEAN_NDC_AREA) return { show: true, hidden: 0 };
  return { show: false, hidden: count };
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
