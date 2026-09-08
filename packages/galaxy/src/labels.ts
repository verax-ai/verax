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
 * Personal space of one name in NDC. Chosen so π r² equals the same
 * readable area labelBudget used as a scene mean: a second name inside
 * this disk is the smear, measured on the 500-agent inventory.
 */
export const LABEL_NEIGHBORHOOD_NDC = Math.sqrt(MIN_MEAN_NDC_AREA / Math.PI);

/**
 * A handful of names in one disk is still readable (the three-agent
 * fixture puts two on one planet). Five or more in that disk is the
 * smear measured on a 12-group, 500-agent inventory.
 */
export const LABEL_READABLE_NEIGHBORS = 4;

export type Ndc = { readonly x: number; readonly y: number };

export type CameraEye = {
  readonly x: number;
  readonly y: number;
  readonly z: number;
  readonly lookX: number;
  readonly lookY: number;
  readonly lookZ: number;
  readonly fovDeg: number;
};

export type LabelHideReason = "distance" | "crowd";

export type LabelCrowd = {
  show: boolean;
  hidden: number;
  reason: LabelHideReason | null;
  densest: number;
};

/**
 * World point to NDC. The metric is the image the camera actually
 * draws, not the world gap: two bodies a metre apart stack when the
 * camera looks along that metre. Behind the camera is not on screen.
 */
export function projectNdc(world: { x: number; y: number; z: number }, cam: CameraEye): Ndc | null {
  if (!(cam.fovDeg > 0) || !Number.isFinite(cam.fovDeg)) return null;
  const fx = cam.lookX - cam.x;
  const fy = cam.lookY - cam.y;
  const fz = cam.lookZ - cam.z;
  const fl = Math.hypot(fx, fy, fz);
  if (!(fl > 0)) return null;
  const f0 = fx / fl;
  const f1 = fy / fl;
  const f2 = fz / fl;
  let rightX = -f2;
  let rightY = 0;
  let rightZ = f0;
  let rl = Math.hypot(rightX, rightY, rightZ);
  if (rl < 1e-8) {
    rightX = 1;
    rightY = 0;
    rightZ = 0;
    rl = 1;
  }
  rightX /= rl;
  rightY /= rl;
  rightZ /= rl;
  const upX = rightY * f2 - rightZ * f1;
  const upY = rightZ * f0 - rightX * f2;
  const upZ = rightX * f1 - rightY * f0;
  const dx = world.x - cam.x;
  const dy = world.y - cam.y;
  const dz = world.z - cam.z;
  const camZ = dx * f0 + dy * f1 + dz * f2;
  if (!(camZ > 1e-6)) return null;
  const camX = dx * rightX + dy * rightY + dz * rightZ;
  const camY = dx * upX + dy * upY + dz * upZ;
  const tan = Math.tan((cam.fovDeg * Math.PI) / 360);
  if (!(tan > 0)) return null;
  return { x: camX / camZ / tan, y: camY / camZ / tan };
}

/**
 * How many names sit in the densest personal-space disk. The scene
 * average does not enter: a tight knot in an otherwise empty sky is
 * still unreadable.
 */
export function densestNeighborhood(ndc: readonly Ndc[], radius = LABEL_NEIGHBORHOOD_NDC): number {
  if (!(ndc.length > 0)) return 0;
  if (!(radius > 0)) return ndc.length;
  const r2 = radius * radius;
  let max = 0;
  for (let i = 0; i < ndc.length; i += 1) {
    const a = ndc[i]!;
    let n = 0;
    for (let j = 0; j < ndc.length; j += 1) {
      const b = ndc[j]!;
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      if (dx * dx + dy * dy <= r2) n += 1;
    }
    if (n > max) max = n;
  }
  return max;
}

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

/**
 * Whether names stay readable in their own neighborhood. Distance LOD
 * still hides a far set (reason "distance"). A close set whose densest
 * disk holds more than one name is a crowd (reason "crowd"). The set
 * is shown as a whole or not at all.
 */
export function labelCrowd(
  ndc: readonly Ndc[],
  kind: LabelKind,
  cameraDistance: number,
  sceneRadius: number,
): LabelCrowd {
  const count = ndc.length;
  if (!(count > 0)) return { show: true, hidden: 0, reason: null, densest: 0 };
  if (!labelVisible(kind, cameraDistance, sceneRadius)) {
    return { show: false, hidden: count, reason: "distance", densest: densestNeighborhood(ndc) };
  }
  const densest = densestNeighborhood(ndc);
  if (densest <= LABEL_READABLE_NEIGHBORS) return { show: true, hidden: 0, reason: null, densest };
  return { show: false, hidden: count, reason: "crowd", densest };
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
