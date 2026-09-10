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
 * The sprite scale an agent name is drawn at, straight from Galaxy.tsx.
 *
 * This is NOT the height it covers on screen. With sizeAttenuation off,
 * three.js multiplies the scale by the view-space depth and then projects
 * it, so the box that lands on screen is `scale / tan(fov/2)` tall -- at
 * fov 46 that is 2.36x this number. Reading it as NDC directly is how the
 * crowd rule came to allow names that print on top of each other:
 * measured 8 Sep and still on screen 10 Sep, after the disk became a box.
 */
export const AGENT_LABEL_SPRITE_SCALE = 0.036;

/** Canvas fov in Galaxy.tsx. Used only to turn world distance into NDC. */
export const LABEL_FOV_DEG = 46;

/** The sprite scale a group name is drawn at. Same reading as above. */
export const PLANET_LABEL_SPRITE_SCALE = 0.05;

/**
 * Width of a name when the painted texture has not been measured: a short
 * English name is about four times wider than it is tall. A caller that
 * knows the real aspect passes it, and the wider of the two is what gets
 * measured -- guessing narrow would report a clearance that is not there.
 */
export const LABEL_ASPECT_FALLBACK = 4;

/**
 * One name needs a neighbour-sized gap or two labels fuse into a white
 * smear: the defect measured on a 500-agent inventory at opening
 * distance 85, scene radius 48, fov 46°: the GPU was fine (p95 5.9 on
 * hardware); the names were not readable. Area, not a head-count cap:
 * showing 8 of 500 would leak a count through which names remain.
 */
const LABEL_BOX_NDC = AGENT_LABEL_SPRITE_SCALE * AGENT_LABEL_SPRITE_SCALE * LABEL_ASPECT_FALLBACK;
const NEIGHBOUR_CLEARANCE = 4;
const MIN_MEAN_NDC_AREA = LABEL_BOX_NDC * NEIGHBOUR_CLEARANCE;
const FOV_HALF_TAN = Math.tan((LABEL_FOV_DEG * Math.PI) / 360);

export type Ndc = { readonly x: number; readonly y: number };

/**
 * A projected name. `aspect` is the painted texture's width over its
 * height; a caller that has not painted yet leaves it out and the
 * fallback width is used.
 */
export type LabelPoint = { readonly x: number; readonly y: number; readonly aspect?: number };

export type CameraEye = {
  readonly x: number;
  readonly y: number;
  readonly z: number;
  readonly lookX: number;
  readonly lookY: number;
  readonly lookZ: number;
  readonly fovDeg: number;
  /**
   * Width over height of the canvas the sky is drawn on -- not the window,
   * the canvas. A perspective camera divides x by this, so a rule that
   * leaves it out reads a wide screen as if it were square and reports a
   * horizontal gap that is not there.
   */
  readonly viewportAspect: number;
};

export type LabelHideReason = "distance" | "crowd";

export type LabelCrowd = {
  /** The box each of these names covers, for the kind judged after them. */
  box: LabelBox;
  /** True only when every name is printed; a partial crowd is not "shown". */
  show: boolean;
  /** Per name, in the order given: printed, or stood down for a neighbour. */
  keep: boolean[];
  hidden: number;
  reason: LabelHideReason | null;
  /** Names sharing the most crowded box, itself counted. 1 = nothing touches. */
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
  const aspect = cam.viewportAspect > 0 ? cam.viewportAspect : 1;
  return { x: camX / camZ / (tan * aspect), y: camY / camZ / tan };
}

/**
 * A name is a box, not a dot, so crowding is a box question. The disk this
 * replaces asked whether two centres were far apart; two names can clear
 * each other's disk and still print on top of one another, because a name
 * is about three times wider than that disk is across. Measured 8 Sep on
 * the 123-agent focus seat: seven overlapping pairs while the rule
 * reported none hidden.
 */
export function labelsOverlap(
  a: LabelPoint,
  b: LabelPoint,
  box: LabelBox,
  boxB: LabelBox = box,
): boolean {
  const halfW = (labelNdcWidth(a, box) + labelNdcWidth(b, boxB)) / 2;
  const halfH = (labelNdcHeight(box) + labelNdcHeight(boxB)) / 2;
  return Math.abs(a.x - b.x) < halfW && Math.abs(a.y - b.y) < halfH;
}

/**
 * What a sprite of this scale actually covers, in the same NDC the points
 * are projected into: `scale / tan(fov/2)` tall, and that over the canvas
 * aspect wide. Both halves come from the three.js sprite shader, which
 * multiplies the scale by depth and lets the projection divide it back out.
 */
export type LabelBox = {
  readonly spriteScale: number;
  readonly fovDeg: number;
  readonly viewportAspect: number;
};

export function labelNdcHeight(box: LabelBox): number {
  const tan = Math.tan((box.fovDeg * Math.PI) / 360);
  return tan > 0 ? box.spriteScale / tan : box.spriteScale;
}

function labelNdcWidth(p: LabelPoint, box: LabelBox): number {
  const aspect = p.aspect !== undefined && p.aspect > 0 ? p.aspect : LABEL_ASPECT_FALLBACK;
  const wide = box.viewportAspect > 0 ? box.viewportAspect : 1;
  return (labelNdcHeight(box) * aspect) / wide;
}

/**
 * How many names the most crowded box shares its space with, itself
 * counted. One means nothing overlaps it.
 */
export function densestOverlap(points: readonly LabelPoint[], box: LabelBox): number {
  let max = 0;
  for (let i = 0; i < points.length; i += 1) {
    let n = 1;
    for (let j = 0; j < points.length; j += 1) {
      if (i !== j && labelsOverlap(points[i]!, points[j]!, box)) n += 1;
    }
    if (n > max) max = n;
  }
  return max;
}

/**
 * Which names can be printed without any two of them touching. Taken in
 * the order the caller gives -- the ledger's order, so the same sky always
 * keeps the same names -- and a name is dropped only when it would land on
 * one already kept. The dropped ones are counted, never silently lost:
 * an unreadable name and an uncounted one are the same defect.
 */
export function readableLabels(
  points: readonly LabelPoint[],
  box: LabelBox,
  taken: readonly TakenLabel[] = [],
): { keep: boolean[]; hidden: number } {
  const keep: boolean[] = [];
  const kept: LabelPoint[] = [];
  let hidden = 0;
  for (const p of points) {
    const clearOfTaken = taken.every((t) => !labelsOverlap(p, t.at, box, t.box));
    const clear = clearOfTaken && kept.every((k) => !labelsOverlap(p, k, box));
    keep.push(clear);
    if (clear) kept.push(p);
    else hidden += 1;
  }
  return { keep, hidden };
}

/**
 * A name already on the screen, with the box it covers. Group names are
 * placed first and agent names have to clear them: judging each kind only
 * against its own left a group name and an agent name printed on the same
 * spot, which is the same smear seen from a different angle (measured on
 * the overview, 10 Sep).
 */
export type TakenLabel = { readonly at: LabelPoint; readonly box: LabelBox };

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
 * Which names stay readable where they land. Distance LOD still hides a
 * far set as a whole (reason "distance"): at that range no arrangement is
 * readable. Closer in, the set is thinned name by name instead of dropped
 * whole -- hiding fourteen readable names because two of them touch was
 * the old rule's other half of the same mistake.
 */
export function labelCrowd(
  points: readonly LabelPoint[],
  kind: LabelKind,
  cameraDistance: number,
  sceneRadius: number,
  viewportAspect: number,
  taken: readonly TakenLabel[] = [],
): LabelCrowd {
  const count = points.length;
  if (!(count > 0)) {
    return {
      box: { spriteScale: AGENT_LABEL_SPRITE_SCALE, fovDeg: LABEL_FOV_DEG, viewportAspect },
      show: true,
      keep: [],
      hidden: 0,
      reason: null,
      densest: 0,
    };
  }
  const box: LabelBox = {
    spriteScale: kind === "planet" ? PLANET_LABEL_SPRITE_SCALE : AGENT_LABEL_SPRITE_SCALE,
    fovDeg: LABEL_FOV_DEG,
    viewportAspect,
  };
  const densest = densestOverlap(points, box);
  if (!labelVisible(kind, cameraDistance, sceneRadius)) {
    return { box, show: false, keep: points.map(() => false), hidden: count, reason: "distance", densest };
  }
  const { keep, hidden } = readableLabels(points, box, taken);
  return {
    box,
    show: hidden === 0,
    keep,
    hidden,
    reason: hidden === 0 ? null : "crowd",
    densest,
  };
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
