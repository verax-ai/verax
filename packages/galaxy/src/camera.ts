/**
 * Closest camera-to-target distance.
 *
 * Was 45. The sky radius is 48, so that floor sat outside the sky: a
 * group lives in a ~4.5 disk around its planet, and from outside the
 * sky that disk is one smear. The crowd rule was right; the seat was
 * wrong. 6 sits just outside a packed group and well in front of the
 * canvas near plane (0.1). It is inside the sky, which is the point.
 */
export const ZOOM_MIN = 6;
export const ZOOM_MAX = 700;
/** Matches the Canvas near plane. The camera must stay in front of it. */
export const CAMERA_NEAR = 0.1;
/**
 * How far a look-at may sit from the origin. Planets land at 48 * 1.15
 * (~55); twice the sky radius keeps a real planet and rejects a runaway.
 */
export const LOOK_BOUND = 96;
/** World gap between the outermost group member and the camera seat. */
export const FOCUS_CLEARANCE = 3;
export const DAMP = 0.92;
export const LERP_ANGLE = 0.045;
export const LERP_ZOOM = 0.055;
export const LERP_LOOK = 0.08;

export type Point3 = { x: number; y: number; z: number };

export type Orbit = {
  yaw: number;
  pitch: number;
  distance: number;
  targetYaw: number;
  targetPitch: number;
  targetDistance: number;
  velYaw: number;
  velPitch: number;
  lookX: number;
  lookY: number;
  lookZ: number;
  targetLookX: number;
  targetLookY: number;
  targetLookZ: number;
};

export type FocusSeat = {
  target: Point3;
  distance: number;
};

export function clampZoom(distance: number): number {
  return Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, distance));
}

export function clampPitch(pitch: number): number {
  return Math.max(-0.7, Math.min(0.9, pitch));
}

/** Keep a look-at on a real record. A non-finite or runaway point is not one. */
export function clampLookAt(at: Point3): Point3 {
  const x = Number.isFinite(at.x) ? at.x : 0;
  const y = Number.isFinite(at.y) ? at.y : 0;
  const z = Number.isFinite(at.z) ? at.z : 0;
  const r = Math.hypot(x, y, z);
  if (!(r > LOOK_BOUND)) return { x, y, z };
  const s = LOOK_BOUND / r;
  return { x: x * s, y: y * s, z: z * s };
}

/**
 * Camera seat for a planet's own neighborhood.
 * The target is the planet record's position — not a made-up midpoint.
 * Distance sits outside the group so names can resolve, inside the old
 * scene-scale floor that kept every group as a smear.
 */
export function focusOrbit(planetAt: Point3, groupRadius: number): FocusSeat {
  const target = clampLookAt(planetAt);
  const radius = Number.isFinite(groupRadius) && groupRadius > 0 ? groupRadius : 0;
  const raw = Math.max(ZOOM_MIN, CAMERA_NEAR + radius, radius + FOCUS_CLEARANCE);
  return { target, distance: clampZoom(raw) };
}

export function aimOrbit(orbit: Orbit, seat: FocusSeat, reducedMotion: boolean): void {
  orbit.targetLookX = seat.target.x;
  orbit.targetLookY = seat.target.y;
  orbit.targetLookZ = seat.target.z;
  orbit.targetDistance = seat.distance;
  if (!reducedMotion) return;
  orbit.lookX = seat.target.x;
  orbit.lookY = seat.target.y;
  orbit.lookZ = seat.target.z;
  orbit.distance = seat.distance;
}

export function createOrbit(distance = 120): Orbit {
  const d = clampZoom(distance);
  return {
    yaw: 0,
    pitch: 0.62,
    distance: d,
    targetYaw: 0,
    targetPitch: 0.62,
    targetDistance: d,
    velYaw: 0,
    velPitch: 0,
    lookX: 0,
    lookY: 0,
    lookZ: 0,
    targetLookX: 0,
    targetLookY: 0,
    targetLookZ: 0,
  };
}

export function nudgeOrbit(orbit: Orbit, dx: number, dy: number, dragging: boolean): void {
  if (!dragging) return;
  orbit.targetYaw += dx;
  orbit.targetPitch = clampPitch(orbit.targetPitch + dy);
  orbit.velYaw = dx;
  orbit.velPitch = dy;
}

export function zoomOrbit(orbit: Orbit, delta: number): void {
  orbit.targetDistance = clampZoom(orbit.targetDistance + delta);
}

/** One frame. Reduced motion freezes spin and inertia; the scene stays readable. */
export function stepOrbit(orbit: Orbit, reducedMotion: boolean, nowMs: number): void {
  if (reducedMotion) {
    orbit.velYaw = 0;
    orbit.velPitch = 0;
    orbit.yaw = orbit.targetYaw;
    orbit.pitch = orbit.targetPitch;
    orbit.distance = orbit.targetDistance;
    orbit.lookX = orbit.targetLookX;
    orbit.lookY = orbit.targetLookY;
    orbit.lookZ = orbit.targetLookZ;
    return;
  }
  if (!orbit.velYaw && !orbit.velPitch) {
    // coast already applied when the pointer is up
  } else {
    orbit.targetYaw += orbit.velYaw;
    orbit.targetPitch = clampPitch(orbit.targetPitch + orbit.velPitch);
    orbit.velYaw *= DAMP;
    orbit.velPitch *= DAMP;
    if (Math.abs(orbit.velYaw) < 1e-5) orbit.velYaw = 0;
    if (Math.abs(orbit.velPitch) < 1e-5) orbit.velPitch = 0;
  }
  const sway = 0.0087 * Math.sin(nowMs * 0.00015);
  orbit.yaw += (orbit.targetYaw - orbit.yaw) * LERP_ANGLE;
  orbit.pitch += (orbit.targetPitch - orbit.pitch) * LERP_ANGLE;
  orbit.distance += (orbit.targetDistance - orbit.distance) * LERP_ZOOM;
  orbit.lookX += (orbit.targetLookX - orbit.lookX) * LERP_LOOK;
  orbit.lookY += (orbit.targetLookY - orbit.lookY) * LERP_LOOK;
  orbit.lookZ += (orbit.targetLookZ - orbit.lookZ) * LERP_LOOK;
  orbit.pitch = clampPitch(orbit.pitch);
  orbit.distance = clampZoom(orbit.distance);
  const look = clampLookAt({ x: orbit.lookX, y: orbit.lookY, z: orbit.lookZ });
  orbit.lookX = look.x;
  orbit.lookY = look.y;
  orbit.lookZ = look.z;
  void sway;
}

export function orbitLook(orbit: Orbit): Point3 {
  return { x: orbit.lookX, y: orbit.lookY, z: orbit.lookZ };
}

export function cameraPosition(orbit: Orbit, lookAt?: Point3): {
  x: number;
  y: number;
  z: number;
  lookX: number;
  lookY: number;
  lookZ: number;
} {
  const at = lookAt ?? orbitLook(orbit);
  const py = orbit.pitch;
  const yy = orbit.yaw;
  const d = orbit.distance;
  return {
    x: at.x + Math.sin(yy) * Math.cos(py) * d,
    y: at.y + Math.sin(py) * d,
    z: at.z + Math.cos(yy) * Math.cos(py) * d,
    lookX: at.x,
    lookY: at.y,
    lookZ: at.z,
  };
}
