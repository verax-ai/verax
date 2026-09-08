export const ZOOM_MIN = 45;
export const ZOOM_MAX = 700;
export const DAMP = 0.92;
export const LERP_ANGLE = 0.045;
export const LERP_ZOOM = 0.055;

export type Orbit = {
  yaw: number;
  pitch: number;
  distance: number;
  targetYaw: number;
  targetPitch: number;
  targetDistance: number;
  velYaw: number;
  velPitch: number;
};

export function clampZoom(distance: number): number {
  return Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, distance));
}

export function clampPitch(pitch: number): number {
  return Math.max(-0.7, Math.min(0.9, pitch));
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
  orbit.pitch = clampPitch(orbit.pitch);
  orbit.distance = clampZoom(orbit.distance);
  void sway;
}

export function cameraPosition(orbit: Orbit, lookAt = { x: 0, y: 0, z: 0 }): {
  x: number;
  y: number;
  z: number;
  lookX: number;
  lookY: number;
  lookZ: number;
} {
  const py = orbit.pitch;
  const yy = orbit.yaw;
  const d = orbit.distance;
  return {
    x: lookAt.x + Math.sin(yy) * Math.cos(py) * d,
    y: lookAt.y + Math.sin(py) * d,
    z: lookAt.z + Math.cos(yy) * Math.cos(py) * d,
    lookX: lookAt.x,
    lookY: lookAt.y,
    lookZ: lookAt.z,
  };
}
