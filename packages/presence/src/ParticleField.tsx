import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { AdditiveBlending, BufferAttribute, BufferGeometry, ShaderMaterial } from "three";
import type { PresenceState, StateParams } from "./state.ts";

export type PointsMeta = {
  version: number;
  count: number;
  bbox: { min: [number, number, number]; max: [number, number, number] };
};

const VERTEX = /* glsl */ `
attribute vec3 target;
attribute float seed;
uniform vec3 uBBoxMin;
uniform vec3 uBBoxMax;
uniform float uProgress;
uniform vec4 uState;
uniform float uTime;
uniform float uAudio;
varying float vAlpha;
vec3 decodeTarget() {
  return mix(uBBoxMin, uBBoxMax, target / 65535.0);
}
vec3 cloudPos() {
  float a = seed * 6.2831853;
  float b = fract(seed * 17.0) * 3.14159265;
  float r = 1.6 + fract(seed * 9.0) * 1.4;
  return vec3(sin(b) * cos(a), cos(b), sin(b) * sin(a)) * r;
}
vec3 spiralPos() {
  float a = seed * 12.566 + uProgress * 6.0;
  float r = mix(1.4, 0.15, uProgress);
  return vec3(cos(a) * r, (seed - 0.5) * 1.8, sin(a) * r);
}
void main() {
  vec3 dest = decodeTarget();
  dest.y += sin(uTime * 2.0 + seed * 6.2831853) * uState.z;
  vec3 chest = vec3(0.0, mix(uBBoxMin.y, uBBoxMax.y, 0.55), 0.0);
  dest = mix(dest, chest, uState.w);
  dest.y -= (1.0 - uState.x) * (uBBoxMax.y - uBBoxMin.y) * 0.35;
  vec3 p0 = cloudPos();
  vec3 p1 = spiralPos();
  vec3 p = uProgress < 0.5
    ? mix(p0, p1, uProgress * 2.0)
    : mix(p1, dest, (uProgress - 0.5) * 2.0);
  vec4 mv = modelViewMatrix * vec4(p, 1.0);
  gl_Position = projectionMatrix * mv;
  gl_PointSize = max(1.0, 180.0 / max(1.0, -mv.z));
  vAlpha = 0.55 + uAudio * 0.2;
}
`;

const FRAGMENT = /* glsl */ `
uniform vec3 uColor;
varying float vAlpha;
void main() {
  vec2 c = gl_PointCoord - vec2(0.5);
  float d = length(c);
  if (d > 0.5) discard;
  float a = (1.0 - smoothstep(0.15, 0.5, d)) * vAlpha;
  gl_FragColor = vec4(uColor, a);
}
`;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function ParticleField({
  cloud,
  meta,
  count,
  params,
  presence,
  startedAtMs,
}: {
  cloud: Uint16Array;
  meta: PointsMeta;
  count: number;
  params: StateParams;
  presence: PresenceState;
  startedAtMs: number;
}) {
  const geo = useMemo(() => {
    const geometry = new BufferGeometry();
    const n = meta.count;
    geometry.setAttribute("target", new BufferAttribute(cloud, 3));
    const seeds = new Float32Array(n);
    const rand = mulberry32(0x56455258);
    for (let i = 0; i < n; i += 1) seeds[i] = rand();
    geometry.setAttribute("seed", new BufferAttribute(seeds, 1));
    geometry.setDrawRange(0, count);
    return geometry;
  }, [cloud, meta.count, count]);

  const material = useMemo(
    () =>
      new ShaderMaterial({
        vertexShader: VERTEX,
        fragmentShader: FRAGMENT,
        transparent: true,
        depthWrite: false,
        blending: AdditiveBlending,
        uniforms: {
          uBBoxMin: { value: meta.bbox.min.slice() },
          uBBoxMax: { value: meta.bbox.max.slice() },
          uProgress: { value: 0 },
          uState: { value: [params.budgetScale, params.ringSpin, params.breathAmp, params.pullToChest] },
          uTime: { value: 0 },
          uAudio: { value: 0 },
          uColor: { value: params.coreColor.slice() },
        },
      }),
    [meta, params],
  );

  const matRef = useRef(material);
  matRef.current = material;

  useEffect(() => {
    geo.setDrawRange(0, count);
  }, [geo, count]);

  useFrame((_, dt) => {
    const elapsed = (performance.now() - startedAtMs) / 1000;
    const uniforms = matRef.current.uniforms;
    uniforms.uTime.value = elapsed;
    uniforms.uProgress.value = presence === "booting" ? Math.min(1, elapsed / 4) : 1;
    uniforms.uState.value = [params.budgetScale, params.ringSpin, params.breathAmp, params.pullToChest];
    uniforms.uColor.value = params.coreColor.slice();
    uniforms.uAudio.value = 0;
    const w = window as Window & { __veraxPushFrame?: (ms: number) => void };
    w.__veraxPushFrame?.(dt * 1000);
  });

  return <points geometry={geo} material={material} />;
}
