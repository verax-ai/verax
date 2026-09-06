import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Bloom, EffectComposer } from "@react-three/postprocessing";
import { ACESFilmicToneMapping, Group } from "three";
import { ChestCore } from "./ChestCore.tsx";
import { Figure } from "./Figure.tsx";
import { Lights } from "./Lights.tsx";
import { MatrixRain } from "./MatrixRain.tsx";
import { ParticleField, type PointsMeta } from "./ParticleField.tsx";
import { fitFromBox } from "./fit.ts";
import { createQuality, TIER_COUNTS } from "./quality.ts";
import { createPresence, PRESENCE_STATES, type PresenceState } from "./state.ts";

function assetBase(): string {
  const raw = (import.meta as { env?: { BASE_URL?: string } }).env?.BASE_URL ?? "/";
  return raw.endsWith("/") ? raw : `${raw}/`;
}

async function loadCloud(): Promise<{ cloud: Uint16Array; meta: PointsMeta }> {
  const base = assetBase();
  const [bin, meta] = await Promise.all([
    fetch(`${base}verax-points.bin`).then((r) => r.arrayBuffer()),
    fetch(`${base}verax-points.json`).then((r) => r.json() as Promise<PointsMeta>),
  ]);
  const view = new DataView(bin);
  const version = view.getUint32(0, true);
  const count = view.getUint32(4, true);
  if (version !== 1) throw new Error("points-version");
  return { cloud: new Uint16Array(bin, 32, count * 3), meta };
}

function readForcedTier(): number | null {
  const raw = new URLSearchParams(window.location.search).get("tier");
  if (!raw) return null;
  const n = Number(raw);
  return (TIER_COUNTS as readonly number[]).includes(n) ? n : null;
}

function readForcedState(): PresenceState | null {
  const raw = new URLSearchParams(window.location.search).get("state");
  if (!raw) return null;
  return (PRESENCE_STATES as readonly string[]).includes(raw) ? (raw as PresenceState) : null;
}

function readBloom(): boolean {
  return new URLSearchParams(window.location.search).get("bloom") === "1";
}

function ProceduralBreath({ children }: { children: ReactNode }) {
  const ref = useRef<Group>(null);
  useFrame(() => {
    if (!ref.current) return;
    const reduce =
      typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      ref.current.scale.set(1, 1, 1);
      ref.current.rotation.z = 0;
      return;
    }
    const t = performance.now() / 1000;
    const s = 1 + 0.02 * Math.sin(t * 1.2);
    ref.current.scale.setScalar(s);
    ref.current.rotation.z = 0.015 * Math.sin(t * 0.8);
  });
  return <group ref={ref}>{children}</group>;
}

export function Stage({
  particles = true,
  rain = true,
  breath = "presence",
}: {
  particles?: boolean;
  rain?: boolean;
  breath?: "presence" | "procedural";
} = {}) {
  const startedAtMs = useMemo(() => performance.now(), []);
  const forcedState = useMemo(() => readForcedState(), []);
  const presence = useMemo(
    () => createPresence(() => performance.now() - startedAtMs + 0, forcedState ?? "booting"),
    [startedAtMs, forcedState],
  );
  const quality = useMemo(() => createQuality(() => performance.now()), []);
  const forced = useMemo(() => readForcedTier(), []);
  const bloom = useMemo(() => readBloom(), []);
  const [state, setState] = useState<PresenceState>(presence.state);
  const [count, setCount] = useState(forced ?? quality.count);
  const [cloud, setCloud] = useState<Uint16Array | null>(null);
  const [meta, setMeta] = useState<PointsMeta | null>(null);
  const [missing, setMissing] = useState(false);
  const onMissing = useCallback(() => setMissing(true), []);

  useEffect(() => {
    void loadCloud().then((loaded) => {
      setCloud(loaded.cloud);
      setMeta(loaded.meta);
    });
  }, []);

  useEffect(() => {
    const id = window.setInterval(() => {
      setState(presence.state);
      if (forced === null) setCount(quality.count);
    }, 100);
    return () => window.clearInterval(id);
  }, [presence, quality, forced]);

  useEffect(() => {
    const w = window as Window & { __veraxPushFrame?: (ms: number) => void; __veraxTier?: number };
    w.__veraxPushFrame = (ms: number) => {
      quality.push(ms);
      w.__veraxTier = forced ?? quality.count;
    };
    w.__veraxTier = forced ?? quality.count;
    return () => {
      delete w.__veraxPushFrame;
    };
  }, [quality, forced]);

  const params = presence.params();
  const floor = TIER_COUNTS[TIER_COUNTS.length - 1] ?? 5_000;
  const low = count <= floor;
  const fit = meta ? fitFromBox(meta.bbox) : null;

  return (
    <div className="stage">
      {missing ? <p className="model-missing">model missing, run pack-model</p> : null}
      {rain ? <MatrixRain on={!low} /> : null}
      <Canvas
        camera={{ position: [0, 0.2, 5.4], fov: 44 }}
        gl={{ antialias: false, toneMapping: ACESFilmicToneMapping, toneMappingExposure: 1.05 }}
      >
        <Lights color={params.coreColor} />
        {cloud && meta && fit ? (
          <group position={fit.position} scale={fit.scale}>
            {breath === "procedural" ? (
              <ProceduralBreath>
                <Figure presence={state} startedAtMs={startedAtMs} onMissing={onMissing} assetBase={assetBase()} />
                {particles ? (
                  <ParticleField
                    cloud={cloud}
                    meta={meta}
                    count={Math.min(count, meta.count)}
                    params={params}
                    presence={state}
                    startedAtMs={startedAtMs}
                  />
                ) : null}
                <ChestCore
                  box={meta.bbox}
                  color={params.coreColor}
                  ringSpin={0}
                  breathAmp={0}
                />
              </ProceduralBreath>
            ) : (
              <>
                <Figure presence={state} startedAtMs={startedAtMs} onMissing={onMissing} assetBase={assetBase()} />
                {particles ? (
                  <ParticleField
                    cloud={cloud}
                    meta={meta}
                    count={Math.min(count, meta.count)}
                    params={params}
                    presence={state}
                    startedAtMs={startedAtMs}
                  />
                ) : null}
                <ChestCore
                  box={meta.bbox}
                  color={params.coreColor}
                  ringSpin={params.ringSpin}
                  breathAmp={params.breathAmp}
                />
              </>
            )}
          </group>
        ) : null}
        {bloom ? (
          <EffectComposer>
            <Bloom intensity={0.35} luminanceThreshold={0.2} mipmapBlur />
          </EffectComposer>
        ) : null}
      </Canvas>
    </div>
  );
}
