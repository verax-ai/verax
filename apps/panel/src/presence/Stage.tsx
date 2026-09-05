import { useEffect, useMemo, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { Bloom, EffectComposer } from "@react-three/postprocessing";
import { MatrixRain } from "./MatrixRain.tsx";
import { ParticleField, type PointsMeta } from "./ParticleField.tsx";
import { createPresence, type PresenceState } from "./state.ts";
import { createQuality } from "./quality.ts";

async function loadCloud(): Promise<{ cloud: Uint16Array; meta: PointsMeta }> {
  const [bin, meta] = await Promise.all([
    fetch("/verax-points.bin").then((r) => r.arrayBuffer()),
    fetch("/verax-points.json").then((r) => r.json() as Promise<PointsMeta>),
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
  return n === 60_000 || n === 30_000 || n === 15_000 ? n : null;
}

export function Stage() {
  const startedAtMs = useMemo(() => performance.now(), []);
  const presence = useMemo(() => createPresence(() => performance.now() - startedAtMs + 0), [startedAtMs]);
  const quality = useMemo(() => createQuality(() => performance.now()), []);
  const forced = useMemo(() => readForcedTier(), []);
  const [state, setState] = useState<PresenceState>(presence.state);
  const [count, setCount] = useState(forced ?? quality.count);
  const [cloud, setCloud] = useState<Uint16Array | null>(null);
  const [meta, setMeta] = useState<PointsMeta | null>(null);

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
  const low = count <= 15_000;

  return (
    <div className="stage">
      <MatrixRain on={!low} />
      <Canvas camera={{ position: [0, 0.4, 3.2], fov: 45 }} gl={{ antialias: false }}>
        {cloud && meta ? (
          <ParticleField
            cloud={cloud}
            meta={meta}
            count={Math.min(count, meta.count)}
            params={params}
            presence={state}
            startedAtMs={startedAtMs}
          />
        ) : null}
        {low ? null : (
          <EffectComposer>
            <Bloom intensity={0.35} luminanceThreshold={0.2} mipmapBlur />
          </EffectComposer>
        )}
      </Canvas>
    </div>
  );
}
