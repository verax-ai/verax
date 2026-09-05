import { useCallback, useEffect, useMemo, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { ACESFilmicToneMapping, Vector3 } from "three";
import {
  ChestCore,
  Figure,
  Lights,
  MatrixRain,
  ParticleField,
  createPresence,
  createQuality,
  fitFromBox,
  type PointsMeta,
  type PresenceState,
} from "@verax-ai/presence";
import anchors from "./anchors.json";
import { copyFor, readLang, type Copy, type Lang } from "./lang.ts";
import { COPY_GROUP, LABEL_IDS, LEFT_LABELS, LINK_HREF, RIGHT_LABELS, type LabelId } from "./parts.ts";

function assetBase(): string {
  const raw = (import.meta as { env?: { BASE_URL?: string } }).env?.BASE_URL ?? "/";
  return raw.endsWith("/") ? raw : `${raw}/`;
}

const BASE = assetBase();

type AnchorMap = Record<string, [number, number, number]>;

function asAnchorMap(raw: Record<string, number[]>): AnchorMap {
  const out: AnchorMap = {};
  for (const [id, p] of Object.entries(raw)) {
    if (p.length < 3) throw new Error(`anchor:${id}`);
    out[id] = [p[0]!, p[1]!, p[2]!];
  }
  return out;
}

const ANCHORS = asAnchorMap(anchors);

async function loadCloud(): Promise<{ cloud: Uint16Array; meta: PointsMeta }> {
  const [bin, meta] = await Promise.all([
    fetch(`${BASE}verax-points.bin`).then((r) => r.arrayBuffer()),
    fetch(`${BASE}verax-points.json`).then((r) => r.json() as Promise<PointsMeta>),
  ]);
  const view = new DataView(bin);
  if (view.getUint32(0, true) !== 1) throw new Error("points-version");
  const count = view.getUint32(4, true);
  return { cloud: new Uint16Array(bin, 32, count * 3), meta };
}

function reducedMotion(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function hrefFor(link: string): string | null {
  return LINK_HREF[link] ?? (link === "—" ? null : `https://${link}/`);
}

function Projector({
  points,
  on,
}: {
  points: AnchorMap;
  on: (next: Record<string, { x: number; y: number }>) => void;
}) {
  useFrame(({ camera, size }) => {
    const next: Record<string, { x: number; y: number }> = {};
    const v = new Vector3();
    for (const [id, p] of Object.entries(points)) {
      v.set(p[0], p[1], p[2]).project(camera);
      next[id] = { x: (v.x * 0.5 + 0.5) * size.width, y: (-v.y * 0.5 + 0.5) * size.height };
    }
    on(next);
  });
  return null;
}

function Card({ copy, group }: { copy: Copy; group: string }) {
  const link = copy[`${group}.link`] ?? "—";
  const href = hrefFor(link);
  return (
    <section className="card" aria-live="polite">
      <h2>
        {copy[`${group}.part`]} · {copy[`${group}.prod`]}
      </h2>
      <p className="q">{copy[`${group}.q`]}</p>
      <p>{copy[`${group}.what`]}</p>
      <p className="status">{copy[`${group}.status`]}</p>
      {href ? (
        <p>
          <a href={href} target="_blank" rel="noreferrer">
            {link}
          </a>
        </p>
      ) : (
        <p className="status">{link}</p>
      )}
    </section>
  );
}

export function App() {
  const [lang, setLang] = useState<Lang>("en");
  const copy = useMemo(() => copyFor(lang), [lang]);
  const quiet = useMemo(() => reducedMotion(), []);
  const startedAtMs = useMemo(() => performance.now(), []);
  const presence = useMemo(
    () => createPresence(() => performance.now() - startedAtMs, quiet ? "idle" : "booting"),
    [startedAtMs, quiet],
  );
  const quality = useMemo(() => createQuality(() => performance.now()), []);
  const [state, setState] = useState<PresenceState>(presence.state);
  const [count, setCount] = useState(quality.count);
  const [cloud, setCloud] = useState<Uint16Array | null>(null);
  const [meta, setMeta] = useState<PointsMeta | null>(null);
  const [missing, setMissing] = useState(false);
  const [selected, setSelected] = useState<LabelId | "whole">("whole");
  const [flash, setFlash] = useState(0);
  const [screen, setScreen] = useState<Record<string, { x: number; y: number }>>({});
  const onMissing = useCallback(() => setMissing(true), []);

  useEffect(() => {
    const next = readLang();
    setLang(next);
    document.documentElement.lang = next;
    document.title = next === "tr" ? copyFor("tr").title : "Verax — one body, six parts";
  }, []);

  useEffect(() => {
    void loadCloud().then((loaded) => {
      setCloud(loaded.cloud);
      setMeta(loaded.meta);
    });
  }, []);

  useEffect(() => {
    const id = window.setInterval(() => {
      setState(presence.state);
      setCount(quality.count);
    }, 100);
    return () => window.clearInterval(id);
  }, [presence, quality]);

  const params = presence.params();
  const fit = meta ? fitFromBox(meta.bbox) : null;
  const worldAnchors = useMemo(() => {
    if (!fit) return {};
    const out: AnchorMap = {};
    for (const [id, p] of Object.entries(ANCHORS)) {
      out[id] = [p[0] * fit.scale + fit.position[0], p[1] * fit.scale + fit.position[1], p[2] * fit.scale + fit.position[2]];
    }
    return out;
  }, [fit]);

  const group = selected === "whole" ? "whole" : COPY_GROUP[selected];
  const pullLocal =
    selected === "whole" ? undefined : ANCHORS[selected];
  const pullParams = pullLocal ? { ...params, pullToChest: 0.22 } : params;

  const pick = (id: LabelId | "whole") => {
    setSelected(id);
    setFlash((n) => n + 1);
  };

  return (
    <div className="page">
      {missing ? <p className="model-missing">model missing, run pack-model</p> : null}
      <MatrixRain on={!quiet} />
      <div className="figure-wrap">
        <Canvas
          camera={{ position: [0, 0.2, 5.4], fov: 44 }}
          gl={{ antialias: false, toneMapping: ACESFilmicToneMapping, toneMappingExposure: 1.05 }}
        >
          <Lights color={params.coreColor} />
          {cloud && meta && fit ? (
            <group position={fit.position} scale={fit.scale}>
              <Figure presence={state} startedAtMs={startedAtMs} onMissing={onMissing} assetBase={BASE} />
              <ParticleField
                cloud={cloud}
                meta={meta}
                count={Math.min(count, meta.count)}
                params={pullParams}
                presence={state}
                startedAtMs={startedAtMs}
                pullTarget={pullLocal}
              />
              <ChestCore
                key={flash}
                box={meta.bbox}
                color={params.coreColor}
                ringSpin={params.ringSpin + (flash ? 1.5 : 0)}
                breathAmp={params.breathAmp}
              />
            </group>
          ) : null}
          <Projector points={worldAnchors} on={setScreen} />
        </Canvas>
      </div>
      <header className="intro">
        <h1>{copy.title}</h1>
        <p>{copy.lede}</p>
      </header>
      <div className="overlay">
        <div className="col">
          {LEFT_LABELS.map((id) => (
            <button
              key={id}
              type="button"
              className={selected === id ? "label on" : "label"}
              onMouseEnter={() => pick(id)}
              onFocus={() => pick(id)}
              onClick={() => pick(id)}
            >
              {copy[`${COPY_GROUP[id]}.part`]}
            </button>
          ))}
        </div>
        <div />
        <div className="col right">
          {RIGHT_LABELS.map((id) => (
            <button
              key={id}
              type="button"
              className={selected === id ? "label on" : "label"}
              onMouseEnter={() => pick(id)}
              onFocus={() => pick(id)}
              onClick={() => pick(id)}
            >
              {copy[`${COPY_GROUP[id]}.part`]}
            </button>
          ))}
        </div>
      </div>
      <svg className="lines" aria-hidden="true">
        {LABEL_IDS.map((id) => {
          const p = screen[id];
          if (!p) return null;
          const side = LEFT_LABELS.includes(id) ? 120 : window.innerWidth - 120;
          return <line key={id} x1={side} y1={p.y} x2={p.x} y2={p.y} stroke="#5CE1FF" strokeOpacity="0.45" />;
        })}
      </svg>
      <Card copy={copy} group={group} />
      <a className="cta" href="https://verax-ai.com/" target="_blank" rel="noreferrer">
        {copy.cta} → verax-ai.com
      </a>
    </div>
  );
}
