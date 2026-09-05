import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
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
type ScreenMap = Record<string, { x: number; y: number }>;
type Laid = { top: number; midY: number; edgeX: number; elbowX: number };

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

function useNarrow(): boolean {
  const [narrow, setNarrow] = useState(
    () => typeof window !== "undefined" && window.matchMedia("(max-width: 800px)").matches,
  );
  useEffect(() => {
    const mq = window.matchMedia("(max-width: 800px)");
    const on = () => setNarrow(mq.matches);
    on();
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return narrow;
}

function placeColumn(ids: readonly LabelId[], screen: ScreenMap, heights: Record<string, number>): Record<string, number> {
  const items = ids
    .map((id) => {
      const p = screen[id];
      const h = heights[id];
      if (!p || h == null) return null;
      return { id, h, desired: p.y - h / 2 };
    })
    .filter((x): x is { id: LabelId; h: number; desired: number } => x !== null)
    .sort((a, b) => a.desired - b.desired);
  const tops: Record<string, number> = {};
  let prevBottom = Number.NEGATIVE_INFINITY;
  for (const item of items) {
    let top = item.desired;
    if (top < prevBottom + 8) top = prevBottom + 8;
    tops[item.id] = top;
    prevBottom = top + item.h;
  }
  return tops;
}

function Projector({
  points,
  on,
}: {
  points: AnchorMap;
  on: (next: ScreenMap) => void;
}) {
  const prev = useRef<ScreenMap>({});
  useFrame(({ camera, size, gl }) => {
    const next: ScreenMap = {};
    const v = new Vector3();
    for (const [id, p] of Object.entries(points)) {
      v.set(p[0], p[1], p[2]).project(camera);
      next[id] = { x: (v.x * 0.5 + 0.5) * size.width, y: (-v.y * 0.5 + 0.5) * size.height };
    }
    let moved = Object.keys(next).length !== Object.keys(prev.current).length;
    if (!moved) {
      for (const [id, b] of Object.entries(next)) {
        const a = prev.current[id];
        if (!a || Math.abs(a.x - b.x) > 0.5 || Math.abs(a.y - b.y) > 0.5) {
          moved = true;
          break;
        }
      }
    }
    if (!moved) return;
    prev.current = next;
    on(next);
    const r = gl.domElement.getBoundingClientRect();
    const view: ScreenMap = {};
    for (const [id, p] of Object.entries(next)) {
      view[id] = { x: p.x + r.left, y: p.y + r.top };
    }
    (window as Window & { __veraxAnchors?: ScreenMap }).__veraxAnchors = view;
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
  const [screen, setScreen] = useState<ScreenMap>({});
  const [laid, setLaid] = useState<Record<string, Laid>>({});
  const narrow = useNarrow();
  const overlayRef = useRef<HTMLDivElement>(null);
  const labelRefs = useRef<Partial<Record<LabelId, HTMLButtonElement | null>>>({});
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

  useLayoutEffect(() => {
    if (narrow) {
      setLaid({});
      return;
    }
    const overlay = overlayRef.current;
    if (!overlay) return;
    const rem = parseFloat(getComputedStyle(document.documentElement).fontSize);
    const inset = 1.5 * rem;
    const stageW = overlay.clientWidth;
    const heights: Record<string, number> = {};
    const widths: Record<string, number> = {};
    for (const id of LABEL_IDS) {
      const el = labelRefs.current[id];
      if (!el) continue;
      heights[id] = el.offsetHeight;
      widths[id] = el.offsetWidth;
    }
    const tops = { ...placeColumn(LEFT_LABELS, screen, heights), ...placeColumn(RIGHT_LABELS, screen, heights) };
    const next: Record<string, Laid> = {};
    for (const id of LABEL_IDS) {
      const p = screen[id];
      const top = tops[id];
      const h = heights[id];
      const w = widths[id];
      if (!p || top == null || h == null || w == null) continue;
      const left = LEFT_LABELS.includes(id);
      const edgeX = left ? inset + w : stageW - inset - w;
      next[id] = { top, midY: top + h / 2, edgeX, elbowX: left ? edgeX + 22 : edgeX - 22 };
    }
    setLaid(next);
  }, [screen, narrow]);

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
  const pullLocal = selected === "whole" ? undefined : ANCHORS[selected];
  const pullParams = pullLocal ? { ...params, pullToChest: 0.22 } : params;

  const pick = (id: LabelId | "whole") => {
    setSelected(id);
    setFlash((n) => n + 1);
  };

  return (
    <div className="page">
      {missing ? <p className="model-missing">model missing, run pack-model</p> : null}
      <MatrixRain on={!quiet} />
      <header className="intro">
        <h1>{copy.title}</h1>
        <p>{copy.lede}</p>
      </header>
      <div className="stage">
        <div className="figure-wrap">
          <Canvas
            camera={{ position: [0, 0.15, 6.4], fov: 44 }}
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
                  box={meta.bbox}
                  color={params.coreColor}
                  ringSpin={params.ringSpin}
                  breathAmp={params.breathAmp}
                  flash={flash}
                />
              </group>
            ) : null}
            <Projector points={worldAnchors} on={setScreen} />
          </Canvas>
        </div>
        <div className="overlay" ref={overlayRef}>
          {LABEL_IDS.map((id) => {
            const side = LEFT_LABELS.includes(id) ? "left" : "right";
            const pos = laid[id];
            return (
              <button
                key={id}
                ref={(el) => {
                  labelRefs.current[id] = el;
                }}
                type="button"
                data-anchor={id}
                className={selected === id ? `label ${side} on` : `label ${side}`}
                style={narrow || !pos ? undefined : { top: pos.top }}
                onMouseEnter={() => pick(id)}
                onFocus={() => pick(id)}
                onClick={() => pick(id)}
              >
                {copy[`${COPY_GROUP[id]}.part`]}
              </button>
            );
          })}
        </div>
        {narrow ? null : (
          <svg className="lines" aria-hidden="true">
            {LABEL_IDS.map((id) => {
              const p = screen[id];
              const pos = laid[id];
              if (!p || !pos) return null;
              const r = selected === id ? 4 * 1.35 : 4;
              return (
                <g key={id}>
                  <polyline
                    points={`${pos.edgeX},${pos.midY} ${pos.elbowX},${pos.midY} ${p.x},${p.y}`}
                    fill="none"
                    stroke="#5CE1FF"
                    strokeOpacity="0.45"
                  />
                  <circle cx={p.x} cy={p.y} r={r} fill="#5CE1FF" fillOpacity="0.9" />
                </g>
              );
            })}
          </svg>
        )}
        <Card copy={copy} group={group} />
      </div>
      <footer className="bar">
        <p className="origin">Figure: operator-generated model</p>
        <a className="cta" href="https://verax-ai.com/" target="_blank" rel="noreferrer">
          {copy.cta} → verax-ai.com
        </a>
      </footer>
    </div>
  );
}
