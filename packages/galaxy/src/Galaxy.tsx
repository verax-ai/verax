import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Bloom, EffectComposer } from "@react-three/postprocessing";
import { CanvasTexture, Color, DoubleSide, Group, InstancedMesh, NoToneMapping, Object3D, type Mesh } from "three";
import { cameraPosition, createOrbit, nudgeOrbit, stepOrbit, zoomOrbit, type Orbit } from "./camera.ts";
import { UNMEASURED_RGB, type Appearance } from "./draw.ts";
import { dustPositions } from "./dust.ts";
import {
  AGENT_LABEL_NDC_HEIGHT,
  LABEL_FOV_DEG,
  labelAspect,
  labelCrowd,
  labelText,
  paintLabel,
  projectNdc,
  type LabelHideReason,
} from "./labels.ts";
import type { GalaxyModel } from "./model.ts";
import { defaultOpen, easeOpen, mix3, parkPoint, readOpenQuery, stepOpen } from "./open.ts";
import { placeScene, SCENE_RADIUS, type PlacedScene } from "./place.ts";
import type { Point3 } from "./address.ts";
import { galaxyTier, readForcedTier } from "./quality.ts";

export type GalaxySelect = { kind: "star" | "planet" | "agent" | "core"; id: string };

export type GalaxyProps = {
  model: GalaxyModel;
  reducedMotion?: boolean;
  onSelect?: (hit: GalaxySelect) => void;
  /** 0 = closed sphere, 1 = open. Omit to let click own the target. */
  open?: number;
  /** Data arrived. Until then the closed sphere spins and ignores click. */
  ready?: boolean;
  /** Template with `{n}`. Shown only when names are hidden. */
  hiddenLabelsText?: string;
};

function readReduced(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function rgb(a: Appearance): Color {
  return new Color(a.color.r, a.color.g, a.color.b);
}

function FrameSampler() {
  useFrame((_, dt) => {
    const w = window as Window & { __veraxPushFrame?: (ms: number) => void };
    w.__veraxPushFrame?.(dt * 1000);
  });
  return null;
}

function OrbitRig({
  orbit,
  reducedMotion,
}: {
  orbit: Orbit;
  reducedMotion: boolean;
}) {
  const { camera } = useThree();
  useFrame(() => {
    stepOrbit(orbit, reducedMotion, typeof performance !== "undefined" ? performance.now() : 0);
    const p = cameraPosition(orbit);
    camera.position.set(p.x, p.y, p.z);
    camera.lookAt(p.lookX, p.lookY, p.lookZ);
  });
  return null;
}

function OpenDriver({
  target,
  reducedMotion,
  openRef,
}: {
  target: number;
  reducedMotion: boolean;
  openRef: { current: number };
}) {
  useFrame((_, dt) => {
    openRef.current = stepOpen(openRef.current, target, dt * 1000, reducedMotion);
  });
  return null;
}

function Flying({
  id,
  dest,
  openRef,
  reducedMotion,
  children,
}: {
  id: string;
  dest: { x: number; y: number; z: number };
  openRef: { current: number };
  reducedMotion: boolean;
  children: React.ReactNode;
}) {
  const g = useRef<Group>(null);
  const park = useMemo(() => parkPoint(id), [id]);
  useFrame(() => {
    if (!g.current) return;
    const t = easeOpen(openRef.current, reducedMotion);
    const at = mix3(park, dest, t);
    g.current.position.set(at.x, at.y, at.z);
    const s = 0.14 + 0.86 * t;
    g.current.scale.setScalar(s);
  });
  return <group ref={g}>{children}</group>;
}

function DustLayer({
  count,
  reducedMotion,
  openRef,
}: {
  count: number;
  reducedMotion: boolean;
  openRef: { current: number };
}) {
  const mesh = useRef<InstancedMesh>(null);
  const positions = useMemo(() => dustPositions(count === 20_000 ? 0 : count === 10_000 ? 1 : 2, SCENE_RADIUS), [count]);
  const parks = useMemo(() => {
    const out = new Float32Array(count * 3);
    for (let i = 0; i < count; i += 1) {
      const p = parkPoint(`dust:${i}`);
      out[i * 3] = p.x;
      out[i * 3 + 1] = p.y;
      out[i * 3 + 2] = p.z;
    }
    return out;
  }, [count]);
  const dummy = useMemo(() => new Object3D(), []);
  const color = useMemo(() => new Color(0.18, 0.12, 0.28), []);
  const lastT = useRef(-1);
  useEffect(() => {
    lastT.current = -1;
  }, [count]);
  useFrame(() => {
    const m = mesh.current;
    if (!m) return;
    const t = easeOpen(openRef.current, reducedMotion);
    if (Math.abs(t - lastT.current) > 1e-4) {
      for (let i = 0; i < count; i += 1) {
        dummy.position.set(
          (parks[i * 3] ?? 0) + ((positions[i * 3] ?? 0) - (parks[i * 3] ?? 0)) * t,
          (parks[i * 3 + 1] ?? 0) + ((positions[i * 3 + 1] ?? 0) - (parks[i * 3 + 1] ?? 0)) * t,
          (parks[i * 3 + 2] ?? 0) + ((positions[i * 3 + 2] ?? 0) - (parks[i * 3 + 2] ?? 0)) * t,
        );
        dummy.scale.setScalar(0.22);
        dummy.updateMatrix();
        m.setMatrixAt(i, dummy.matrix);
        m.setColorAt(i, color);
      }
      m.instanceMatrix.needsUpdate = true;
      if (m.instanceColor) m.instanceColor.needsUpdate = true;
      lastT.current = t;
    }
    if (!reducedMotion) m.rotation.y += 0.00015 * (1 - t * 0.7);
  });
  return (
    <instancedMesh ref={mesh} args={[undefined, undefined, count]} frustumCulled={false}>
      <tetrahedronGeometry args={[0.25]} />
      <meshBasicMaterial transparent opacity={0.22} depthWrite={false} />
    </instancedMesh>
  );
}

function CoreMesh({
  look,
  reducedMotion,
  openRef,
  onSelect,
}: {
  look: Appearance;
  reducedMotion: boolean;
  openRef: { current: number };
  onSelect?: (hit: GalaxySelect) => void;
}) {
  const ref = useRef<Mesh>(null);
  useFrame(() => {
    if (!ref.current) return;
    const t = easeOpen(openRef.current, reducedMotion);
    const pulse = reducedMotion ? look.size : look.size * (0.96 + 0.04 * Math.sin((performance.now() / 1000) * 1.1));
    const closed = 1.15 + (1 - t) * 0.2;
    ref.current.scale.setScalar((look.unmeasured ? 1 : pulse) * closed);
    if (!reducedMotion && t < 1) ref.current.rotation.y += 0.012 * (1 - t);
  });
  const c = look.unmeasured ? new Color(UNMEASURED_RGB.r, UNMEASURED_RGB.g, UNMEASURED_RGB.b) : rgb(look);
  return (
    <mesh
      ref={ref}
      name="core"
      userData={{ kind: "core", id: "core" }}
      onClick={(e) => {
        e.stopPropagation();
        onSelect?.({ kind: "core", id: "core" });
      }}
    >
      <sphereGeometry args={[2.4, 24, 20]} />
      <meshBasicMaterial color={c} transparent opacity={look.unmeasured ? 0.35 : 0.85} />
    </mesh>
  );
}

function PlanetMeshes({
  placed,
  reducedMotion,
  openRef,
  onSelect,
}: {
  placed: PlacedScene["planets"];
  reducedMotion: boolean;
  openRef: { current: number };
  onSelect?: (hit: GalaxySelect) => void;
}) {
  return (
    <group>
      {placed.map((p) => (
        <Flying key={p.id} id={`planet:${p.id}`} dest={p.at} openRef={openRef} reducedMotion={reducedMotion}>
          <mesh
            name={`planet:${p.id}`}
            userData={{ kind: "planet", id: p.id }}
            onClick={(e) => {
              e.stopPropagation();
              onSelect?.({ kind: "planet", id: p.id });
            }}
          >
            <sphereGeometry args={[p.look.size * 0.26, 12, 10]} />
            <meshBasicMaterial
              color={rgb(p.look)}
              transparent
              opacity={p.look.unmeasured ? 0.35 : 0.9}
              depthWrite={false}
            />
          </mesh>
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <ringGeometry args={[p.look.size * 0.95, p.look.size * 1.12, 40]} />
            <meshBasicMaterial
              color={rgb(p.look)}
              transparent
              opacity={p.look.unmeasured ? 0.2 : 0.55}
              side={DoubleSide}
              depthWrite={false}
            />
          </mesh>
          {p.ring && !p.ring.unmeasured ? (
            <mesh rotation={[Math.PI / 2, 0, 0]}>
              <ringGeometry args={[p.ring.size * 1.2, p.ring.size * 1.35, 48]} />
              <meshBasicMaterial
                color={rgb(p.ring)}
                transparent
                opacity={0.35}
                side={DoubleSide}
                depthWrite={false}
              />
            </mesh>
          ) : null}
        </Flying>
      ))}
    </group>
  );
}

function StarPoints({
  placed,
  reducedMotion,
  openRef,
  onSelect,
}: {
  placed: PlacedScene["stars"];
  reducedMotion: boolean;
  openRef: { current: number };
  onSelect?: (hit: GalaxySelect) => void;
}) {
  return (
    <group>
      {placed.map((s) => (
        <Flying key={s.id} id={s.id} dest={s.at} openRef={openRef} reducedMotion={reducedMotion}>
          <mesh
            name={`star:${s.id}`}
            userData={{ kind: "star", id: s.id }}
            onClick={(e) => {
              e.stopPropagation();
              onSelect?.({ kind: "star", id: s.id });
            }}
          >
            <sphereGeometry args={[STAR_RADIUS, 8, 8]} />
            <meshBasicMaterial
              color={s.flag ? new Color(s.flag.r, s.flag.g, s.flag.b) : new Color(0.75, 0.8, 0.95)}
              transparent
              opacity={0.95}
            />
          </mesh>
        </Flying>
      ))}
    </group>
  );
}

function AgentMeshes({
  placed,
  reducedMotion,
  openRef,
  onSelect,
}: {
  placed: PlacedScene["agents"];
  reducedMotion: boolean;
  openRef: { current: number };
  onSelect?: (hit: GalaxySelect) => void;
}) {
  return (
    <group>
      {placed.map((a) => (
        <Flying key={a.id} id={`agent:${a.id}`} dest={a.at} openRef={openRef} reducedMotion={reducedMotion}>
          <mesh
            name={`agent:${a.id}`}
            userData={{ kind: "agent", id: a.id }}
            onClick={(e) => {
              e.stopPropagation();
              onSelect?.({ kind: "agent", id: a.id });
            }}
          >
            <octahedronGeometry args={[AGENT_RADIUS, 0]} />
            <meshBasicMaterial color={rgb(a.look)} wireframe transparent opacity={a.look.unmeasured ? 0.4 : 0.95} />
          </mesh>
          {a.witness === "same-org" ? (
            <mesh>
              <ringGeometry args={[0.78, 0.88, 24]} />
              <meshBasicMaterial color={new Color(0.7, 0.85, 1)} transparent opacity={0.55} side={DoubleSide} />
            </mesh>
          ) : null}
        </Flying>
      ))}
    </group>
  );
}

function EdgeArcs({
  edges,
  openRef,
  reducedMotion,
}: {
  edges: PlacedScene["edges"];
  openRef: { current: number };
  reducedMotion: boolean;
}) {
  const g = useRef<Group>(null);
  useFrame(() => {
    if (!g.current) return;
    const t = easeOpen(openRef.current, reducedMotion);
    g.current.visible = t > 0.72;
    g.current.scale.setScalar(t);
  });
  return (
    <group ref={g}>
      {edges.map((e) => {
        const mx = (e.from.x + e.to.x) / 2;
        const my = (e.from.y + e.to.y) / 2 + 2.4;
        const mz = (e.from.z + e.to.z) / 2;
        const pts: [number, number, number][] = [];
        for (let i = 0; i <= 12; i += 1) {
          const t = i / 12;
          const u = 1 - t;
          pts.push([
            u * u * e.from.x + 2 * u * t * mx + t * t * e.to.x,
            u * u * e.from.y + 2 * u * t * my + t * t * e.to.y,
            u * u * e.from.z + 2 * u * t * mz + t * t * e.to.z,
          ]);
        }
        return (
          <group key={`${e.fromId}->${e.toId}:${e.kind}`}>
            {pts.slice(1).map((p, i) => (
              <mesh key={i} position={p}>
                <sphereGeometry args={[0.04, 6, 6]} />
                <meshBasicMaterial color={new Color(0.35, 0.55, 0.8)} transparent opacity={0.45} />
              </mesh>
            ))}
          </group>
        );
      })}
    </group>
  );
}

type PaintedLabel = { id: string; at: Point3; map: CanvasTexture; aspect: number };

/**
 * One texture per name. A record with no name gets no sprite, and a page with
 * no 2d context gets none either: an empty sprite would claim a name the
 * viewer cannot read and cannot trace back to a record.
 */
function usePaintedLabels(items: readonly { id: string; label: string; at: Point3 }[]): PaintedLabel[] {
  const painted = useMemo(() => {
    if (typeof document === "undefined") return [];
    const out: PaintedLabel[] = [];
    for (const item of items) {
      const text = labelText(item.label);
      if (text === null) continue;
      const canvas = document.createElement("canvas");
      if (!paintLabel(canvas, text)) continue;
      out.push({ id: item.id, at: item.at, map: new CanvasTexture(canvas), aspect: labelAspect(canvas) });
    }
    return out;
  }, [items]);
  useEffect(() => {
    return () => {
      for (const label of painted) label.map.dispose();
    };
  }, [painted]);
  return painted;
}

// Screen-space heights (NDC, so 2 is the whole viewport). A label scaled in
// world units shrinks with distance until it is a smudge, which reads as a
// name without being one; these hold a readable size at every zoom.
/**
 * A record is a body in the sky, so it has to be visible as one. At the opening
 * distance the old 0.18 radius covered about one pixel: the scene drew every
 * record faithfully and the viewer saw an empty rectangle.
 */
const STAR_RADIUS = 0.55;
const AGENT_RADIUS = 0.95;
/** Opening distance. Far enough for the whole sky, near enough to read it. */
export const OPENING_DISTANCE = 85;

const PLANET_LABEL_HEIGHT = 0.05;

function fillHidden(template: string, n: number): string {
  return template.replace(/\{n\}/g, String(n));
}

function namesShown(
  kind: "planet" | "agent",
  items: readonly { at: { x: number; y: number; z: number } }[],
  orbit: Orbit,
): { show: boolean; hidden: number; reason: LabelHideReason | null } {
  const eye = { ...cameraPosition(orbit), fovDeg: LABEL_FOV_DEG };
  const ndc = [];
  for (const item of items) {
    const p = projectNdc(item.at, eye);
    if (p) ndc.push(p);
  }
  return labelCrowd(ndc, kind, orbit.distance, SCENE_RADIUS);
}

function LabelSprites({
  placed,
  orbit,
  openRef,
  reducedMotion,
  onHidden,
}: {
  placed: PlacedScene;
  orbit: Orbit;
  openRef: { current: number };
  reducedMotion: boolean;
  onHidden: (hidden: number) => void;
}) {
  const g = useRef<Group>(null);
  const planetLabels = usePaintedLabels(placed.planets);
  const agentLabels = usePaintedLabels(placed.agents);
  const planetCount = planetLabels.length;
  const agentCount = agentLabels.length;
  const [showPlanet, setShowPlanet] = useState(() => namesShown("planet", planetLabels, orbit).show);
  const [showAgent, setShowAgent] = useState(() => namesShown("agent", agentLabels, orbit).show);
  const lastHidden = useRef(-1);
  useFrame(() => {
    if (g.current) g.current.visible = easeOpen(openRef.current, reducedMotion) > 0.88;
    // Each kind is judged on its own screen neighborhood. A crowd of
    // agents does not hide a readable planet name, and the other way.
    const nextPlanet = namesShown("planet", planetLabels, orbit);
    const nextAgent = namesShown("agent", agentLabels, orbit);
    if (nextPlanet.show !== showPlanet) setShowPlanet(nextPlanet.show);
    if (nextAgent.show !== showAgent) setShowAgent(nextAgent.show);
    const hidden = (nextPlanet.show ? 0 : planetCount) + (nextAgent.show ? 0 : agentCount);
    if (hidden !== lastHidden.current) {
      lastHidden.current = hidden;
      onHidden(hidden);
    }
  });
  return (
    <group ref={g}>
      {showPlanet
        ? planetLabels.map((l) => (
            <sprite
              key={`l-p-${l.id}`}
              position={[l.at.x, l.at.y, l.at.z]}
              // Sits above its body; an agent in the same group sits below,
              // so two names on one address stay separately readable.
              center={[0.5, -0.35]}
              scale={[PLANET_LABEL_HEIGHT * l.aspect, PLANET_LABEL_HEIGHT, 1]}
            >
              <spriteMaterial map={l.map} transparent opacity={0.92} depthWrite={false} sizeAttenuation={false} />
            </sprite>
          ))
        : null}
      {showAgent
        ? agentLabels.map((l) => (
            <sprite
              key={`l-a-${l.id}`}
              position={[l.at.x, l.at.y, l.at.z]}
              center={[0.5, 1.35]}
              scale={[AGENT_LABEL_NDC_HEIGHT * l.aspect, AGENT_LABEL_NDC_HEIGHT, 1]}
            >
              <spriteMaterial map={l.map} transparent opacity={0.78} depthWrite={false} sizeAttenuation={false} />
            </sprite>
          ))
        : null}
    </group>
  );
}

function SceneBody({
  model,
  reducedMotion,
  orbit,
  onSelect,
  target,
  onCoreToggle,
  onHiddenLabels,
}: {
  model: GalaxyModel;
  reducedMotion: boolean;
  orbit: Orbit;
  onSelect?: (hit: GalaxySelect) => void;
  target: number;
  onCoreToggle: () => void;
  onHiddenLabels: (hidden: number) => void;
}) {
  const placed = useMemo(() => placeScene(model), [model]);
  const search = typeof window !== "undefined" ? window.location.search : "";
  const forced = readForcedTier(search);
  const [tierIndex, setTierIndex] = useState(forced ?? 0);
  const quality = galaxyTier(tierIndex);
  const openRef = useRef(target);

  useEffect(() => {
    const w = window as Window & { __veraxPushFrame?: (ms: number) => void; __veraxTier?: number };
    const prev = w.__veraxPushFrame;
    w.__veraxPushFrame = (ms: number) => {
      prev?.(ms);
      if (forced !== null) return;
      if (ms > 22 && tierIndex < 2) setTierIndex((i) => Math.min(2, i + 1));
    };
    w.__veraxTier = quality.dust;
    return () => {
      w.__veraxPushFrame = prev;
    };
  }, [forced, quality.dust, tierIndex]);

  return (
    <group>
      <OpenDriver target={target} reducedMotion={reducedMotion} openRef={openRef} />
      <OrbitRig orbit={orbit} reducedMotion={reducedMotion} />
      <DustLayer count={quality.dust} reducedMotion={reducedMotion} openRef={openRef} />
      <CoreMesh
        look={placed.core}
        reducedMotion={reducedMotion}
        openRef={openRef}
        onSelect={() => {
          onCoreToggle();
          onSelect?.({ kind: "core", id: "core" });
        }}
      />
      <PlanetMeshes placed={placed.planets} reducedMotion={reducedMotion} openRef={openRef} onSelect={onSelect} />
      <StarPoints placed={placed.stars} reducedMotion={reducedMotion} openRef={openRef} onSelect={onSelect} />
      <AgentMeshes placed={placed.agents} reducedMotion={reducedMotion} openRef={openRef} onSelect={onSelect} />
      <EdgeArcs edges={placed.edges} openRef={openRef} reducedMotion={reducedMotion} />
      <LabelSprites
        placed={placed}
        orbit={orbit}
        openRef={openRef}
        reducedMotion={reducedMotion}
        onHidden={onHiddenLabels}
      />
      {quality.bloom.strength > 0 ? (
        <EffectComposer>
          <Bloom
            intensity={quality.bloom.strength}
            luminanceThreshold={quality.bloom.threshold}
            luminanceSmoothing={quality.bloom.radius}
            mipmapBlur
          />
        </EffectComposer>
      ) : null}
    </group>
  );
}

export function Galaxy({
  model,
  reducedMotion,
  onSelect,
  open,
  ready = true,
  hiddenLabelsText,
}: GalaxyProps) {
  const reduce = reducedMotion ?? readReduced();
  const orbit = useMemo(() => createOrbit(OPENING_DISTANCE), []);
  const dragging = useRef(false);
  const moved = useRef(false);
  const last = useRef({ x: 0, y: 0 });
  const queryOpen = typeof window !== "undefined" ? readOpenQuery(window.location.search) : null;
  const [want, setWant] = useState(defaultOpen(open, queryOpen));
  const [hiddenLabels, setHiddenLabels] = useState(0);
  const target = ready ? (open ?? want) : 0;

  const toggle = useCallback(() => {
    if (!ready || open !== undefined) return;
    setWant((w) => (w >= 0.5 ? 0 : 1));
  }, [ready, open]);

  const onPointerDown = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    dragging.current = true;
    moved.current = false;
    last.current = { x: e.clientX, y: e.clientY };
  }, []);
  const onPointerUp = useCallback(() => {
    dragging.current = false;
  }, []);
  const onPointerMove = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragging.current) return;
    const dx = (e.clientX - last.current.x) * 0.005;
    const dy = (e.clientY - last.current.y) * 0.004;
    if (Math.abs(e.clientX - last.current.x) + Math.abs(e.clientY - last.current.y) > 6) moved.current = true;
    last.current = { x: e.clientX, y: e.clientY };
    nudgeOrbit(orbit, dx, dy, true);
  }, [orbit]);
  const onWheel = useCallback(
    (e: React.WheelEvent<HTMLDivElement>) => {
      e.preventDefault();
      zoomOrbit(orbit, e.deltaY * 0.28);
    },
    [orbit],
  );

  return (
    <div
      className="galaxy-stage"
      data-testid="galaxy-stage"
      data-ready={ready ? "1" : "0"}
      data-target={String(target)}
      onPointerDown={onPointerDown}
      onPointerUp={onPointerUp}
      onPointerLeave={onPointerUp}
      onPointerMove={onPointerMove}
      onWheel={onWheel}
    >
      {hiddenLabels > 0 && hiddenLabelsText ? (
        <p className="galaxy-labels-hidden" data-testid="galaxy-labels-hidden">
          {fillHidden(hiddenLabelsText, hiddenLabels)}
        </p>
      ) : null}
      <Canvas
        camera={{ position: [0, 40, 110], fov: LABEL_FOV_DEG, near: 0.1, far: 2000 }}
        gl={{ antialias: true, toneMapping: NoToneMapping }}
        onCreated={({ gl }) => {
          gl.setClearColor(0x000000, 1);
        }}
        onPointerMissed={() => {
          if (!moved.current) toggle();
        }}
      >
        <FrameSampler />
        <SceneBody
          model={model}
          reducedMotion={reduce}
          orbit={orbit}
          onSelect={onSelect}
          target={target}
          onCoreToggle={toggle}
          onHiddenLabels={(n) => setHiddenLabels((prev) => (prev === n ? prev : n))}
        />
      </Canvas>
    </div>
  );
}
