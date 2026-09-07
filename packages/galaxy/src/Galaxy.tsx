import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Bloom, EffectComposer } from "@react-three/postprocessing";
import { Color, DoubleSide, Group, InstancedMesh, NoToneMapping, Object3D, type Mesh } from "three";
import { cameraPosition, createOrbit, nudgeOrbit, stepOrbit, zoomOrbit, type Orbit } from "./camera.ts";
import { UNMEASURED_RGB, type Appearance } from "./draw.ts";
import { dustPositions } from "./dust.ts";
import { labelVisible } from "./labels.ts";
import type { GalaxyModel } from "./model.ts";
import { placeScene, SCENE_RADIUS, type PlacedScene } from "./place.ts";
import { galaxyTier, readForcedTier } from "./quality.ts";

export type GalaxySelect = { kind: "star" | "planet" | "agent" | "core"; id: string };

export type GalaxyProps = {
  model: GalaxyModel;
  reducedMotion?: boolean;
  onSelect?: (hit: GalaxySelect) => void;
  /** 0 = closed sphere (loading), 1 = open. Commit D drives this. */
  open?: number;
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

function DustLayer({ count, reducedMotion }: { count: number; reducedMotion: boolean }) {
  const mesh = useRef<InstancedMesh>(null);
  const positions = useMemo(() => dustPositions(count === 20_000 ? 0 : count === 10_000 ? 1 : 2, SCENE_RADIUS), [count]);
  useEffect(() => {
    const m = mesh.current;
    if (!m) return;
    const dummy = new Object3D();
    const color = new Color(0.18, 0.12, 0.28);
    for (let i = 0; i < count; i += 1) {
      dummy.position.set(positions[i * 3] ?? 0, positions[i * 3 + 1] ?? 0, positions[i * 3 + 2] ?? 0);
      dummy.scale.setScalar(0.22);
      dummy.updateMatrix();
      m.setMatrixAt(i, dummy.matrix);
      m.setColorAt(i, color);
    }
    m.instanceMatrix.needsUpdate = true;
    if (m.instanceColor) m.instanceColor.needsUpdate = true;
  }, [count, positions]);
  useFrame(() => {
    if (!mesh.current || reducedMotion) return;
    mesh.current.rotation.y += 0.00015;
  });
  return (
    <instancedMesh ref={mesh} args={[undefined, undefined, count]} frustumCulled={false}>
      <tetrahedronGeometry args={[0.25]} />
      <meshBasicMaterial transparent opacity={0.22} depthWrite={false} />
    </instancedMesh>
  );
}

function CoreMesh({ look, reducedMotion }: { look: Appearance; reducedMotion: boolean }) {
  const ref = useRef<Mesh>(null);
  useFrame(() => {
    if (!ref.current) return;
    const pulse = reducedMotion ? look.size : look.size * (0.96 + 0.04 * Math.sin((performance.now() / 1000) * 1.1));
    ref.current.scale.setScalar(look.unmeasured ? 1 : pulse);
  });
  const c = look.unmeasured ? new Color(UNMEASURED_RGB.r, UNMEASURED_RGB.g, UNMEASURED_RGB.b) : rgb(look);
  return (
    <mesh ref={ref} name="core" userData={{ kind: "core", id: "core" }}>
      <sphereGeometry args={[2.4, 24, 20]} />
      <meshBasicMaterial color={c} transparent opacity={look.unmeasured ? 0.35 : 0.85} />
    </mesh>
  );
}

function PlanetMeshes({
  placed,
  reducedMotion,
  onSelect,
}: {
  placed: PlacedScene["planets"];
  reducedMotion: boolean;
  onSelect?: (hit: GalaxySelect) => void;
}) {
  return (
    <group>
      {placed.map((p) => (
        <group key={p.id} position={[p.at.x, p.at.y, p.at.z]}>
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
        </group>
      ))}
    </group>
  );
}

function StarPoints({
  placed,
  onSelect,
}: {
  placed: PlacedScene["stars"];
  onSelect?: (hit: GalaxySelect) => void;
}) {
  return (
    <group>
      {placed.map((s) => (
        <mesh
          key={s.id}
          position={[s.at.x, s.at.y, s.at.z]}
          name={`star:${s.id}`}
          userData={{ kind: "star", id: s.id }}
          onClick={(e) => {
            e.stopPropagation();
            onSelect?.({ kind: "star", id: s.id });
          }}
        >
          <sphereGeometry args={[0.18, 8, 8]} />
          <meshBasicMaterial
            color={s.flag ? new Color(s.flag.r, s.flag.g, s.flag.b) : new Color(0.75, 0.8, 0.95)}
            transparent
            opacity={0.95}
          />
        </mesh>
      ))}
    </group>
  );
}

function AgentMeshes({
  placed,
  onSelect,
}: {
  placed: PlacedScene["agents"];
  onSelect?: (hit: GalaxySelect) => void;
}) {
  return (
    <group>
      {placed.map((a) => (
        <group key={a.id} position={[a.at.x, a.at.y, a.at.z]}>
          <mesh
            name={`agent:${a.id}`}
            userData={{ kind: "agent", id: a.id }}
            onClick={(e) => {
              e.stopPropagation();
              onSelect?.({ kind: "agent", id: a.id });
            }}
          >
            <octahedronGeometry args={[0.62, 0]} />
            <meshBasicMaterial color={rgb(a.look)} wireframe transparent opacity={a.look.unmeasured ? 0.4 : 0.95} />
          </mesh>
          {a.witness === "same-org" ? (
            <mesh>
              <ringGeometry args={[0.78, 0.88, 24]} />
              <meshBasicMaterial color={new Color(0.7, 0.85, 1)} transparent opacity={0.55} side={DoubleSide} />
            </mesh>
          ) : null}
        </group>
      ))}
    </group>
  );
}

function EdgeArcs({ edges }: { edges: PlacedScene["edges"] }) {
  return (
    <group>
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

function LabelSprites({
  placed,
  distance,
}: {
  placed: PlacedScene;
  distance: number;
}) {
  const showPlanet = labelVisible("planet", distance, SCENE_RADIUS);
  const showAgent = labelVisible("agent", distance, SCENE_RADIUS);
  const showStar = labelVisible("star", distance, SCENE_RADIUS);
  return (
    <group>
      {showPlanet
        ? placed.planets.map((p) => (
            <sprite key={`l-p-${p.id}`} position={[p.at.x, p.at.y + 1.4, p.at.z]} scale={[4.5, 1.1, 1]}>
              <spriteMaterial color={new Color(0.9, 0.92, 0.98)} opacity={0.85} depthWrite={false} />
            </sprite>
          ))
        : null}
      {showAgent
        ? placed.agents.map((a) => (
            <sprite key={`l-a-${a.id}`} position={[a.at.x, a.at.y + 0.9, a.at.z]} scale={[2.2, 0.6, 1]}>
              <spriteMaterial color={new Color(0.75, 0.8, 0.9)} opacity={0.7} depthWrite={false} />
            </sprite>
          ))
        : null}
      {showStar
        ? placed.stars.map((s) => (
            <sprite key={`l-s-${s.id}`} position={[s.at.x, s.at.y + 0.35, s.at.z]} scale={[1.2, 0.35, 1]}>
              <spriteMaterial color={new Color(0.7, 0.75, 0.9)} opacity={0.45} depthWrite={false} />
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
  open,
}: {
  model: GalaxyModel;
  reducedMotion: boolean;
  orbit: Orbit;
  onSelect?: (hit: GalaxySelect) => void;
  open: number;
}) {
  const placed = useMemo(() => placeScene(model), [model]);
  const search = typeof window !== "undefined" ? window.location.search : "";
  const forced = readForcedTier(search);
  const [tierIndex, setTierIndex] = useState(forced ?? 0);
  const quality = galaxyTier(tierIndex);
  const group = useRef<Group>(null);

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

  useFrame(() => {
    if (!group.current) return;
    const t = Math.max(0, Math.min(1, open));
    group.current.scale.setScalar(0.08 + t * 0.92);
  });

  return (
    <group ref={group}>
      <OrbitRig orbit={orbit} reducedMotion={reducedMotion} />
      <DustLayer count={quality.dust} reducedMotion={reducedMotion} />
      <CoreMesh look={placed.core} reducedMotion={reducedMotion} />
      <PlanetMeshes placed={placed.planets} reducedMotion={reducedMotion} onSelect={onSelect} />
      <StarPoints placed={placed.stars} onSelect={onSelect} />
      <AgentMeshes placed={placed.agents} onSelect={onSelect} />
      <EdgeArcs edges={placed.edges} />
      <LabelSprites placed={placed} distance={orbit.distance} />
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

export function Galaxy({ model, reducedMotion, onSelect, open = 1 }: GalaxyProps) {
  const reduce = reducedMotion ?? readReduced();
  const orbit = useMemo(() => createOrbit(120), []);
  const dragging = useRef(false);
  const last = useRef({ x: 0, y: 0 });

  const onPointerDown = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    dragging.current = true;
    last.current = { x: e.clientX, y: e.clientY };
  }, []);
  const onPointerUp = useCallback(() => {
    dragging.current = false;
  }, []);
  const onPointerMove = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragging.current) return;
    const dx = (e.clientX - last.current.x) * 0.005;
    const dy = (e.clientY - last.current.y) * 0.004;
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
      onPointerDown={onPointerDown}
      onPointerUp={onPointerUp}
      onPointerLeave={onPointerUp}
      onPointerMove={onPointerMove}
      onWheel={onWheel}
    >
      <Canvas
        camera={{ position: [0, 40, 110], fov: 46, near: 0.1, far: 2000 }}
        gl={{ antialias: true, toneMapping: NoToneMapping }}
        onCreated={({ gl }) => {
          gl.setClearColor(0x000000, 1);
        }}
      >
        <FrameSampler />
        <SceneBody model={model} reducedMotion={reduce} orbit={orbit} onSelect={onSelect} open={open} />
      </Canvas>
    </div>
  );
}
