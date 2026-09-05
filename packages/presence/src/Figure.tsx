import { useEffect, useRef, useState } from "react";
import { useFrame } from "@react-three/fiber";
import { Group, Mesh, type Material } from "three";
import { GLTFLoader } from "three/examples/jsm/loaders/GLTFLoader.js";
import { MeshoptDecoder } from "three/examples/jsm/libs/meshopt_decoder.module.js";
import type { PresenceState } from "./state.ts";

export const MODEL_FILE = "verax-body.glb";

export function modelUrl(assetBase = "/"): string {
  const base = assetBase.endsWith("/") ? assetBase : `${assetBase}/`;
  return `${base}${MODEL_FILE}`;
}

function applyOpacity(root: Group, opacity: number): void {
  root.traverse((obj) => {
    const mesh = obj as Mesh;
    if (!mesh.isMesh) return;
    const list = Array.isArray(mesh.material) ? mesh.material : [mesh.material];
    for (const mat of list) {
      const m = mat as Material & { opacity?: number; transparent?: boolean; depthWrite?: boolean };
      m.transparent = true;
      m.opacity = opacity;
      m.depthWrite = opacity > 0.95;
      m.needsUpdate = true;
    }
  });
}

export function Figure({
  presence,
  startedAtMs,
  onMissing,
  assetBase = "/",
}: {
  presence: PresenceState;
  startedAtMs: number;
  onMissing: () => void;
  assetBase?: string;
}) {
  const [root, setRoot] = useState<Group | null>(null);
  const reported = useRef(false);
  const lastOpacity = useRef<number | null>(null);

  useEffect(() => {
    let dead = false;
    const miss = () => {
      if (!dead && !reported.current) {
        reported.current = true;
        onMissing();
      }
    };
    void fetch(modelUrl(assetBase))
      .then((res) => {
        if (!res.ok) {
          miss();
          return null;
        }
        return res.arrayBuffer();
      })
      .then(async (buf) => {
        if (!buf || dead) return;
        await MeshoptDecoder.ready;
        const loader = new GLTFLoader();
        loader.setMeshoptDecoder(MeshoptDecoder);
        const gltf = await loader.parseAsync(buf, "");
        if (dead) return;
        const scene = gltf.scene;
        scene.rotation.y = 0;
        setRoot(scene);
      })
      .catch(miss);
    return () => {
      dead = true;
    };
  }, [onMissing, assetBase]);

  useEffect(() => {
    lastOpacity.current = null;
  }, [root]);

  useFrame(() => {
    if (!root) return;
    const elapsed = (performance.now() - startedAtMs) / 1000;
    const progress = presence === "booting" ? Math.min(1, elapsed / 4) : 1;
    const boot = progress <= 0.75 ? 0 : Math.min(1, (progress - 0.75) / 0.25);
    const asleep = presence === "asleep" ? 0.25 : 1;
    const next = boot * asleep;
    if (lastOpacity.current === next) return;
    lastOpacity.current = next;
    applyOpacity(root, next);
  });

  if (!root) return null;
  return <primitive object={root} />;
}
