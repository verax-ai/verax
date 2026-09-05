import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { AdditiveBlending, CanvasTexture, Color, type PointLight, type Sprite, type SpriteMaterial } from "three";
import { chestLocal, type Box3 } from "./fit.ts";

function radialTexture(): CanvasTexture {
  const size = 64;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("chest-core-canvas");
  const g = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  g.addColorStop(0, "rgba(255,255,255,1)");
  g.addColorStop(0.35, "rgba(255,255,255,0.45)");
  g.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);
  const tex = new CanvasTexture(canvas);
  tex.needsUpdate = true;
  return tex;
}

export function ChestCore({
  box,
  color,
  ringSpin,
  breathAmp,
}: {
  box: Box3;
  color: readonly [number, number, number];
  ringSpin: number;
  breathAmp: number;
}) {
  const tex = useMemo(() => radialTexture(), []);
  const spriteRef = useRef<Sprite>(null);
  const lightRef = useRef<PointLight>(null);
  const current = useRef(new Color(color[0], color[1], color[2]));
  const target = useRef(new Color(color[0], color[1], color[2]));
  const pos = chestLocal(box);

  useFrame(({ clock }) => {
    target.current.setRGB(color[0], color[1], color[2]);
    current.current.lerp(target.current, 0.04);
    const pulse = 1 + Math.sin(clock.elapsedTime * (2 + ringSpin * 4)) * (0.12 + breathAmp * 2);
    const s = 0.38 * pulse;
    const sprite = spriteRef.current;
    if (sprite) {
      sprite.scale.set(s, s, s);
      (sprite.material as SpriteMaterial).color.copy(current.current);
    }
    const light = lightRef.current;
    if (light) {
      light.color.copy(current.current);
      light.intensity = 0.9 * pulse;
    }
  });

  return (
    <group position={pos}>
      <sprite ref={spriteRef}>
        <spriteMaterial map={tex} transparent depthWrite={false} blending={AdditiveBlending} />
      </sprite>
      <pointLight ref={lightRef} distance={2.4} intensity={0.9} />
    </group>
  );
}
