import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { Color, type DirectionalLight, type PointLight } from "three";

export function Lights({ color }: { color: readonly [number, number, number] }) {
  const fill = useRef<DirectionalLight>(null);
  const point = useRef<PointLight>(null);
  const current = useRef(new Color(color[0], color[1], color[2]));
  const target = useRef(new Color(color[0], color[1], color[2]));

  useFrame(() => {
    target.current.setRGB(color[0], color[1], color[2]);
    current.current.lerp(target.current, 0.04);
    if (fill.current) fill.current.color.copy(current.current);
    if (point.current) point.current.color.copy(current.current);
  });

  return (
    <>
      <ambientLight intensity={0.9} />
      <directionalLight position={[4, 6, 5]} intensity={1.4} />
      <directionalLight ref={fill} position={[-4, 2, -2]} intensity={0.7} />
      <pointLight ref={point} position={[0, 1, 4]} intensity={1.1} />
    </>
  );
}
