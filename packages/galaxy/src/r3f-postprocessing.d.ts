declare module "@react-three/postprocessing" {
  import type { ReactNode } from "react";
  export function EffectComposer(props: { children?: ReactNode }): ReactNode;
  export function Bloom(props: {
    intensity?: number;
    luminanceThreshold?: number;
    luminanceSmoothing?: number;
    mipmapBlur?: boolean;
  }): ReactNode;
}
