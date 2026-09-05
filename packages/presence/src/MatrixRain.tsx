import { useEffect, useRef } from "react";

export const RAIN_PALETTE = {
  head: "#ffffff",
  full: "#5CE1FF",
  mid: "#2F6BFF",
  dim: "#12305F",
  trail: "rgba(2,6,15,0.10)",
} as const;

export const RAIN_GLYPHS = "アイウエオカキクケコ01VERAX量子";

export function MatrixRain({ on }: { on: boolean }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !on) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;
    const fontSize = 13;
    let drops: number[] = [];
    const resize = () => {
      canvas.width = canvas.clientWidth;
      canvas.height = canvas.clientHeight;
      const cols = Math.max(1, Math.floor(canvas.width / fontSize));
      drops = Array.from({ length: cols }, () => Math.random() * -40);
    };
    resize();
    let raf = 0;
    const tick = () => {
      if (document.hidden) {
        raf = requestAnimationFrame(tick);
        return;
      }
      ctx.fillStyle = RAIN_PALETTE.trail;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fontSize}px ui-monospace, monospace`;
      for (let i = 0; i < drops.length; i += 1) {
        const yPx = drops[i]! * fontSize;
        if (yPx < 0) {
          drops[i] = drops[i]! + 0.5;
          continue;
        }
        const g = RAIN_GLYPHS.charAt((i + Math.floor(drops[i]!)) % RAIN_GLYPHS.length);
        const r = (i * 17 + Math.floor(drops[i]!)) % 100;
        ctx.fillStyle = r > 88 ? RAIN_PALETTE.head : r > 75 ? RAIN_PALETTE.full : r > 45 ? RAIN_PALETTE.mid : RAIN_PALETTE.dim;
        ctx.fillText(g, i * fontSize, yPx % (canvas.height + fontSize));
        if (yPx > canvas.height && r > 97) drops[i] = 0;
        else drops[i] = drops[i]! + 0.5;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    window.addEventListener("resize", resize);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [on]);

  if (!on) return null;
  return <canvas ref={ref} className="matrix" aria-hidden="true" />;
}
