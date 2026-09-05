import { useEffect, useRef } from "react";

export function MatrixRain({ on }: { on: boolean }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !on) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;
    const resize = () => {
      canvas.width = canvas.clientWidth;
      canvas.height = canvas.clientHeight;
    };
    resize();
    const glyphs = "01";
    const cols = Math.max(1, Math.floor(canvas.width / 14));
    const drops = Array.from({ length: cols }, () => 0);
    let raf = 0;
    const tick = () => {
      ctx.fillStyle = "rgba(11,18,32,0.18)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#2f6b4f";
      ctx.font = "12px ui-monospace, monospace";
      for (let i = 0; i < drops.length; i += 1) {
        const g = glyphs.charAt((i + drops[i]!) % glyphs.length);
        ctx.fillText(g, i * 14, (drops[i]! * 14) % (canvas.height + 14));
        drops[i] = (drops[i]! + 1) % 80;
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
