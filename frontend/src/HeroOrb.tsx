import { useEffect, useRef } from "react";

/**
 * HeroWave — 3-layer animated sea wave, Handhold.io style.
 * Colors: violet → sky blue → teal/emerald, drawn on light background.
 */
export default function HeroWave() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = Math.max(1, window.devicePixelRatio || 1);
    let W = 0, H = 0;
    let animId = 0;
    let t = 0;

    function resize() {
      const p = canvas!.parentElement;
      W = p ? p.clientWidth  : window.innerWidth;
      H = p ? p.clientHeight : window.innerHeight;
      canvas!.width  = Math.round(W * dpr);
      canvas!.height = Math.round(H * dpr);
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    resize();
    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    /**
     * Draw one wave layer.
     * yBase   – vertical centre of the wave (0..1 relative to H)
     * amp     – amplitude in pixels
     * freq    – spatial frequency
     * speed   – animation speed multiplier
     * phase   – static phase offset so layers are staggered
     * fillTop – rgba color at the wave crest
     * stroke  – rgba color for the edge line
     */
    function wave(
      yBase: number, amp: number, freq: number, speed: number, phase: number,
      fillTop: string, stroke: string,
    ) {
      const pts: [number, number][] = [];

      for (let i = 0; i <= W; i++) {
        const x = i;
        const y =
          yBase +
          Math.sin(x * freq + phase + t * speed) * amp +
          Math.sin(x * freq * 0.55 - phase * 0.6 - t * speed * 0.65) * amp * 0.38;
        pts.push([x, y]);
      }

      // ── Filled area below the wave line ──────────────────────────
      const grad = ctx!.createLinearGradient(0, yBase - amp, 0, H);
      grad.addColorStop(0, fillTop);
      grad.addColorStop(1, "rgba(250,250,248,0)");

      ctx!.beginPath();
      ctx!.moveTo(0, H);
      ctx!.lineTo(pts[0][0], pts[0][1]);
      for (const [x, y] of pts) ctx!.lineTo(x, y);
      ctx!.lineTo(W, H);
      ctx!.closePath();
      ctx!.fillStyle = grad;
      ctx!.fill();

      // ── Wave edge line ────────────────────────────────────────────
      ctx!.beginPath();
      ctx!.moveTo(pts[0][0], pts[0][1]);
      for (const [x, y] of pts) ctx!.lineTo(x, y);
      ctx!.strokeStyle = stroke;
      ctx!.lineWidth   = 1.8;
      ctx!.stroke();
    }

    function frame() {
      t += 0.006;
      ctx!.clearRect(0, 0, W, H);

      // Layer 1 — violet (furthest back)
      wave(
        H * 0.60, H * 0.042, 0.0048, 0.55, 0,
        "rgba(196,181,253,0.22)",
        "rgba(167,139,250,0.50)",
      );

      // Layer 2 — sky blue (middle)
      wave(
        H * 0.67, H * 0.038, 0.0062, 0.70, 2.1,
        "rgba(125,211,252,0.20)",
        "rgba(56,189,248,0.48)",
      );

      // Layer 3 — teal/emerald (front, most movement)
      wave(
        H * 0.74, H * 0.032, 0.0079, 0.85, 4.4,
        "rgba(94,234,212,0.18)",
        "rgba(45,212,191,0.42)",
      );

      animId = requestAnimationFrame(frame);
    }

    animId = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(animId); ro.disconnect(); };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: "absolute", inset: 0,
        width: "100%", height: "100%",
        pointerEvents: "none", zIndex: 0,
        display: "block",
      }}
    />
  );
}
