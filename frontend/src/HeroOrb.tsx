import React, { useEffect, useRef } from "react";

/**
 * HeroWave — pure-canvas ambient wave, matching the Handhold.io reference.
 * Only renders a single soft, slow-moving wave fill at the lower portion
 * of the hero. No colored orbs, no particles.
 */
export default function HeroWave() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId = 0;
    let width = 0;
    let height = 0;
    const dpr = Math.max(1, window.devicePixelRatio || 1);

    function resize() {
      if (!canvas) return;
      width = canvas.clientWidth || canvas.offsetWidth || 800;
      height = canvas.clientHeight || canvas.offsetHeight || 600;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    resize();
    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    const start = performance.now();

    function draw(now: number) {
      if (!ctx) return;
      const t = (now - start) * 0.00022; // very slow time

      ctx.clearRect(0, 0, width, height);

      // ── Wave 1 (main, very subtle) ──────────────────────────────
      const baseY = height * 0.68;
      const amp   = Math.min(width, height) * 0.032;
      const segs  = 120;

      const drawWave = (
        yBase: number,
        ampScale: number,
        phaseOffset: number,
        fillColor: string,
        strokeColor: string
      ) => {
        ctx.beginPath();
        ctx.moveTo(0, height);
        ctx.lineTo(
          0,
          yBase + Math.sin(t * 1.1 + phaseOffset) * amp * ampScale
        );
        for (let i = 0; i <= segs; i++) {
          const x = (i / segs) * width;
          const y =
            yBase +
            Math.sin(x * 0.006 + t + phaseOffset) * amp * ampScale +
            Math.cos(x * 0.009 - t * 0.85 + phaseOffset) * amp * 0.35 * ampScale;
          ctx.lineTo(x, y);
        }
        ctx.lineTo(width, height);
        ctx.closePath();

        ctx.fillStyle = fillColor;
        ctx.fill();

        // Stroke the wave edge only
        ctx.beginPath();
        ctx.moveTo(
          0,
          yBase + Math.sin(t * 1.1 + phaseOffset) * amp * ampScale
        );
        for (let i = 0; i <= segs; i++) {
          const x = (i / segs) * width;
          const y =
            yBase +
            Math.sin(x * 0.006 + t + phaseOffset) * amp * ampScale +
            Math.cos(x * 0.009 - t * 0.85 + phaseOffset) * amp * 0.35 * ampScale;
          ctx.lineTo(x, y);
        }
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 1;
        ctx.stroke();
      };

      // Layer 1 — back fill, very light
      drawWave(
        baseY + amp * 0.5,
        0.9,
        0.6,
        "rgba(230, 228, 222, 0.45)",
        "rgba(200, 198, 190, 0.18)"
      );

      // Layer 2 — front fill, slightly more visible
      drawWave(
        baseY,
        1.0,
        0,
        "rgba(236, 234, 228, 0.55)",
        "rgba(200, 198, 190, 0.25)"
      );

      animId = requestAnimationFrame(draw);
    }

    animId = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animId);
      ro.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        zIndex: 0,
      }}
    />
  );
}
