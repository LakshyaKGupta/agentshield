import React, { useEffect, useRef } from "react";

/**
 * HeroWave — 3-layer animated sea wave, Handhold.io style.
 * Mouse: adds a tiny additive Y pixel-offset (max ±6px), not a multiplier.
 * Click: expanding ring ripples.
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

    // Mouse position relative to parent (–999 = off-screen)
    let mx = -999, my = -999;

    // Ripples on click
    type Ripple = { x: number; y: number; r: number; life: number };
    const ripples: Ripple[] = [];

    /* ── resize ── */
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

    /* ── event listeners on parent section ── */
    const target = canvas.parentElement ?? canvas;

    const onMouseMove = (e: MouseEvent) => {
      const rect = target.getBoundingClientRect();
      mx = e.clientX - rect.left;
      my = e.clientY - rect.top;
    };
    const onMouseLeave = () => { mx = -999; my = -999; };
    const onClick = (e: MouseEvent) => {
      const rect = target.getBoundingClientRect();
      ripples.push({ x: e.clientX - rect.left, y: e.clientY - rect.top, r: 0, life: 1 });
    };

    target.addEventListener("mousemove", onMouseMove);
    target.addEventListener("mouseleave", onMouseLeave);
    target.addEventListener("click", onClick);

    /**
     * Draw one wave layer.
     * mouseAmp: MAX pixel offset the mouse can add (positive = push down, negative = push up).
     *           Kept very small (±5px) so it's subtle.
     */
    function wave(
      yBase: number,
      amp: number,
      freq: number,
      speed: number,
      phase: number,
      fillTop: string,
      stroke: string,
      mouseAmp: number,   // small pixel amount, e.g. 4
    ) {
      const pts: [number, number][] = [];

      for (let i = 0; i <= W; i++) {
        const x = i;

        // ── Subtle mouse offset: purely additive, max ±mouseAmp px ──
        let mouseOffset = 0;
        if (mx > -900) {
          const dx = x - mx;
          // Gaussian falloff over ~15% of canvas width
          const sigma = W * 0.15;
          mouseOffset = mouseAmp * Math.exp(-(dx * dx) / (2 * sigma * sigma));
        }

        // ── Ripple additive offset ──
        let rippleOffset = 0;
        for (const rip of ripples) {
          const dx = x - rip.x;
          const d = Math.abs(dx);
          if (d < 280) {
            rippleOffset += rip.life * 10 * Math.sin(d / 28 - t * 7) * Math.exp(-d / 100);
          }
        }

        const y =
          yBase +
          mouseOffset +
          rippleOffset +
          Math.sin(x * freq + phase + t * speed) * amp +
          Math.sin(x * freq * 0.55 - phase * 0.6 - t * speed * 0.65) * amp * 0.38;

        pts.push([x, y]);
      }

      // Filled area below wave
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

      // Wave edge line
      ctx!.beginPath();
      ctx!.moveTo(pts[0][0], pts[0][1]);
      for (const [x, y] of pts) ctx!.lineTo(x, y);
      ctx!.strokeStyle = stroke;
      ctx!.lineWidth = 2;
      ctx!.stroke();
    }

    function drawRipples() {
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rip = ripples[i];
        rip.r   += 3.5;
        rip.life -= 0.018;
        if (rip.life <= 0) { ripples.splice(i, 1); continue; }

        ctx!.beginPath();
        ctx!.arc(rip.x, rip.y, rip.r, 0, Math.PI * 2);
        ctx!.strokeStyle = `rgba(56,189,248,${rip.life * 0.35})`;
        ctx!.lineWidth = 2 * rip.life;
        ctx!.stroke();

        ctx!.beginPath();
        ctx!.arc(rip.x, rip.y, rip.r * 0.55, 0, Math.PI * 2);
        ctx!.strokeStyle = `rgba(167,139,250,${rip.life * 0.20})`;
        ctx!.lineWidth = 1.5 * rip.life;
        ctx!.stroke();
      }
    }

    function frame() {
      t += 0.007;
      ctx!.clearRect(0, 0, W, H);

      // Layer 1 — gold/amber (back)
      wave(H * 0.58, H * 0.048, 0.0048, 0.55, 0,
        "rgba(251,191,36,0.18)", "rgba(245,158,11,0.42)", 4);

      // Layer 2 — sky blue (mid)
      wave(H * 0.65, H * 0.042, 0.0062, 0.72, 2.1,
        "rgba(125,211,252,0.22)", "rgba(56,189,248,0.52)", 5);

      // Layer 3 — violet (front, most movement)
      wave(H * 0.72, H * 0.036, 0.0079, 0.90, 4.4,
        "rgba(196,181,253,0.20)", "rgba(167,139,250,0.48)", 6);

      drawRipples();
      animId = requestAnimationFrame(frame);
    }

    animId = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(animId);
      ro.disconnect();
      target.removeEventListener("mousemove", onMouseMove);
      target.removeEventListener("mouseleave", onMouseLeave);
      target.removeEventListener("click", onClick);
    };
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
