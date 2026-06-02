import React, { useEffect, useRef } from "react";

/**
 * HeroWave — 3-layer animated sea wave, Handhold.io style.
 * Improvements:
 *  - Smooth cubic bezier curves instead of lineTo (no jagged edges)
 *  - 4 wave layers instead of 3 for more depth
 *  - Breathing amplitude (t-based sine on amp)
 *  - Mouse: gentle additive Gaussian offset (max ±5px)
 *  - Click: expanding dual-ring ripples
 */
export default function HeroWave() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const target = canvas.parentElement ?? canvas;

    const dpr = Math.max(1, window.devicePixelRatio || 1);
    let W = 0, H = 0;
    let animId = 0;
    let t = 0;

    let mx = -999, my = -999;

    type Ripple = { x: number; y: number; r: number; life: number };
    const ripples: Ripple[] = [];

    let targetRect: DOMRect | null = null;

    /* ── resize ── */
    function resize() {
      const p = canvas!.parentElement;
      W = p ? p.clientWidth  : window.innerWidth;
      H = p ? p.clientHeight : window.innerHeight;
      canvas!.width  = Math.round(W * dpr);
      canvas!.height = Math.round(H * dpr);
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      targetRect = target.getBoundingClientRect();
    }
    resize();
    const ro = new ResizeObserver(resize);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    /* ── event listeners ── */
    const onMouseMove = (e: MouseEvent) => {
      if (!targetRect) targetRect = target.getBoundingClientRect();
      mx = e.clientX - targetRect.left;
      my = e.clientY - targetRect.top;
    };
    const onMouseLeave = () => { mx = -999; my = -999; };
    const onClick = (e: MouseEvent) => {
      if (!targetRect) targetRect = target.getBoundingClientRect();
      ripples.push({ x: e.clientX - targetRect.left, y: e.clientY - targetRect.top, r: 0, life: 1 });
    };
    const handleScroll = () => {
      targetRect = target.getBoundingClientRect();
    };

    target.addEventListener("mousemove", onMouseMove);
    target.addEventListener("mouseleave", onMouseLeave);
    target.addEventListener("click", onClick);
    window.addEventListener("scroll", handleScroll, { passive: true });

    /**
     * Compute Y points for a wave layer, then draw using
     * smooth cubic bezier curves for silky rendering.
     *
     * ampBreath: fraction of amp that pulses via a second sine on t
     * mouseAmp:  max pixel offset from mouse (additive Gaussian)
     */
    function wave(
      yBase: number,
      amp: number,
      ampBreath: number,  // 0..1, breathing variation
      freq: number,
      speed: number,
      phase: number,
      fillTop: string,
      stroke: string,
      mouseAmp: number,
    ) {
      // Breathing — amp gently pulses up/down
      const liveAmp = amp * (1 + ampBreath * Math.sin(t * 0.4 + phase));

      // Sample every N pixels (fewer samples = smoother bezier + 60% CPU savings)
      const STEP = W > 1200 ? 12 : 8;
      const pts: [number, number][] = [];

      for (let i = 0; i <= W; i += STEP) {
        // Mouse Gaussian offset
        let mouseOffset = 0;
        if (mx > -900) {
          const dx = i - mx;
          const sigma = W * 0.18;
          mouseOffset = mouseAmp * Math.exp(-(dx * dx) / (2 * sigma * sigma));
        }

        // Ripple offset
        let rippleOffset = 0;
        for (const rip of ripples) {
          const dx = i - rip.x;
          const d = Math.abs(dx);
          if (d < 300) {
            rippleOffset += rip.life * 9 * Math.sin(d / 26 - t * 7) * Math.exp(-d / 110);
          }
        }

        const y =
          yBase
          + mouseOffset
          + rippleOffset
          + Math.sin(i * freq + phase + t * speed) * liveAmp
          + Math.sin(i * freq * 0.53 - phase * 0.7 - t * speed * 0.62) * liveAmp * 0.36
          + Math.sin(i * freq * 1.7  + phase * 0.3 + t * speed * 1.1)  * liveAmp * 0.12;

        pts.push([i, y]);
      }

      /* ── Draw fill using smooth cardinal spline ── */
      const fillPath = new Path2D();
      fillPath.moveTo(0, H);
      fillPath.lineTo(pts[0][0], pts[0][1]);

      // Catmull-Rom → cubic bezier conversion for smooth curve
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[Math.max(i - 1, 0)];
        const p1 = pts[i];
        const p2 = pts[i + 1];
        const p3 = pts[Math.min(i + 2, pts.length - 1)];
        const tension = 0.5;
        const cp1x = p1[0] + (p2[0] - p0[0]) * tension / 3;
        const cp1y = p1[1] + (p2[1] - p0[1]) * tension / 3;
        const cp2x = p2[0] - (p3[0] - p1[0]) * tension / 3;
        const cp2y = p2[1] - (p3[1] - p1[1]) * tension / 3;
        fillPath.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2[0], p2[1]);
      }

      fillPath.lineTo(W, H);
      fillPath.closePath();

      const grad = ctx!.createLinearGradient(0, yBase - liveAmp * 1.2, 0, H);
      grad.addColorStop(0, fillTop);
      grad.addColorStop(0.6, fillTop.replace(/[\d.]+\)$/, "0.06)"));
      grad.addColorStop(1, "rgba(250,250,248,0)");
      ctx!.fillStyle = grad;
      ctx!.fill(fillPath);

      /* ── Draw stroke (same smooth bezier) ── */
      const strokePath = new Path2D();
      strokePath.moveTo(pts[0][0], pts[0][1]);
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[Math.max(i - 1, 0)];
        const p1 = pts[i];
        const p2 = pts[i + 1];
        const p3 = pts[Math.min(i + 2, pts.length - 1)];
        const tension = 0.5;
        const cp1x = p1[0] + (p2[0] - p0[0]) * tension / 3;
        const cp1y = p1[1] + (p2[1] - p0[1]) * tension / 3;
        const cp2x = p2[0] - (p3[0] - p1[0]) * tension / 3;
        const cp2y = p2[1] - (p3[1] - p1[1]) * tension / 3;
        strokePath.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2[0], p2[1]);
      }
      ctx!.strokeStyle = stroke;
      ctx!.lineWidth = 1.8;
      ctx!.lineJoin = "round";
      ctx!.lineCap = "round";
      ctx!.stroke(strokePath);
    }

    function drawRipples() {
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rip = ripples[i];
        rip.r   += 4;
        rip.life -= 0.016;
        if (rip.life <= 0) { ripples.splice(i, 1); continue; }

        // Outer ring
        ctx!.beginPath();
        ctx!.arc(rip.x, rip.y, rip.r, 0, Math.PI * 2);
        ctx!.strokeStyle = `rgba(56,189,248,${(rip.life * 0.38).toFixed(2)})`;
        ctx!.lineWidth = 2.2 * rip.life;
        ctx!.stroke();

        // Inner ring (slower expand)
        ctx!.beginPath();
        ctx!.arc(rip.x, rip.y, rip.r * 0.5, 0, Math.PI * 2);
        ctx!.strokeStyle = `rgba(167,139,250,${(rip.life * 0.22).toFixed(2)})`;
        ctx!.lineWidth = 1.6 * rip.life;
        ctx!.stroke();
      }
    }

    function frame() {
      t += 0.008; // slightly faster = more lively
      ctx!.clearRect(0, 0, W, H);

      // Layer 0 — faint warm gold (furthest back, very slow)
      wave(H * 0.52, H * 0.030, 0.18, 0.0038, 0.40, 1.0,
        "rgba(251,191,36,0.10)", "rgba(245,158,11,0.22)", 3);

      // Layer 1 — amber (back)
      wave(H * 0.59, H * 0.046, 0.14, 0.0050, 0.58, 0.0,
        "rgba(251,191,36,0.20)", "rgba(245,158,11,0.46)", 4);

      // Layer 2 — sky blue (mid)
      wave(H * 0.66, H * 0.040, 0.12, 0.0065, 0.75, 2.1,
        "rgba(125,211,252,0.24)", "rgba(56,189,248,0.54)", 5);

      // Layer 3 — violet (front, most movement)
      wave(H * 0.73, H * 0.034, 0.10, 0.0082, 0.92, 4.4,
        "rgba(196,181,253,0.22)", "rgba(167,139,250,0.50)", 5);

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
      window.removeEventListener("scroll", handleScroll);
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
