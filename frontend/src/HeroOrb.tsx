import React, { useEffect, useRef } from "react";

/**
 * HeroWave — 3-layer animated sea wave, Handhold.io style.
 * Added: mouse-proximity distortion + click ripples.
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

    // Mouse influence on wave
    let mx = -999, my = -999;

    // Ripples on click
    type Ripple = { x: number; y: number; r: number; life: number };
    const ripples: Ripple[] = [];

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

    // Track mouse over the whole section (parent)
    const parent = canvas.parentElement;
    const onMouseMove = (e: MouseEvent) => {
      const rect = (parent ?? canvas).getBoundingClientRect();
      mx = e.clientX - rect.left;
      my = e.clientY - rect.top;
    };
    const onMouseLeave = () => { mx = -999; my = -999; };
    const onClick = (e: MouseEvent) => {
      const rect = (parent ?? canvas).getBoundingClientRect();
      ripples.push({ x: e.clientX - rect.left, y: e.clientY - rect.top, r: 0, life: 1 });
    };

    const target = parent ?? canvas;
    // enable pointer events on target section
    target.style.pointerEvents = "auto";
    target.addEventListener("mousemove", onMouseMove);
    target.addEventListener("mouseleave", onMouseLeave);
    target.addEventListener("click", onClick);

    /**
     * Draw one wave layer with optional mouse distortion.
     */
    function wave(
      yBase: number, amp: number, freq: number, speed: number, phase: number,
      fillTop: string, stroke: string, mouseInfluence: number,
    ) {
      const pts: [number, number][] = [];

      for (let i = 0; i <= W; i++) {
        const x = i;
        // Mouse proximity distortion
        let mdist = 1;
        if (mx > -900) {
          const dx = x - mx;
          const dy = yBase - my;
          const d = Math.sqrt(dx * dx + dy * dy);
          mdist = 1 + mouseInfluence * Math.exp(-d / (W * 0.18));
        }
        // Ripple distortion
        let rippleY = 0;
        for (const rip of ripples) {
          const dx = x - rip.x;
          const d = Math.abs(dx);
          if (d < 300) {
            rippleY += rip.life * 18 * Math.sin((d / 30 - t * 8)) * Math.exp(-d / 120);
          }
        }

        const y =
          yBase * mdist +
          Math.sin(x * freq + phase + t * speed) * amp +
          Math.sin(x * freq * 0.55 - phase * 0.6 - t * speed * 0.65) * amp * 0.38 +
          rippleY;
        pts.push([x, y]);
      }

      // Filled area
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

      // Wave edge
      ctx!.beginPath();
      ctx!.moveTo(pts[0][0], pts[0][1]);
      for (const [x, y] of pts) ctx!.lineTo(x, y);
      ctx!.strokeStyle = stroke;
      ctx!.lineWidth   = 2;
      ctx!.stroke();
    }

    function drawRipples() {
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rip = ripples[i];
        rip.r += 3.5;
        rip.life -= 0.018;
        if (rip.life <= 0) { ripples.splice(i, 1); continue; }

        // Draw expanding ring
        ctx!.beginPath();
        ctx!.arc(rip.x, rip.y, rip.r, 0, Math.PI * 2);
        ctx!.strokeStyle = `rgba(56,189,248,${rip.life * 0.45})`;
        ctx!.lineWidth = 2 * rip.life;
        ctx!.stroke();

        // Second outer ring (slower)
        ctx!.beginPath();
        ctx!.arc(rip.x, rip.y, rip.r * 0.6, 0, Math.PI * 2);
        ctx!.strokeStyle = `rgba(167,139,250,${rip.life * 0.25})`;
        ctx!.lineWidth = 1.5 * rip.life;
        ctx!.stroke();
      }
    }

    function frame() {
      t += 0.007; // slightly faster than before
      ctx!.clearRect(0, 0, W, H);

      // Layer 1 — warm gold/amber (back)
      wave(
        H * 0.58, H * 0.048, 0.0048, 0.55, 0,
        "rgba(251,191,36,0.18)",
        "rgba(245,158,11,0.42)",
        -1.5,
      );

      // Layer 2 — sky blue (mid)
      wave(
        H * 0.65, H * 0.042, 0.0062, 0.72, 2.1,
        "rgba(125,211,252,0.22)",
        "rgba(56,189,248,0.52)",
        -2.5,
      );

      // Layer 3 — violet (front, most movement)
      wave(
        H * 0.72, H * 0.036, 0.0079, 0.90, 4.4,
        "rgba(196,181,253,0.20)",
        "rgba(167,139,250,0.48)",
        -3.5,
      );

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
