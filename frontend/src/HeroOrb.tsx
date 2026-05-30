import React, { useEffect, useRef } from "react";

export default function HeroOrb() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let w = 0, h = 0;

    function resize() {
      if (!canvas) return;
      w = canvas.offsetWidth;
      h = canvas.offsetHeight;
      canvas.width = w * window.devicePixelRatio;
      canvas.height = h * window.devicePixelRatio;
      ctx!.scale(window.devicePixelRatio, window.devicePixelRatio);
    }

    resize();
    window.addEventListener("resize", resize);

    // Orb parameters
    const orbs = [
      { x: 0.5, y: 0.52, r: 0.38, colorA: "rgba(47,128,237,0.13)", colorB: "rgba(242,201,76,0.06)", speed: 0.00018, phase: 0 },
      { x: 0.5, y: 0.52, r: 0.24, colorA: "rgba(47,128,237,0.10)", colorB: "rgba(47,128,237,0.0)", speed: 0.00024, phase: 1.2 },
      { x: 0.5, y: 0.52, r: 0.14, colorA: "rgba(200,220,255,0.18)", colorB: "rgba(255,255,255,0.0)", speed: 0.00030, phase: 2.5 },
    ];

    // Particle field
    const N = 60;
    const particles = Array.from({ length: N }, () => ({
      x: Math.random(),
      y: Math.random(),
      size: 0.5 + Math.random() * 1.2,
      opacity: 0.12 + Math.random() * 0.18,
      speed: 0.00004 + Math.random() * 0.00008,
      angle: Math.random() * Math.PI * 2,
    }));

    let t = 0;

    function draw() {
      if (!ctx) return;
      ctx.clearRect(0, 0, w, h);

      // Draw orbs
      for (const orb of orbs) {
        const ox = w * orb.x + Math.sin(t * orb.speed * 1000 + orb.phase) * w * 0.04;
        const oy = h * orb.y + Math.cos(t * orb.speed * 900 + orb.phase) * h * 0.025;
        const r = Math.min(w, h) * orb.r;
        const grad = ctx.createRadialGradient(ox, oy, 0, ox, oy, r);
        grad.addColorStop(0, orb.colorA);
        grad.addColorStop(1, orb.colorB);
        ctx.beginPath();
        ctx.arc(ox, oy, r, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();
      }

      // Draw particles
      for (const p of particles) {
        p.angle += p.speed;
        const px = (p.x + Math.cos(p.angle) * 0.015) * w;
        const py = (p.y + Math.sin(p.angle * 1.3) * 0.012) * h;
        ctx.beginPath();
        ctx.arc(px, py, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(47,128,237,${p.opacity})`;
        ctx.fill();
      }

      t = Date.now();
      animId = requestAnimationFrame(draw);
    }

    draw();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", resize);
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
