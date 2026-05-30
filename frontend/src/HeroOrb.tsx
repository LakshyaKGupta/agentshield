import React, { useEffect, useRef } from "react";

export default function HeroOrb() {
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
      width = canvas.clientWidth || canvas.offsetWidth;
      height = canvas.clientHeight || canvas.offsetHeight;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    resize();
    window.addEventListener("resize", resize);

    const particles = Array.from({ length: 46 }, () => ({
      x: Math.random(),
      y: Math.random(),
      radius: 0.9 + Math.random() * 1.6,
      opacity: 0.08 + Math.random() * 0.2,
      phase: Math.random() * Math.PI * 2,
      speed: 0.00018 + Math.random() * 0.00008,
    }));

    let start = performance.now();

    function drawRibbon(time: number) {
      const phase = (time - start) * 0.00034;
      const baseY = height * 0.46;
      const amplitude = Math.min(width, height) * 0.035;
      const path = new Path2D();

      path.moveTo(0, height);
      path.lineTo(0, baseY + Math.sin(phase * 1.08) * amplitude * 0.8);

      const segments = 96;
      for (let i = 0; i <= segments; i += 1) {
        const x = (i / segments) * width;
        const y =
          baseY +
          Math.sin(x * 0.008 + phase) * amplitude * 1.05 +
          Math.cos(x * 0.012 - phase * 0.85) * amplitude * 0.22;
        path.lineTo(x, y);
      }

      path.lineTo(width, height);
      path.closePath();

      const ribbonGradient = ctx.createLinearGradient(0, 0, width, height);
      ribbonGradient.addColorStop(0, "rgba(249,115,22,0.28)");
      ribbonGradient.addColorStop(0.4, "rgba(59,130,246,0.18)");
      ribbonGradient.addColorStop(0.75, "rgba(255,255,255,0.12)");
      ribbonGradient.addColorStop(1, "rgba(255,255,255,0.03)");

      ctx.fillStyle = ribbonGradient;
      ctx.fill(path);

      ctx.save();
      ctx.strokeStyle = "rgba(255,255,255,0.28)";
      ctx.lineWidth = 1.5;
      ctx.stroke(path);
      ctx.restore();

      ctx.save();
      ctx.globalCompositeOperation = "screen";
      ctx.strokeStyle = "rgba(255,255,255,0.14)";
      ctx.lineWidth = 1.3;
      ctx.beginPath();
      ctx.moveTo(0, baseY + Math.sin(phase * 1.08 + 0.28) * amplitude * 0.82);
      for (let i = 0; i <= segments; i += 1) {
        const x = (i / segments) * width;
        const y =
          baseY +
          Math.sin(x * 0.008 + phase + 0.42) * amplitude * 0.78 +
          Math.cos(x * 0.012 - phase * 0.92) * amplitude * 0.08;
        ctx.lineTo(x, y);
      }
      ctx.stroke();
      ctx.restore();
    }

    function drawOrbs(time: number) {
      const orbConfigs = [
        { x: 0.32, y: 0.35, r: 0.16, colorA: "rgba(59,130,246,0.2)", colorB: "rgba(59,130,246,0)", speed: 0.00014, phase: 0 },
        { x: 0.62, y: 0.52, r: 0.12, colorA: "rgba(249,115,22,0.18)", colorB: "rgba(249,115,22,0)", speed: 0.0002, phase: 1.5 },
        { x: 0.47, y: 0.44, r: 0.08, colorA: "rgba(255,255,255,0.22)", colorB: "rgba(255,255,255,0)", speed: 0.00024, phase: 2.8 },
      ];

      for (const orb of orbConfigs) {
        const ox = width * orb.x + Math.sin(time * orb.speed * 900 + orb.phase) * width * 0.028;
        const oy = height * orb.y + Math.cos(time * orb.speed * 950 + orb.phase) * height * 0.02;
        const radius = Math.min(width, height) * orb.r;
        const gradient = ctx.createRadialGradient(ox, oy, 0, ox, oy, radius);
        gradient.addColorStop(0, orb.colorA);
        gradient.addColorStop(1, orb.colorB);
        ctx.beginPath();
        ctx.arc(ox, oy, radius, 0, Math.PI * 2);
        ctx.fillStyle = gradient;
        ctx.fill();
      }
    }

    function drawParticles(time: number) {
      particles.forEach((p) => {
        const px = (p.x + Math.cos(time * p.speed * 950 + p.phase) * 0.02) * width;
        const py = (p.y + Math.sin(time * p.speed * 1150 + p.phase) * 0.022) * height;
        ctx.beginPath();
        ctx.arc(px, py, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,255,255,${p.opacity})`;
        ctx.fill();
      });
    }

    function draw(now: number) {
      if (!ctx) return;
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = "rgba(247,245,241,0.2)";
      ctx.fillRect(0, 0, width, height);
      drawRibbon(now);
      drawOrbs(now);
      drawParticles(now);
      animId = requestAnimationFrame(draw);
    }

    draw(start);

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
