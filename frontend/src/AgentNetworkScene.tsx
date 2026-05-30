import React, { useEffect, useRef } from "react";
import * as THREE from "three";

export default function AgentNetworkScene() {
  const hostRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let w = host.clientWidth;
    let h = host.clientHeight;

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x050508, 0.045);

    const camera = new THREE.PerspectiveCamera(50, w / h, 0.1, 100);
    camera.position.set(0, 1.2, 10);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(w, h);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.1;
    host.appendChild(renderer.domElement);

    // ── lights ────────────────────────────────────────────────
    scene.add(new THREE.AmbientLight(0x1a1a2e, 2));
    const blueLight = new THREE.PointLight(0x4a9eff, 8, 20);
    blueLight.position.set(-2, 3, 4);
    scene.add(blueLight);
    const goldLight = new THREE.PointLight(0xf7c948, 4, 16);
    goldLight.position.set(4, -1, 3);
    scene.add(goldLight);
    const purpleLight = new THREE.PointLight(0x8b5cf6, 3, 14);
    purpleLight.position.set(0, -3, 2);
    scene.add(purpleLight);

    // ── node positions ────────────────────────────────────────
    const NODE_DATA = [
      { pos: [0, 0, 0],        color: 0x4a9eff, emissive: 0x4a9eff, size: 0.38, label: "Shield" },
      { pos: [-3.2, 1.6, -1], color: 0x60d9fa, emissive: 0x60d9fa, size: 0.22, label: "Identity" },
      { pos: [3.0, 1.4, -1.2],color: 0xf7c948, emissive: 0xf7c948, size: 0.24, label: "Policy" },
      { pos: [-2.8,-1.8, 0.2],color: 0x8b5cf6, emissive: 0x8b5cf6, size: 0.22, label: "Ledger" },
      { pos: [2.6, -1.9,-0.4],color: 0xf97316, emissive: 0xf97316, size: 0.23, label: "Guard" },
      { pos: [0.2,  2.9,-0.8],color: 0xa3e635, emissive: 0xa3e635, size: 0.19, label: "Trust" },
    ] as const;

    const group = new THREE.Group();
    scene.add(group);

    // ── nodes (sphere + glow halo) ────────────────────────────
    const nodeMeshes = NODE_DATA.map(({ pos, color, emissive, size }) => {
      const geo = new THREE.SphereGeometry(size, 48, 48);
      const mat = new THREE.MeshStandardMaterial({
        color,
        emissive,
        emissiveIntensity: 0.7,
        roughness: 0.1,
        metalness: 0.6,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(...pos);
      group.add(mesh);

      // glow halo (larger transparent sphere)
      const haloGeo = new THREE.SphereGeometry(size * 2.2, 24, 24);
      const haloMat = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.06,
        side: THREE.BackSide,
      });
      const halo = new THREE.Mesh(haloGeo, haloMat);
      mesh.add(halo);

      return mesh;
    });

    // ── edges (animated dashed lines) ────────────────────────
    const EDGE_PAIRS = [
      [0, 1], [0, 2], [0, 3], [0, 4], [0, 5],
      [1, 3], [2, 4], [3, 5],
    ];
    const edgeMats: THREE.LineBasicMaterial[] = [];
    EDGE_PAIRS.forEach(([a, b]) => {
      const points = [
        nodeMeshes[a].position.clone(),
        nodeMeshes[b].position.clone(),
      ];
      const geo = new THREE.BufferGeometry().setFromPoints(points);
      const mat = new THREE.LineBasicMaterial({
        color: 0x4a9eff,
        transparent: true,
        opacity: 0.14,
      });
      edgeMats.push(mat);
      group.add(new THREE.Line(geo, mat));
    });

    // ── pulse travellers ──────────────────────────────────────
    const PULSE_COLOR = [0x4a9eff, 0xf7c948, 0x8b5cf6, 0x60d9fa, 0xf97316];
    const pulses = EDGE_PAIRS.map(([a, b], i) => {
      const mesh = new THREE.Mesh(
        new THREE.SphereGeometry(0.055, 16, 16),
        new THREE.MeshBasicMaterial({ color: PULSE_COLOR[i % PULSE_COLOR.length] })
      );
      group.add(mesh);
      return {
        mesh,
        from: nodeMeshes[a].position,
        to: nodeMeshes[b].position,
        t: i / EDGE_PAIRS.length,
        speed: 0.006 + Math.random() * 0.004,
        reverse: i % 2 === 0,
      };
    });

    // ── central ring ──────────────────────────────────────────
    const ring1 = new THREE.Mesh(
      new THREE.TorusGeometry(0.72, 0.008, 16, 120),
      new THREE.MeshBasicMaterial({ color: 0x4a9eff, transparent: true, opacity: 0.5 })
    );
    group.add(ring1);

    const ring2 = new THREE.Mesh(
      new THREE.TorusGeometry(0.98, 0.004, 16, 120),
      new THREE.MeshBasicMaterial({ color: 0xf7c948, transparent: true, opacity: 0.3 })
    );
    ring2.rotation.x = Math.PI / 2.6;
    group.add(ring2);

    // ── floating particles ────────────────────────────────────
    const PART_COUNT = 320;
    const partPositions = new Float32Array(PART_COUNT * 3);
    for (let i = 0; i < PART_COUNT; i++) {
      partPositions[i * 3]     = (Math.random() - 0.5) * 14;
      partPositions[i * 3 + 1] = (Math.random() - 0.5) * 10;
      partPositions[i * 3 + 2] = (Math.random() - 0.5) * 8;
    }
    const partGeo = new THREE.BufferGeometry();
    partGeo.setAttribute("position", new THREE.Float32BufferAttribute(partPositions, 3));
    const particles = new THREE.Points(
      partGeo,
      new THREE.PointsMaterial({ color: 0x4a9eff, size: 0.022, transparent: true, opacity: 0.45 })
    );
    scene.add(particles);

    // ── grid plane ────────────────────────────────────────────
    const gridHelper = new THREE.GridHelper(28, 28, 0x1a2a3a, 0x0f1a24);
    gridHelper.position.y = -4.5;
    (gridHelper.material as THREE.Material).transparent = true;
    (gridHelper.material as THREE.Material).opacity = 0.38;
    scene.add(gridHelper);

    // ── camera orbit state ────────────────────────────────────
    let mouseX = 0, mouseY = 0;
    const onMouseMove = (e: MouseEvent) => {
      mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener("mousemove", onMouseMove);

    // ── resize ────────────────────────────────────────────────
    const onResize = () => {
      if (!host) return;
      w = host.clientWidth; h = host.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener("resize", onResize);

    // ── animate ───────────────────────────────────────────────
    let frame: number;
    const clock = new THREE.Clock();

    const animate = () => {
      frame = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      // slow group rotation
      group.rotation.y = elapsed * 0.06 + mouseX * 0.18;
      group.rotation.x = Math.sin(elapsed * 0.04) * 0.06 + mouseY * 0.08;

      // rings
      ring1.rotation.z = elapsed * 0.4;
      ring2.rotation.y = elapsed * 0.3;

      // node breathe
      nodeMeshes.forEach((n, i) => {
        n.scale.setScalar(1 + Math.sin(elapsed * 1.2 + i * 1.1) * 0.05);
        (n.material as THREE.MeshStandardMaterial).emissiveIntensity =
          0.5 + Math.sin(elapsed * 1.8 + i) * 0.25;
      });

      // pulse travellers
      pulses.forEach((p) => {
        p.t += p.speed * (p.reverse ? -1 : 1);
        if (p.t > 1) { p.t = 0; p.reverse = false; }
        if (p.t < 0) { p.t = 1; p.reverse = true; }
        p.mesh.position.lerpVectors(p.from, p.to, Math.abs(p.t));
      });

      // edge pulse opacity
      edgeMats.forEach((m, i) => {
        m.opacity = 0.09 + Math.sin(elapsed * 1.4 + i * 0.7) * 0.07;
      });

      // particles drift
      particles.rotation.y = -elapsed * 0.018;
      particles.rotation.x = Math.sin(elapsed * 0.009) * 0.04;

      // camera subtle orbit
      camera.position.x += (mouseX * 0.6 - camera.position.x) * 0.04;
      camera.position.y += (-mouseY * 0.4 + 1.2 - camera.position.y) * 0.04;
      camera.lookAt(0, 0, 0);

      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("resize", onResize);
      if (host.contains(renderer.domElement)) host.removeChild(renderer.domElement);
      renderer.dispose();
      scene.traverse((obj) => {
        if (obj instanceof THREE.Mesh || obj instanceof THREE.Points || obj instanceof THREE.Line) {
          obj.geometry.dispose();
          const m = obj.material;
          if (Array.isArray(m)) m.forEach((x) => x.dispose());
          else m.dispose();
        }
      });
    };
  }, []);

  return <div ref={hostRef} style={{ width: "100%", height: "100%", position: "absolute", inset: 0 }} aria-label="Animated 3D agent security network" />;
}
