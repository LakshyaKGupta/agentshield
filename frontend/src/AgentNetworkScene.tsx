import React, { useEffect, useRef } from "react";
import * as THREE from "three";

export default function AgentNetworkScene() {
  const hostRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const width = host.clientWidth;
    const height = host.clientHeight;
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 9);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, preserveDrawingBuffer: true });
    renderer.setClearColor(0xffffff, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);
    host.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);
    scene.add(new THREE.AmbientLight(0xffffff, 1.1));
    const point = new THREE.PointLight(0x2f80ed, 6, 24);
    point.position.set(1, 2.5, 5);
    scene.add(point);
    const goldLight = new THREE.PointLight(0xf2c94c, 4, 18);
    goldLight.position.set(-3, -1, 4);
    scene.add(goldLight);

    const positions = [
      [0, 0, 0, 0x111111, 0.52],
      [-3.0, 1.45, -0.5, 0x2f80ed, 0.27],
      [2.95, 1.22, -0.9, 0xf2c94c, 0.3],
      [-2.7, -1.65, 0.15, 0x56ccf2, 0.28],
      [2.45, -1.85, -0.25, 0xf2994a, 0.28],
      [0.15, 2.72, -0.75, 0x9bbcff, 0.23],
    ] as const;

    const nodes = positions.map(([x, y, z, color, size]) => {
      const mesh = new THREE.Mesh(
        new THREE.SphereGeometry(size, 32, 32),
        new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.45, roughness: 0.35, metalness: 0.2 })
      );
      mesh.position.set(x, y, z);
      group.add(mesh);
      return mesh;
    });

    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(0.94, 0.012, 12, 100),
      new THREE.MeshBasicMaterial({ color: 0x2f80ed, transparent: true, opacity: 0.72 })
    );
    group.add(ring);

    const outerRing = new THREE.Mesh(
      new THREE.TorusGeometry(1.28, 0.006, 12, 100),
      new THREE.MeshBasicMaterial({ color: 0xf2c94c, transparent: true, opacity: 0.42 })
    );
    outerRing.rotation.x = Math.PI / 2.4;
    group.add(outerRing);

    const material = new THREE.LineBasicMaterial({ color: 0x2f80ed, transparent: true, opacity: 0.32 });
    for (let i = 1; i < nodes.length; i += 1) {
      const geometry = new THREE.BufferGeometry().setFromPoints([nodes[0].position, nodes[i].position]);
      group.add(new THREE.Line(geometry, material));
    }

    const pulses = nodes.slice(1).map((node, index) => {
      const mesh = new THREE.Mesh(
        new THREE.SphereGeometry(0.045, 16, 16),
        new THREE.MeshBasicMaterial({ color: index === 3 ? 0xf2994a : 0x2f80ed })
      );
      group.add(mesh);
      return { mesh, target: node.position, offset: index / 5 };
    });

    const particles = new THREE.Points(
      new THREE.BufferGeometry().setAttribute(
        "position",
        new THREE.Float32BufferAttribute(Array.from({ length: 240 }, () => (Math.random() - 0.5) * 10), 3)
      ),
      new THREE.PointsMaterial({ color: 0x2f80ed, size: 0.025, transparent: true, opacity: 0.38 })
    );
    scene.add(particles);

    let frame = 0;
    const animate = () => {
      frame = requestAnimationFrame(animate);
      group.rotation.y += 0.0025;
      ring.rotation.z += 0.01;
      outerRing.rotation.y += 0.008;
      particles.rotation.y -= 0.0009;
      nodes.forEach((node, index) => {
        node.scale.setScalar(1 + Math.sin(Date.now() / 650 + index) * 0.04);
      });
      pulses.forEach(({ mesh, target, offset }) => {
        const t = (Date.now() / 1600 + offset) % 1;
        mesh.position.set(target.x * t, target.y * t, target.z * t);
      });
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frame);
      host.removeChild(renderer.domElement);
      renderer.dispose();
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Points || object instanceof THREE.Line) {
          object.geometry.dispose();
          const material = object.material;
          if (Array.isArray(material)) material.forEach((m) => m.dispose());
          else material.dispose();
        }
      });
    };
  }, []);

  return <div className="three-scene" ref={hostRef} aria-label="Animated 3D agent network" />;
}
