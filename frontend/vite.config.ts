import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react({
      // Use the modern automatic JSX runtime (React 17+)
      // This means you do NOT need `import React from "react"` in every file
      jsxRuntime: "automatic",
    }),
  ],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: false,
    proxy: {
      // All /api/* requests are forwarded to the FastAPI backend.
      // This makes the frontend and backend share the same origin in dev,
      // so httpOnly session cookies and CSRF double-submit cookies work
      // without any CORS relaxation.
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        // Strip the /api prefix before forwarding: /api/v1/agents → /v1/agents
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
      // WebSocket events endpoint
      "/ws": {
        target: "ws://127.0.0.1:8000",
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    target: "es2020",
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("/three/")) return "vendor-three";
          if (id.includes("/firebase/")) return "vendor-firebase";
          if (id.includes("/framer-motion/") || id.includes("/gsap/")) return "vendor-motion";
          if (id.includes("/react/") || id.includes("/react-dom/") || id.includes("/scheduler/")) return "vendor-react";
          return "vendor";
        },
      },
    },
  },
});
