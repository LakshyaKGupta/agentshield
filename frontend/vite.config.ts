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
  },
  build: {
    target: "es2020",
    sourcemap: false,
  },
});
