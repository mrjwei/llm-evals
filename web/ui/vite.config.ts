/// <reference types="vitest/config" />
// The cjp web app's interface (Plan P6). `npm run build` writes dist/, which
// `cjp ui` serves from the same origin as the API (decision 013).
//
// `npm run dev` serves the sources with hot reload on http://127.0.0.1:5173/
// and passes /api to a running `cjp ui --no-browser` on port 8738. The proxy
// keeps the browser's Origin (localhost), so the API's guard still applies.
import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: "http://127.0.0.1:8738", changeOrigin: true } },
  },
  // The main chunk (~520 kB, 160 kB gzip) loads from this Mac, not a network,
  // so Vite's 500 kB hint would only alarm someone reading the launcher window.
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false, chunkSizeWarningLimit: 800 },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
