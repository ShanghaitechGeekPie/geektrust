import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/webui/dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      // The Go panel requires Host to equal its listen address and rejects
      // cross-origin POSTs; changeOrigin rewrites Host to the target and the
      // proxyReq hook drops the dev server's Origin header.
      "/api": {
        target: "http://127.0.0.1:8081",
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq) => {
            proxyReq.removeHeader("origin");
          });
        },
      },
    },
  },
});
