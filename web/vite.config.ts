import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";
import { panelFonts } from "./build/fonts";

export default defineConfig(({ command }) => ({
  plugins: [panelFonts(), react(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "@panel-fonts": fileURLToPath(new URL(
        `./.generated/${command === "serve" ? "fonts-dev" : "fonts"}/noto-sans-sc.css`,
        import.meta.url,
      )),
    },
  },
  build: {
    outDir: "../internal/webui/dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
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
}));
