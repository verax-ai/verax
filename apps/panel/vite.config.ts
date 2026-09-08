import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const token = process.env.VERAX_DEV_TOKEN ?? env.VERAX_DEV_TOKEN ?? "";
  const target = process.env.VERAX_BODY_URL ?? env.VERAX_BODY_URL ?? "http://127.0.0.1:8787";
  return {
    plugins: [react()],
    optimizeDeps: {
      exclude: ["@verax-ai/galaxy"],
    },
    resolve: {
      dedupe: ["react", "react-dom", "three"],
    },
    server: {
      fs: { allow: ["..", "../.."] },
      proxy: {
        "/api": {
          target,
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on("proxyReq", (req) => {
              if (token && !req.getHeader("Authorization")) {
                req.setHeader("Authorization", `Bearer ${token}`);
              }
            });
          },
        },
        "/healthz": {
          target,
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on("proxyReq", (req) => {
              if (token && !req.getHeader("Authorization")) {
                req.setHeader("Authorization", `Bearer ${token}`);
              }
            });
          },
        },
        "/.well-known": {
          target,
          changeOrigin: true,
        },
      },
    },
    preview: {
      proxy: {
        "/api": {
          target,
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on("proxyReq", (req) => {
              if (token && !req.getHeader("Authorization")) {
                req.setHeader("Authorization", `Bearer ${token}`);
              }
            });
          },
        },
        "/healthz": {
          target,
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on("proxyReq", (req) => {
              if (token && !req.getHeader("Authorization")) {
                req.setHeader("Authorization", `Bearer ${token}`);
              }
            });
          },
        },
        "/.well-known": {
          target,
          changeOrigin: true,
        },
      },
    },
  };
});
