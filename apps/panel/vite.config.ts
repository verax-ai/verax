import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const token = env.VERAX_DEV_TOKEN ?? "";
  const target = env.VERAX_BODY_URL ?? "http://127.0.0.1:8787";
  return {
    plugins: [react()],
    optimizeDeps: {
      exclude: ["@verax-ai/presence"],
    },
    resolve: {
      dedupe: ["react", "react-dom", "three"],
    },
    server: {
      proxy: {
        "/api": {
          target,
          changeOrigin: true,
          configure: (proxy) => {
            proxy.on("proxyReq", (req) => {
              if (token) req.setHeader("Authorization", `Bearer ${token}`);
            });
          },
        },
      },
    },
  };
});
