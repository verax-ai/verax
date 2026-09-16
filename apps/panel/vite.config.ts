import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = process.env.VERAX_BODY_URL ?? env.VERAX_BODY_URL ?? "http://127.0.0.1:8787";
  const toBody = { target, changeOrigin: true };
  return {
    plugins: [react()],
    resolve: {
      dedupe: ["react", "react-dom"],
    },
    server: {
      fs: { allow: ["..", "../.."] },
      proxy: {
        "/api": toBody,
        "/healthz": toBody,
        "/.well-known": toBody,
      },
    },
    preview: {
      proxy: {
        "/api": toBody,
        "/healthz": toBody,
        "/.well-known": toBody,
      },
    },
  };
});
