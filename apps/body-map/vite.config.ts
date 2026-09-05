import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  base: "/verax/",
  publicDir: "../panel/public",
  optimizeDeps: {
    exclude: ["@verax-ai/presence"],
  },
  resolve: {
    dedupe: ["react", "react-dom", "three"],
  },
});
