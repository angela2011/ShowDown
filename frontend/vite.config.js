import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { apiProxy } from "./proxy.config.js";
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [react()],
    server: {
      proxy: {
        "/api": apiProxy(env),
      },
    },
  };
});
