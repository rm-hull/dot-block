import { tanstackRouter } from "@tanstack/router-plugin/vite";
import babel from "@rolldown/plugin-babel";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import { execSync } from "child_process";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig(() => {
  process.env.VITE_GIT_COMMIT_DATE = execSync("git log -1 --format=%cI").toString().trimEnd();
  process.env.VITE_GIT_COMMIT_HASH = execSync("git describe --always --dirty").toString().trimEnd();

  return {
    plugins: [
      tanstackRouter({ autoCodeSplitting: true }),
      react(),
      babel({ presets: [reactCompilerPreset()] }),
    ],
    build: {
      outDir: "../internal/http/web/dist",
      emptyOutDir: true,
    },
    server: {
      proxy: {
        "/whoami": "http://admin.localhost:8080",
        "/api": "http://localhost:8080",
      },
    },
    resolve: {
      tsconfigPaths: true,
    },
  };
});
