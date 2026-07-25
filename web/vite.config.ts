import { execSync } from "child_process";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import { defineConfig } from "vite";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import babel from "@rolldown/plugin-babel";

// https://vite.dev/config/
export default defineConfig(() => {
  process.env.VITE_GIT_COMMIT_DATE = execSync("git log -1 --format=%cI")
    .toString()
    .trimEnd();
  process.env.VITE_GIT_COMMIT_HASH = execSync("git describe --always --dirty")
    .toString()
    .trimEnd();

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
        "/api": "http://admin.localhost:8080",
      },
    },
    resolve: {
      tsconfigPaths: true,
    },
  };
});
