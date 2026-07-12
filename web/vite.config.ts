import { defineConfig } from "vite";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import babel from "@rolldown/plugin-babel";

// https://vite.dev/config/
export default defineConfig({
    plugins: [react(), babel({ presets: [reactCompilerPreset()] })],
    build: {
        outDir: "../internal/http/web/dist",
        emptyOutDir: true,
    },
    server: {
        proxy: {
            "/api": "http://localhost:8080",
        },
    },
});
