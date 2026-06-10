import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// Built assets are served by tgen's Python API at /, so use relative base.
export default defineConfig({ plugins: [react()], base: "./", build: { outDir: "dist", emptyOutDir: true } });
