import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs", "iife"],
  dts: true,
  clean: true,
  treeshake: true,
  splitting: false,
  sourcemap: true,
  minify: false,
  target: "es2022",
  outDir: "dist",
  deps: {
    neverBundle: ["@frosts/core"],
  },
  platform: "neutral",
  globalName: "frostsRerandomized",
  outputOptions: {
    globals: {
      "@frosts/core": "frostsCore",
    },
  },
});
