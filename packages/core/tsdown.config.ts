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
  external: [
    // Test dependencies - not bundled into production
    "vitest",
    "@vitest/spy",
    "@vitest/expect",
    "@vitest/utils",
    "@vitest/pretty-format",
    "tinyrainbow",
    "chai",
    // Node.js built-ins
    /^node:/,
  ],
  platform: "neutral",
  globalName: "frostsCore",
  outputOptions: {
    globals: {
      vitest: "vitest",
    },
  },
});
