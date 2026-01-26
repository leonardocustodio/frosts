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
    "@frosts/core",
    "@frosts/rerandomized",
    "@noble/hashes/sha2.js",
    "@noble/curves/ed25519.js",
  ],
  platform: "neutral",
  globalName: "frostsEd25519",
  outputOptions: {
    globals: {
      "@frosts/core": "frostsCore",
      "@frosts/rerandomized": "frostsRerandomized",
      "@noble/hashes/sha2.js": "nobleHashesSha2",
      "@noble/curves/ed25519.js": "nobleCurvesEd25519",
    },
  },
});
