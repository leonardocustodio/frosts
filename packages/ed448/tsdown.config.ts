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
    "@noble/hashes/sha3.js",
    "@noble/curves/ed448.js",
  ],
  platform: "neutral",
  globalName: "frostsEd448",
  outputOptions: {
    globals: {
      "@frosts/core": "frostsCore",
      "@frosts/rerandomized": "frostsRerandomized",
      "@noble/hashes/sha3.js": "nobleHashesSha3",
      "@noble/curves/ed448.js": "nobleCurvesEd448",
    },
  },
});
