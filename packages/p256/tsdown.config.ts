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
    neverBundle: [
      "@frosts/core",
      "@frosts/rerandomized",
      "@noble/hashes/sha2.js",
      "@noble/curves/nist.js",
    ],
  },
  platform: "neutral",
  globalName: "frostsP256",
  outputOptions: {
    globals: {
      "@frosts/core": "frostsCore",
      "@frosts/rerandomized": "frostsRerandomized",
      "@noble/hashes/sha2.js": "nobleHashesSha2",
      "@noble/curves/nist.js": "nobleCurvesNist",
    },
  },
});
