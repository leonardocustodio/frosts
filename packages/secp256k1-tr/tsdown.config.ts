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
      "@noble/curves/secp256k1.js",
    ],
  },
  platform: "neutral",
  globalName: "frostsSecp256k1Tr",
  outputOptions: {
    globals: {
      "@frosts/core": "frostsCore",
      "@frosts/rerandomized": "frostsRerandomized",
      "@noble/hashes/sha2.js": "nobleHashesSha2",
      "@noble/curves/secp256k1.js": "nobleCurvesSecp256k1",
    },
  },
});
