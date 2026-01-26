import { resolve } from "path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // Allow tests to import @frosts/ed25519 without creating a package dependency
      "@frosts/ed25519": resolve(__dirname, "../ed25519/dist/index.js"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 60_000,
  },
});
