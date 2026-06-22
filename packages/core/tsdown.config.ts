import { defineConfig } from "tsdown";

// Test dependencies — never bundled into any output. Listing them as external
// guarantees that even the `@frosts/core/tests` subpath references them via a
// bare import instead of inlining them.
const testDependencies = [
  "vitest",
  "@vitest/spy",
  "@vitest/expect",
  "@vitest/utils",
  "@vitest/pretty-format",
  "tinyrainbow",
  "chai",
  "fast-check",
];

const nodeBuiltins = /^node:/;

export default defineConfig([
  // Library build.
  //
  // The public entry (`src/index.ts`) and the generic test-helper entry
  // (`src/tests/index.ts`) are built together with code splitting enabled so
  // that the shared core runtime (types, keys, errors, …) is emitted into
  // shared chunks referenced by BOTH entries. This is what keeps a single copy
  // of classes such as `FrostError` at runtime — the test helpers rely on
  // `instanceof` checks against errors thrown by `@frosts/core`, so they must
  // not get their own duplicate copy of the runtime.
  //
  // Because `src/index.ts` no longer re-exports the test helpers, `vitest` is
  // only ever pulled into the `dist/tests/*` chunk — never into `dist/index.*`.
  {
    entry: ["src/index.ts", "src/tests/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    clean: true,
    treeshake: true,
    splitting: true,
    sourcemap: true,
    minify: false,
    target: "es2022",
    outDir: "dist",
    external: [...testDependencies, nodeBuiltins],
    platform: "neutral",
  },
  // Browser global (IIFE) build for the public entry only.
  //
  // IIFE output cannot be code-split, so it is built separately from the entry
  // above. It only contains the public API (never the test helpers), so it is
  // also free of any `vitest` import.
  {
    entry: ["src/index.ts"],
    format: ["iife"],
    dts: false,
    clean: false,
    treeshake: true,
    splitting: false,
    sourcemap: true,
    minify: false,
    target: "es2022",
    outDir: "dist",
    external: [...testDependencies, nodeBuiltins],
    platform: "neutral",
    globalName: "frostsCore",
    outputOptions: {
      globals: {
        vitest: "vitest",
      },
    },
  },
]);
