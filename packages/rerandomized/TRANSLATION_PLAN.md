# frost-rerandomized Translation Plan

This document outlines the exact 1:1 translation plan from `frost-rust/frost-rerandomized` to `@frosts/rerandomized`.

## Overview

- **Source:** `frost-rust/frost-rerandomized`
- **Target:** `packages/rerandomized`
- **Version:** 0.2.2 (derived from Rust 2.2.0)
- **Status:** ✅ COMPLETE

## File Mapping

| Rust File | TypeScript File | Status |
|-----------|-----------------|--------|
| `src/lib.rs` | `src/index.ts` + modules | ✅ Complete |
| `src/tests.rs` | `tests/rerandomized.test.ts` | ✅ Complete |
| `Cargo.toml` | `package.json` | ✅ Complete |
| `README.md` | `README.md` | ✅ Complete |

## Created Files

### Source Files
| File | Description | Status |
|------|-------------|--------|
| `src/types.ts` | RandomizedCiphersuite interface | ✅ |
| `src/randomizer.ts` | Randomizer<C> class | ✅ |
| `src/params.ts` | RandomizedParams<C> class | ✅ |
| `src/randomize.ts` | Randomize trait implementations | ✅ |
| `src/sign.ts` | signWithRandomizerSeed() | ✅ |
| `src/aggregate.ts` | aggregate() | ✅ |
| `src/index.ts` | Main entry with exports | ✅ |

### Test Files
| File | Description | Status |
|------|-------------|--------|
| `tests/rerandomized.test.ts` | All test functions | ✅ |

### Config Files
| File | Description | Status |
|------|-------------|--------|
| `package.json` | Package metadata | ✅ |
| `tsconfig.json` | TypeScript config | ✅ |
| `tsdown.config.ts` | Build config | ✅ |
| `eslint.config.mjs` | Lint config | ✅ |
| `typedoc.json` | Docs config | ✅ |
| `vitest.config.ts` | Test config | ✅ |

## API Surface (Public Exports)

```typescript
// Types
export type { RandomizedCiphersuite } from "./types";
export { isRandomizedCiphersuite } from "./types";

// Classes
export { Randomizer } from "./randomizer";
export { RandomizedParams } from "./params";

// Functions
export { randomizeKeyPackage, randomizePublicKeyPackage } from "./randomize";
export { signWithRandomizerSeed } from "./sign";
export { aggregate, aggregateRandomized } from "./aggregate";

// Re-exports from @frosts/core
export * from "@frosts/core";
```

## Verification Results

- [x] All functions exist with matching signatures
- [x] All types/interfaces match Rust traits/structs
- [x] All 8 tests pass
- [x] TypeScript compiles without errors
- [x] ESLint passes
- [x] Package builds successfully (ESM, CJS, IIFE)

## Translation Rules Applied

| Rust | TypeScript |
|------|------------|
| `snake_case` functions | `camelCase` functions |
| `PascalCase` types | `PascalCase` types |
| `Result<T, Error<C>>` | `T` (throws `FrostError<C>`) |
| `Option<T>` | `T \| null` |
| `BTreeMap` | `Map` |
| `Vec<u8>` / `&[u8]` | `Uint8Array` |
| `Self::method()` | `ClassName.method()` |

## Notes

- The deprecated `sign()` function (using Randomizer directly) was NOT translated as per Rust deprecation guidance
- The primary API is `signWithRandomizerSeed()` which uses seed-based regeneration
- `aggregate` is exported both as `aggregate` and `aggregateRandomized` to avoid conflicts with @frosts/core's aggregate
