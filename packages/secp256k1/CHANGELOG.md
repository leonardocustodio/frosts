# @frosts/secp256k1

## 0.2.2-alpha.4

### Patch Changes

- Importing `@frosts/secp256k1` no longer crashes for consumers that do not have `vitest` installed. The crash originated in `@frosts/core` (which this package depends on), whose public entry bundled its test helpers and their `vitest` import; those helpers now live under the `@frosts/core/tests` subpath.
- Updated runtime and dev dependencies to their latest versions (`@noble/curves` & `@noble/hashes` 2.2, TypeScript 6, ESLint 10, tsdown 0.22, Vitest 4.1).
