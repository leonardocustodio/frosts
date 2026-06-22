# @frosts/rerandomized

## 0.2.2-alpha.4

### Patch Changes

- Importing `@frosts/rerandomized` no longer crashes for consumers that do not have `vitest` installed. The crash originated in `@frosts/core` (which this package re-exports), whose public entry bundled its test helpers and their `vitest` import; those helpers now live under the `@frosts/core/tests` subpath.
- Updated dev dependencies to their latest versions (TypeScript 6, ESLint 10, tsdown 0.22, Vitest 4.1).
