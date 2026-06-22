# @frosts/core

## 0.2.2-alpha.4

### Patch Changes

- Fixed `@frosts/core` crashing at import time for consumers that do not have `vitest` installed. The generic, parameterized test helpers — and their top-level `vitest` import — are no longer bundled into the public entry points (`dist/index.js`, `dist/index.cjs`, `dist/index.iife.js`). They are now published under the dedicated `@frosts/core/tests` subpath instead. Consumers of the helpers should update their imports:

  ```diff
  -import { tests } from "@frosts/core";
  +import * as tests from "@frosts/core/tests";
  ```

- Updated all dependencies to their latest versions (TypeScript 6, ESLint 10, tsdown 0.22, Vitest 4.1, typedoc 0.28.19, @types/node 26).
