---
"@frosts/core": patch
---

Fix `@frosts/core` crashing at import time for consumers that don't have `vitest` installed.

The package barrel (`src/index.ts`) re-exported the generic test helpers via
`export * as tests from "./tests/index.js"`. Because a re-exported namespace
cannot be tree-shaken away, those helpers — and their top-level
`import { expect } from "vitest"` — were bundled into the public entry points
(`dist/index.js`, `dist/index.cjs`, `dist/index.iife.js`). Since `vitest` is
(correctly) only a dev dependency, importing `@frosts/core` — or any
`@frosts/<curve>` package that depends on it — threw
`ERR_MODULE_NOT_FOUND: Cannot find package 'vitest'` for any runtime consumer.

The test helpers are now published under a dedicated `@frosts/core/tests`
subpath instead of the main entry, so the public entry points no longer import
`vitest`. The subpath is built with code splitting so it shares the same core
runtime chunks as the main entry, preserving `instanceof` checks in the helpers.

Consumers of the generic test functions should update their imports:

```diff
-import { tests } from "@frosts/core";
+import * as tests from "@frosts/core/tests";
```
