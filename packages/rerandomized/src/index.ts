/**
 * FROST implementation supporting re-randomizable keys.
 *
 * To sign with re-randomized FROST:
 *
 * 1. Do Round 1 the same way as regular FROST;
 *
 * 2. The Coordinator should call `RandomizedParams.newFromCommitments()`
 *    and send the generated randomizer seed (the second returned value) to all
 *    participants, using a confidential channel, along with the regular
 *    SigningPackage;
 *
 * 3. Each participant should regenerate the RandomizedParams by calling
 *    `RandomizedParams.regenerateFromSeedAndCommitments()`, which they
 *    should pass to `signWithRandomizerSeed()` and send the resulting
 *    SignatureShare back to the Coordinator;
 *
 * 4. The Coordinator should then call `aggregate()`.
 *
 * @packageDocumentation
 * @module @frosts/rerandomized
 */

// Re-export everything from @frosts/core for convenience
export * from "@frosts/core";

// Export types
export type { RandomizedCiphersuite } from "./types.js";
export { isRandomizedCiphersuite } from "./types.js";

// Export Randomizer class
export { Randomizer } from "./randomizer.js";

// Export RandomizedParams class
export { RandomizedParams } from "./params.js";

// Export randomization functions
export { randomizeKeyPackage, randomizePublicKeyPackage } from "./randomize.js";

// Export signing function
export { signWithRandomizerSeed } from "./sign.js";

// Export aggregation function (rename to avoid conflict with @frosts/core aggregate)
export { aggregate as aggregateRandomized } from "./aggregate.js";

// Also export with the original name for those who want to use it directly
// They can rename in their import if there's a conflict
export { aggregate } from "./aggregate.js";
