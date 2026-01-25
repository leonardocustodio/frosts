/**
 * Test modules for FROST-Ed448-SHAKE256.
 * Ported from frost-ed448/src/tests.rs
 *
 * This module exports all test utilities and test helpers specific to
 * the Ed448-SHAKE256 ciphersuite. These tests use the generic test
 * functions from @frost/core and apply them to the Ed448 implementation.
 *
 * Test modules:
 * - batch: Batch signature verification tests
 * - coefficient-commitment: CoefficientCommitment serialization tests
 * - deserialize: Ed448-specific deserialization edge cases
 * - proptests: Property-based signature tests
 * - vss-commitment: VerifiableSecretSharingCommitment tests
 */

// Coefficient commitment tests - export test data
export { ELEMENTS as COEFFICIENT_ELEMENTS } from "./coefficient-commitment.js";

// Ed448-specific deserialization tests
export { ED448_POINT_SIZE } from "./deserialize.js";

// Property-based tests
export {
  TweakType,
  type Tweak,
  SignatureCase,
  generateRandomTweak,
} from "./proptests.js";

// VSS commitment tests - export test data
export { ELEMENTS as VSS_ELEMENTS } from "./vss-commitment.js";
