/**
 * Test modules for FROST-Ed25519-SHA512.
 * Ported from frost-ed25519/src/tests.rs
 *
 * This module exports all test utilities and test helpers specific to
 * the Ed25519-SHA512 ciphersuite. These tests use the generic test
 * functions from @frosts/core and apply them to the Ed25519 implementation.
 *
 * Test modules:
 * - batch: Batch signature verification tests
 * - coefficient-commitment: CoefficientCommitment serialization tests
 * - deserialize: Ed25519-specific deserialization edge cases
 * - proptests: Property-based signature tests
 * - vss-commitment: VerifiableSecretSharingCommitment tests
 */

// Coefficient commitment tests - export test data
export { ELEMENTS as COEFFICIENT_ELEMENTS } from "./coefficient-commitment.js";

// Ed25519-specific deserialization tests
export { ED25519_POINT_SIZE } from "./deserialize.js";

// Property-based tests
export { TweakType, type Tweak, SignatureCase, generateRandomTweak } from "./proptests.js";

// VSS commitment tests - export test data
export { ELEMENTS as VSS_ELEMENTS } from "./vss-commitment.js";
