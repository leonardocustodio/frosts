/**
 * FROST Core - Flexible Round-Optimized Schnorr Threshold Signatures
 *
 * This module provides the core types and traits for implementing FROST
 * threshold signature schemes. It is designed to be ciphersuite-agnostic,
 * allowing different elliptic curve implementations to be plugged in.
 *
 * @module @frosts/core
 */

// Core types from types.ts - this is the canonical source for:
// - Ciphersuite, Field, Group interfaces
// - Scalar, Element, ScalarOf, ElementOf type aliases
// - CryptoRng interface
// - Challenge, BindingFactor, BindingFactorList, SigningPackage, GroupCommitment classes
// Note: Signature in types.ts is for internal use; use signature.ts for the canonical Signature
export {
  // Core interfaces
  type Ciphersuite,
  type Field,
  type Group,
  type CryptoRng,
  type ScalarOf,
  type ElementOf,
  type Scalar,
  type Element,
  type SigningPackage,
  // Duck-typing interfaces for Ciphersuite method signatures
  type IdentifierLike,
  type SigningNoncesLike,
  type SigningCommitmentsLike,
  type KeyPackageLike,
  type SignatureShareLike,
  type GroupCommitmentShareLike,
  type VerifyingShareLike,
  // FROST protocol classes
  Challenge,
  BindingFactor,
  BindingFactorList,
  GroupCommitment,
  SigningPackageImpl,
} from "./types.js";

// Error types
export * from "./error.js";

// Utility functions from traits.ts
export {
  randomNonzero,
  defaultGenerateNonce,
  supportsDKG,
  supportsIdentifierDerivation,
} from "./traits.js";

// Identifier type
export * from "./identifier.js";

// Signing key
export { SigningKey } from "./signing_key.js";

// Verifying key
export { VerifyingKey } from "./verifying_key.js";

// Signature type from signature.ts - this is the canonical Signature class
export { Signature } from "./signature.js";

// Serialization utilities
export * from "./serialization.js";

// Random number generation
export * from "./random.js";

// Scalar multiplication
export * from "./scalar_mul.js";

// Round 1 types and functions
export * from "./round1.js";

// Round 2 types and functions
export * from "./round2.js";

// Key generation and management
export * from "./keys.js";

// Batch verification
export * from "./batch.js";

// Signature aggregation
export * from "./aggregate.js";

// NOTE: The generic, parameterized test functions for ciphersuite packages are
// intentionally NOT exported from this entry point. They depend on `vitest`
// (a dev-only dependency), so re-exporting them here would force every runtime
// consumer of `@frosts/core` to have `vitest` installed. They are published
// under the dedicated `@frosts/core/tests` subpath instead:
//
//   import * as tests from "@frosts/core/tests";
//
// See ./tests/index.ts.
