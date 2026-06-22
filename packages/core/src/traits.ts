/**
 * Traits used to abstract Ciphersuites.
 *
 * This module re-exports the core trait interfaces from types.ts and provides
 * utility functions for working with them.
 *
 * @module
 */

import { FieldError, GroupError, FrostError } from "./error";

// Re-export all core types from the canonical source
export type {
  CryptoRng,
  Field,
  Group,
  ScalarOf,
  ElementOf,
  Ciphersuite,
  Scalar,
  Element,
} from "./types";

// Import types for use in utility functions
import type { Field, Ciphersuite, CryptoRng, ScalarOf, Scalar, Element } from "./types";

/**
 * Utility function to generate a random non-zero scalar.
 *
 * @param field - The field to generate a scalar for
 * @param rng - A cryptographically secure random number generator
 * @returns A random non-zero scalar
 */
export function randomNonzero<F extends Field>(field: F, rng: CryptoRng): ScalarOf<F> {
  let scalar: ScalarOf<F>;
  do {
    scalar = field.random(rng) as ScalarOf<F>;
  } while (field.isZero(scalar));
  return scalar;
}

/**
 * Default implementation of nonce generation for ciphersuites.
 *
 * @param ciphersuite - The ciphersuite
 * @param rng - A cryptographically secure random number generator
 * @returns A tuple of (nonce scalar, commitment element)
 */
export function defaultGenerateNonce<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): [Scalar<C>, Element<C>] {
  const group = ciphersuite.group;
  const field = group.field;
  const k = randomNonzero(field, rng);
  const R = group.scalarBaseMul(k);
  return [k, R];
}

/**
 * Check if a ciphersuite supports DKG.
 *
 * @param ciphersuite - The ciphersuite to check
 * @returns true if DKG is supported
 */
export function supportsDKG<C extends Ciphersuite>(ciphersuite: C): boolean {
  if (ciphersuite.HDKG === undefined) {
    return false;
  }
  // Test with empty input - if it returns null, DKG is not supported
  const result = ciphersuite.HDKG(new Uint8Array(0));
  return result !== null;
}

/**
 * Check if a ciphersuite supports identifier derivation from strings.
 *
 * @param ciphersuite - The ciphersuite to check
 * @returns true if identifier derivation is supported
 */
export function supportsIdentifierDerivation<C extends Ciphersuite>(ciphersuite: C): boolean {
  if (ciphersuite.HID === undefined) {
    return false;
  }
  // Test with empty input - if it returns null, derivation is not supported
  const result = ciphersuite.HID(new Uint8Array(0));
  return result !== null;
}

// Re-export error types for convenience
export { FieldError, GroupError, FrostError };
