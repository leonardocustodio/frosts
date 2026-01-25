/**
 * Types for the FROST rerandomized signature scheme.
 *
 * This module defines the RandomizedCiphersuite interface which extends
 * the base Ciphersuite with support for rerandomization.
 *
 * @module types
 */

import type { Ciphersuite } from "@frosts/core";

/**
 * A Ciphersuite that supports rerandomization.
 *
 * This interface extends the base Ciphersuite with an additional hash function
 * that maps arbitrary inputs to a randomizer scalar.
 *
 * @typeParam C - The underlying ciphersuite type
 */
export interface RandomizedCiphersuite extends Ciphersuite {
  /**
   * A hash function that hashes into a randomizer scalar.
   *
   * Maps arbitrary inputs to Scalar elements of the prime-order group scalar field.
   * Returns null if the hash fails (e.g., if the result is zero or invalid).
   *
   * @param m - The input bytes to hash
   * @returns The randomizer scalar, or null if hashing fails
   */
  hashRandomizer(m: Uint8Array): this["Scalar"] | null;
}

/**
 * Type guard to check if a ciphersuite supports rerandomization.
 *
 * @param ciphersuite - The ciphersuite to check
 * @returns True if the ciphersuite supports rerandomization
 */
export function isRandomizedCiphersuite(
  ciphersuite: Ciphersuite,
): ciphersuite is RandomizedCiphersuite {
  return typeof (ciphersuite as RandomizedCiphersuite).hashRandomizer === "function";
}
