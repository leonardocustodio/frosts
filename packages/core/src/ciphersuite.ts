/**
 * Ciphersuite re-exports for FROST
 *
 * This module re-exports the Ciphersuite interface and related types from the
 * canonical source in types.ts for backward compatibility.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9591#name-ciphersuites
 *
 * @module ciphersuite
 */

// Re-export all Ciphersuite-related types from the canonical source
export type {
  Ciphersuite,
  Field,
  Group,
  CryptoRng,
  ScalarOf,
  ElementOf,
  Scalar,
  Element,
} from "./types";
