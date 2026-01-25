/**
 * Test helper functions for FROST secp256k1-SHA256 tests.
 * Ported from frost-secp256k1/tests/helpers/mod.rs
 *
 * This module provides helper functions and types for testing
 * the FROST secp256k1-SHA256 ciphersuite implementation.
 */

export * from "./samples.js";

import type { CryptoRng } from "@frost/core";

// Re-export CryptoRng for convenience
export type { CryptoRng };

/**
 * Create a seeded RNG for deterministic testing.
 * Uses a simple counter-based approach for reproducibility.
 *
 * @param seed - Optional seed bytes. If not provided, uses a default seed.
 * @returns A deterministic random number generator
 */
export function createTestRng(seed?: Uint8Array): CryptoRng {
  let counter = 0;
  const seedArray = seed ?? new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

  return {
    fill(buffer: Uint8Array): void {
      for (let i = 0; i < buffer.length; i++) {
        // Simple deterministic byte generation based on seed and counter
        buffer[i] = (seedArray[i % seedArray.length] + counter + i) % 256;
      }
      counter++;
    },
    nextU32(): number {
      const result =
        (seedArray[counter % seedArray.length] << 24) |
        (seedArray[(counter + 1) % seedArray.length] << 16) |
        (seedArray[(counter + 2) % seedArray.length] << 8) |
        seedArray[(counter + 3) % seedArray.length];
      counter++;
      return result >>> 0;
    },
    nextU64(): bigint {
      const lo = BigInt(
        (seedArray[counter % seedArray.length] << 24) |
          (seedArray[(counter + 1) % seedArray.length] << 16) |
          (seedArray[(counter + 2) % seedArray.length] << 8) |
          (seedArray[(counter + 3) % seedArray.length] >>> 0),
      );
      const hi = BigInt(
        (seedArray[(counter + 4) % seedArray.length] << 24) |
          (seedArray[(counter + 5) % seedArray.length] << 16) |
          (seedArray[(counter + 6) % seedArray.length] << 8) |
          (seedArray[(counter + 7) % seedArray.length] >>> 0),
      );
      counter += 2;
      return (hi << 32n) | lo;
    },
  };
}

/**
 * Create a cryptographically secure RNG for production testing.
 *
 * @returns A cryptographically secure random number generator
 */
export function createSecureRng(): CryptoRng {
  return {
    fill(buffer: Uint8Array): void {
      if (
        typeof globalThis.crypto !== "undefined" &&
        globalThis.crypto.getRandomValues !== undefined
      ) {
        globalThis.crypto.getRandomValues(buffer);
      } else {
        throw new Error("No secure random source available - Web Crypto API required");
      }
    },
    nextU32(): number {
      const buffer = new Uint8Array(4);
      if (
        typeof globalThis.crypto !== "undefined" &&
        globalThis.crypto.getRandomValues !== undefined
      ) {
        globalThis.crypto.getRandomValues(buffer);
      } else {
        throw new Error("No secure random source available - Web Crypto API required");
      }
      return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    },
    nextU64(): bigint {
      const buffer = new Uint8Array(8);
      if (
        typeof globalThis.crypto !== "undefined" &&
        globalThis.crypto.getRandomValues !== undefined
      ) {
        globalThis.crypto.getRandomValues(buffer);
      } else {
        throw new Error("No secure random source available - Web Crypto API required");
      }
      const lo = BigInt(
        (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3] >>> 0),
      );
      const hi = BigInt(
        (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | (buffer[7] >>> 0),
      );
      return (hi << 32n) | lo;
    },
  };
}

/**
 * Convert hex string to Uint8Array.
 *
 * @param hex - Hexadecimal string (with or without 0x prefix)
 * @returns Byte array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string.
 *
 * @param bytes - Byte array
 * @returns Hexadecimal string (lowercase, no prefix)
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compare two Uint8Arrays for equality.
 *
 * @param a - First array
 * @param b - Second array
 * @returns true if arrays are equal, false otherwise
 */
export function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Load test vectors from JSON.
 * This is a helper for loading test vector files.
 *
 * @param name - Name of the vector file (without extension)
 * @returns Parsed JSON data
 */
export async function loadTestVectors(name: string): Promise<unknown> {
  // In a real implementation, this would load from the vectors files
  // For now, we'll import them directly in the test files
  throw new Error(`Test vectors "${name}" not yet implemented`);
}

/**
 * FROST secp256k1-SHA256 test vectors.
 * These are imported from the Rust test vector files.
 */
export const VECTORS = {
  config: {
    MAX_PARTICIPANTS: "3",
    NUM_PARTICIPANTS: "2",
    MIN_PARTICIPANTS: "2",
    name: "FROST(secp256k1, SHA-256)",
    group: "secp256k1",
    hash: "SHA-256",
  },
  inputs: {
    participant_list: [1, 3],
    // Test vectors to be filled from frost-secp256k1 vectors.json
    group_secret_key: "",
    verifying_key_key: "",
    message: "74657374",
    share_polynomial_coefficients: [] as string[],
    participant_shares: [] as Array<{
      identifier: number;
      participant_share: string;
    }>,
  },
  round_one_outputs: {
    outputs: [] as Array<{
      identifier: number;
      hiding_nonce_randomness: string;
      binding_nonce_randomness: string;
      hiding_nonce: string;
      binding_nonce: string;
      hiding_nonce_commitment: string;
      binding_nonce_commitment: string;
    }>,
  },
  round_two_outputs: {
    outputs: [] as Array<{
      identifier: number;
      sig_share: string;
    }>,
  },
  final_output: {
    sig: "",
  },
} as const;

/**
 * Ciphersuite name for secp256k1-SHA256.
 */
export const CIPHERSUITE_NAME = "FROST-secp256k1-SHA256-v1";

/**
 * Scalar byte length for secp256k1.
 */
export const SCALAR_LENGTH = 32;

/**
 * Element byte length for secp256k1 (SEC1 compressed format).
 */
export const ELEMENT_LENGTH = 33;

/**
 * Signature byte length for secp256k1 (element + scalar).
 */
export const SIGNATURE_LENGTH = ELEMENT_LENGTH + SCALAR_LENGTH; // 65 bytes
