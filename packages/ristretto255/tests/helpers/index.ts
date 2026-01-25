/**
 * Test helper functions for FROST Ristretto255-SHA512 tests.
 * Ported from frost-ristretto255/tests/helpers/mod.rs
 *
 * This module provides helper functions and types for testing
 * the FROST Ristretto255-SHA512 ciphersuite implementation.
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
 * FROST Ristretto255-SHA512 test vectors.
 * These are imported from the Rust test vector files.
 */
export const VECTORS = {
  config: {
    MAX_PARTICIPANTS: "3",
    NUM_PARTICIPANTS: "2",
    MIN_PARTICIPANTS: "2",
    name: "FROST(ristretto255, SHA-512)",
    group: "ristretto255",
    hash: "SHA-512",
  },
  inputs: {
    participant_list: [1, 3],
    group_secret_key:
      "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
    verifying_key_key:
      "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
    message: "74657374",
    share_polynomial_coefficients: [
      "410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02",
    ],
    participant_shares: [
      {
        identifier: 1,
        participant_share:
          "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
      },
      {
        identifier: 2,
        participant_share:
          "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01",
      },
      {
        identifier: 3,
        participant_share:
          "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
      },
    ],
  },
  round_one_outputs: {
    outputs: [
      {
        identifier: 1,
        hiding_nonce_randomness:
          "4366eff4b4676f97822998ec3e5af1388131bffa3db76e54ee19805f0e778f33",
        binding_nonce_randomness:
          "173a02012818fbb58ed70b2dc620bb22e2d144d8c3953479e213ed7323f0270a",
        hiding_nonce:
          "b16f611649233ec528d20759e8cf828c12630a3b73996a643e59a5eda63c8b05",
        binding_nonce:
          "0cfb25a32975cc397e86509cdeb461d83d5021e4101c9554bd0b33b776645e09",
        hiding_nonce_commitment:
          "4818a19481eddc359c299dc101a84820423fcbe4b08badfa78c24b4de56c022e",
        binding_nonce_commitment:
          "f6df3b1ca00c88b7688a6ebffd6eb2d81a3d1305342ec69cc24cb4558bc2b41b",
      },
      {
        identifier: 3,
        hiding_nonce_randomness:
          "ca93286a68e79bd850839fd4fb4498fbee1bae3829f5dbd9e447860925e556cc",
        binding_nonce_randomness:
          "598dce485138d86ddecebb5c0cfa112ac114eb35fcded3cf69ad915c7abeb425",
        hiding_nonce:
          "4388f2f9912a8d2af3e9a655ce20c4eeb4a8c31df626cf628996f770b156b104",
        binding_nonce:
          "c680e9639176fd17747a915864299a3ad8fbd85883271d85726f311c94ed0604",
        hiding_nonce_commitment:
          "52554f07003db6c789b867872a762bbd5efc5fb699dc8213863369d66117142c",
        binding_nonce_commitment:
          "e0842fef27f9ccc38fbe93c73eb1f04d1de6c917b35aafffc8ffc7c02889cd70",
      },
    ],
  },
  round_two_outputs: {
    outputs: [
      {
        identifier: 1,
        sig_share:
          "1f5adbfd775a95ce4c95c7d81b3898d89bdce160adece3168b38dc9367a20502",
      },
      {
        identifier: 3,
        sig_share:
          "34c974f623cd0b5563334afc2a395ee86c0638136d6cad74240478c13d4a2101",
      },
    ],
  },
  final_output: {
    sig: "fa954853693068803615803a06e2c23a6228f7d6d6b442b72b26696aa776fe75532350f49b27a123b0c811d54671f6c008e319741a59918baf3c5455a5ec2603",
  },
} as const;

/**
 * Ciphersuite name for Ristretto255-SHA512.
 */
export const CIPHERSUITE_NAME = "FROST-RISTRETTO255-SHA512-v1";

/**
 * Scalar byte length for Ristretto255.
 */
export const SCALAR_LENGTH = 32;

/**
 * Element byte length for Ristretto255.
 */
export const ELEMENT_LENGTH = 32;
