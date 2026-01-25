/**
 * Helper functions for testing FROST ciphersuites.
 * Ported from frost-core/src/tests/helpers.rs
 */

import type { Ciphersuite } from "../src/index.js";

/**
 * Random number generator interface matching crypto RNG requirements.
 */
export interface CryptoRng {
  randomBytes(length: number): Uint8Array;
}

/**
 * Helper function for randomly generating an element.
 * Multiplies the generator by a random scalar.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - The random number generator
 * @returns A random group element
 */
export function generateElement<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): C["Element"] {
  const scalar = ciphersuite.scalarRandom(rng);
  return ciphersuite.elementMul(ciphersuite.generator(), scalar);
}

/**
 * Create a seeded RNG for deterministic testing.
 * Uses a simple counter-based approach for reproducibility.
 */
export function createTestRng(seed: Uint8Array): CryptoRng {
  let counter = 0;
  const seedArray = new Uint8Array(seed);

  return {
    randomBytes(length: number): Uint8Array {
      const result = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        // Simple deterministic byte generation based on seed and counter
        result[i] = (seedArray[i % seedArray.length] + counter + i) % 256;
      }
      counter++;
      return result;
    },
  };
}

/**
 * Create a cryptographically secure RNG for production testing.
 */
export function createSecureRng(): CryptoRng {
  return {
    randomBytes(length: number): Uint8Array {
      const result = new Uint8Array(length);
      if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues !== undefined) {
        globalThis.crypto.getRandomValues(result);
      } else {
        // Node.js environment - use crypto.getRandomValues which is available in modern Node
        throw new Error("No secure random source available - Web Crypto API required");
      }
      return result;
    },
  };
}

/**
 * Convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
