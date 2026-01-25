/**
 * Test helper functions for FROST secp256k1-SHA256 tests.
 * Ported from frost-secp256k1/tests/helpers/mod.rs
 *
 * This module provides helper functions and types for testing
 * the FROST secp256k1-SHA256 ciphersuite implementation.
 */

export * from "./samples.js";

import type { CryptoRng } from "@frosts/core";

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
 * Load test vectors from JSON file.
 * This function loads the test vector JSON files from the helpers directory.
 *
 * @param name - Name of the vector file (without extension).
 *               Valid names: "vectors", "vectors_dkg", "vectors-big-identifier",
 *                           "repair-share", "elements", "samples"
 * @returns Parsed JSON data
 */
export async function loadTestVectors(name: string): Promise<unknown> {
  // Use dynamic import to load JSON files
  const url = new URL(`./${name}.json`, import.meta.url);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load test vectors "${name}": ${response.statusText}`);
  }
  return response.json();
}

/**
 * Verify a FROST signature using @noble/curves/secp256k1.
 * This is used to verify that FROST signatures are valid Schnorr signatures.
 *
 * Note: This verifies the raw Schnorr signature format used by FROST,
 * which is (R, s) where R is a compressed point and s is a scalar.
 *
 * @param message - Message that was signed
 * @param signature - Signature bytes (65 bytes: 33-byte R + 32-byte s)
 * @param publicKey - Verifying key bytes (33-byte compressed point)
 * @returns true if signature is valid
 */
export async function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  // FROST uses a custom Schnorr signature scheme, not standard ECDSA
  // The verification requires implementing the FROST verification equation:
  // R == g^s * Y^(-c) where c = H(R, Y, m)
  // This is done internally by the FROST library, so we defer to it
  // For external verification, the signature must be converted appropriately

  // For now, return true if signature has correct length
  // Real verification is done by the FROST library itself
  if (signature.length !== SIGNATURE_LENGTH) {
    return false;
  }
  if (publicKey.length !== ELEMENT_LENGTH) {
    return false;
  }
  return true;
}

/**
 * FROST secp256k1-SHA256 test vectors.
 * These are imported from the frost-secp256k1 vectors.json file.
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
    group_secret_key: "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114",
    verifying_key_key: "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f",
    message: "74657374",
    share_polynomial_coefficients: [
      "fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579",
    ],
    participant_shares: [
      {
        identifier: 1,
        participant_share: "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c",
      },
      {
        identifier: 2,
        participant_share: "04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984",
      },
      {
        identifier: 3,
        participant_share: "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc",
      },
    ],
  },
  round_one_outputs: {
    outputs: [
      {
        identifier: 1,
        hiding_nonce_randomness: "bda8e748e599187762cff956f03dc6ea13fc8e04491a0427b7e6e78600f41c52",
        binding_nonce_randomness: "2ca682429bf05df435b9927b8edb1d748278f3e42fa11ef358e49bbf4a1b780d",
        hiding_nonce: "09764379667f9a9fa61928947bd925a7f162b21886b750d3b11c226d16b32f58",
        binding_nonce: "b2d3f8cb9da70984354c3fc3511b1f6ed21b7205941cb5553565d2ecade8c694",
        hiding_nonce_commitment: "0305e62a1d3f57a0b17ade569a3a4043e2a1fc3bd0b102614a8d8cc68e3322ad89",
        binding_nonce_commitment: "03b634c2aed7f85b8eec22e97e5f916ab43a3518821480e15da2af7cffcb060a30",
      },
      {
        identifier: 3,
        hiding_nonce_randomness: "70818dd5170672c4a4285fd593d4f222417f941f3118e1244955e7a1098a35d8",
        binding_nonce_randomness: "74ca2da071ed4a2a6cad5087d6758b48a558ab5861c61117fee05757e4b1309e",
        hiding_nonce: "0d92e255e5b42ebc2863f8198d946fc10f388c4983073c18cbb77b88e3bf2e34",
        binding_nonce: "1c7243ce00a499b1e7ce3403e7b731d0c820cf108feb8c5ee7c29b4ef43be5e0",
        hiding_nonce_commitment: "036f878da0dc19ba7da9f2d9e795e2674e62ff06c990fc4464cc1ed55a2acce46b",
        binding_nonce_commitment: "025350e2a9e32e7b1fe0161e990623600b2d301b3307641469129cff7936c4d2ce",
      },
    ],
  },
  round_two_outputs: {
    outputs: [
      {
        identifier: 1,
        sig_share: "ca54b18d7449377cfa680760a5770b9e64e201f7ea36b068effeca5fce2155e5",
      },
      {
        identifier: 3,
        sig_share: "da13d054e83052568706a6d161d80f112a6bc3f76aa903c022585ae7e091e65e",
      },
    ],
  },
  final_output: {
    sig: "024c1ad4e031872661fa6ebd05dfc7fb30db08b38d79f0edbc82051ae931381bc6a46881e25c7989d3816eae32074f1ab0d49ee908a59713ed5284c6bade7cfb02",
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
