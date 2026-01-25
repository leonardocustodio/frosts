/**
 * Test helper functions for FROST Ed448 tests.
 * Ported from frost-ed448/tests/helpers/mod.rs
 *
 * This module provides helper functions and types for testing
 * the FROST Ed448 ciphersuite implementation.
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
 * FROST Ed448 test vectors.
 * These are imported from the Rust test vector files.
 */
export const VECTORS = {
  config: {
    MAX_PARTICIPANTS: "3",
    NUM_PARTICIPANTS: "2",
    MIN_PARTICIPANTS: "2",
    name: "FROST(Ed448, SHAKE256)",
    group: "ed448",
    hash: "SHAKE256",
  },
  inputs: {
    participant_list: [1, 3],
    group_secret_key:
      "6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c00",
    verifying_key_key:
      "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000",
    message: "74657374",
    share_polynomial_coefficients: [
      "dbd7a514f7a731976620f0436bd135fe8dddc3fadd6e0d13dbd58a1981e587d377d48e0b7ce4e0092967c5e85884d0275a7a740b6abdcd0500",
    ],
    participant_shares: [
      {
        identifier: 1,
        participant_share:
          "4a2b2f5858a932ad3d3b18bd16e76ced3070d72fd79ae4402df201f525e754716a1bc1b87a502297f2a99d89ea054e0018eb55d39562fd0100",
      },
      {
        identifier: 2,
        participant_share:
          "2503d56c4f516444a45b080182b8a2ebbe4d9b2ab509f25308c88c0ea7ccdc44e2ef4fc4f63403a11b116372438a1e287265cadeff1fcb0700",
      },
      {
        identifier: 3,
        participant_share:
          "00db7a8146f995db0a7cf844ed89d8e94c2b5f259378ff66e39d172828b264185ac4decf7219e4aa4478285b9c0eef4fccdf3eea69dd980d00",
      },
    ],
  },
  round_one_outputs: {
    outputs: [
      {
        identifier: 1,
        hiding_nonce_randomness: "3d9e765ab0f06bc3131acc2f7642223255fd5295f3c04bef5c644c0bae4f85be",
        binding_nonce_randomness: "86160f8224ea273128b0ea5af828a9c0b0985cd9b52a3b8b668ae9d3205a6672",
        hiding_nonce:
          "d9610abd59ac2e9b33a3919acf28f5c895918389c69a26a3fcfe6a70edab4685e9ea3d3641d8bfe1634616fafd457b2ef6503c51f191991300",
        binding_nonce:
          "1caf737f1e73b5ab7f155c239ea70fb5783cd8da454298984a325cb4eb968b0e625936cbb9623e57919b3cc01be40f7f45b6c37fd947772b00",
        hiding_nonce_commitment:
          "2afe1a6d56ee111e7e4b84060c07044643434362edbce8f79f568236884c1c16883e9a4d3f42029f324619b32587d501609941bab590682000",
        binding_nonce_commitment:
          "605d2b3b5af4159ca3fa23e4463a3573d4144b43c7b01322d621817c80fcd84f874ea79655648ca65f128a4cfbec236c0c89f3898b27529180",
      },
      {
        identifier: 3,
        hiding_nonce_randomness: "8cba373b6c3a3601d5cfa3d37cbc93f310d253a2fcf886695bb59ac703d8a100",
        binding_nonce_randomness: "1a84c88d88fbb99a4417157487b45367eb91d7dd2ba55566d6784f39f750a2f7",
        hiding_nonce:
          "3a8f5b86cf6e80d3a2d99ac5628a1229eaa9dd205b3b3bdd3bc8d2270c749d08836379c8b50d964f492ba8785f3deb571e0b4e7db887be1400",
        binding_nonce:
          "4b529518068f9b261d56cffced7f753b9b22db6a79c8c495584ec67edc561da644b70f9af42e633e14bc145b3ea61c5d2bf30090c3700b2f00",
        hiding_nonce_commitment:
          "3f06fbce6ca0f92331e97946e27c649e9fdb96f1ba1061189495bcd6d019e7915de818c3901b9d5d0e2de062ddeca7a40bbd84c9ffbc983900",
        binding_nonce_commitment:
          "ef2f07a309be3c8936c505b385dee51f319ebb9bf26520ed5579c9b3ede6467968d969fc3c7b34d704b86547e8ae11dcdae9fdc0794e642380",
      },
    ],
  },
  round_two_outputs: {
    outputs: [
      {
        identifier: 1,
        sig_share:
          "0dad0c550bade2576c6cbe1d7b57a55b00e57a6e3683c8f84fbfa48751745bb0b2b89624e7d1b443b1ff62ffde9ee0c15e5df678c4ed1c0400",
      },
      {
        identifier: 3,
        sig_share:
          "0baf31c64cf452fe3a520f14c5e2b898d6869341fdd8ea26044086a11a4372cd31ba2ee9cf7e316706067a53d05e184ebb95cae16aac7f3700",
      },
    ],
  },
  final_output: {
    sig: "60e3d4d641dd19054c1eced47f02f4a5e377126fb75f68cbd1122d948f93e26069f6740506da0366eb4225746faf894ecd196a1f56d1e1d280185c3e1b58a13556a7becd31403a5ef4d66b0eb0335cb31f54ff2a296cb7cd7de472c50db750e6aab705dd52affdf80f1af3c05a2f9a9c3b00",
  },
} as const;

/**
 * Ciphersuite name for Ed448-SHAKE256.
 */
export const CIPHERSUITE_NAME = "FROST-ED448-SHAKE256-v1";

/**
 * Scalar byte length for Ed448.
 */
export const SCALAR_LENGTH = 57;

/**
 * Element byte length for Ed448.
 */
export const ELEMENT_LENGTH = 57;
