/**
 * Test helper functions for FROST Ed25519-SHA512 tests.
 * Ported from frost-ed25519/tests/helpers/mod.rs
 *
 * This module provides helper functions and types for testing
 * the FROST Ed25519-SHA512 ciphersuite implementation.
 */

export * from "./samples.js";

import { ed25519 } from "@noble/curves/ed25519";
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

// ============================================================================
// Test Vector Interfaces
// ============================================================================

/**
 * Interface for test vectors configuration.
 */
export interface TestVectorsConfig {
  MAX_PARTICIPANTS: string;
  NUM_PARTICIPANTS: string;
  MIN_PARTICIPANTS: string;
  name: string;
  group: string;
  hash: string;
}

/**
 * Interface for participant share in test vectors.
 */
export interface ParticipantShare {
  identifier: number;
  participant_share: string;
}

/**
 * Interface for round one output in test vectors.
 */
export interface RoundOneOutput {
  identifier: number;
  hiding_nonce_randomness: string;
  binding_nonce_randomness: string;
  hiding_nonce: string;
  binding_nonce: string;
  hiding_nonce_commitment: string;
  binding_nonce_commitment: string;
  binding_factor_input?: string;
  binding_factor?: string;
}

/**
 * Interface for round two output in test vectors.
 */
export interface RoundTwoOutput {
  identifier: number;
  sig_share: string;
}

/**
 * Interface for test vectors inputs.
 */
export interface TestVectorsInputs {
  participant_list: number[];
  group_secret_key: string;
  verifying_key_key: string;
  message: string;
  share_polynomial_coefficients: string[];
  participant_shares: ParticipantShare[];
}

/**
 * Interface for complete test vectors.
 */
export interface TestVectors {
  config: TestVectorsConfig;
  inputs: TestVectorsInputs;
  round_one_outputs: {
    outputs: RoundOneOutput[];
  };
  round_two_outputs: {
    outputs: RoundTwoOutput[];
  };
  final_output: {
    sig: string;
  };
}

/**
 * Interface for DKG test vectors.
 */
export interface DkgTestVectors {
  config: TestVectorsConfig;
  inputs: {
    participant_list: number[];
    message: string;
  };
  round_one_outputs: {
    outputs: Array<{
      identifier: number;
      hiding_nonce: string;
      binding_nonce: string;
      hiding_nonce_commitment: string;
      binding_nonce_commitment: string;
      [key: string]: unknown;
    }>;
  };
  round_two_outputs: {
    outputs: RoundTwoOutput[];
  };
  final_output: {
    sig: string;
  };
}

/**
 * Interface for repair share test vectors.
 */
export interface RepairShareTestVectors {
  repair_share: string;
  helper_1: {
    identifier: string;
    signing_share: string;
  };
  helper_2: {
    identifier: string;
    signing_share: string;
  };
  helper_3: {
    identifier: string;
    signing_share: string;
  };
  participant: {
    identifier: string;
    signing_share: string;
  };
}

/**
 * Interface for elements test vectors.
 */
export interface ElementsTestVectors {
  elements: {
    invalid_element: string;
  };
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
 * FROST Ed25519-SHA512 test vectors.
 * These are imported from the Rust test vector files.
 */
export const VECTORS = {
  config: {
    MAX_PARTICIPANTS: "3",
    NUM_PARTICIPANTS: "2",
    MIN_PARTICIPANTS: "2",
    name: "FROST(Ed25519, SHA-512)",
    group: "ed25519",
    hash: "SHA-512",
  },
  inputs: {
    participant_list: [1, 3],
    group_secret_key:
      "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
    verifying_key_key:
      "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
    message: "74657374",
    share_polynomial_coefficients: [
      "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204",
    ],
    participant_shares: [
      {
        identifier: 1,
        participant_share:
          "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
      },
      {
        identifier: 2,
        participant_share:
          "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
      },
      {
        identifier: 3,
        participant_share:
          "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
      },
    ],
  },
  round_one_outputs: {
    outputs: [
      {
        identifier: 1,
        hiding_nonce_randomness:
          "06894e04ee4aceec8619d5f6a0a180e2f47194d2ac306cba586b555e7c48d765",
        binding_nonce_randomness:
          "40d6f879ff22e22409f7d808fed81f37118e7d3e4af71c0f44c60207553bcbce",
        hiding_nonce:
          "ef6599dea4010581a72b3018c37c29a4341d7cab0773e8687ca74dcf14009701",
        binding_nonce:
          "2baadfa0c69aa60d517ad4751de372a73f9d89cfc39026601f18458cdec12605",
        hiding_nonce_commitment:
          "9b116f12589591a7e23fe8048059ab10ab48e67739e7a2fb3890f61a7999478c",
        binding_nonce_commitment:
          "c39b66b7dfccb122da24f13587f9a08c4347cae70046ca15169adf90ba65854d",
        binding_factor_input:
          "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc93df7739fd1223d8697dfc21b1679435bafda1f92815944f28d2faf21ded33ae94a16100090ae7d83555c9b2d961e3d5d1b62828e8cb58a88a73cda404f8f725a0100000000000000000000000000000000000000000000000000000000000000",
        binding_factor:
          "ff960a65374e216a0918729b153466016664fa980d409bc3f308daa7acb30d0d",
      },
      {
        identifier: 3,
        hiding_nonce_randomness:
          "fa5d950626782aade9e33fa781376d4888c2d1de7c37518bc248eb818ed0cdde",
        binding_nonce_randomness:
          "7459a4d14ded0e365b085271be8dc6600d5b88f3978a2174297ffa32001a5afc",
        hiding_nonce:
          "80f8d9a4b8f9366e1a0b618107c907cd3ee29fa9bb40b4691cc1bde696240005",
        binding_nonce:
          "2610b664a5a187b4855e87d2ff485bebdf043dc2f161fcd4854cd01dc0276404",
        hiding_nonce_commitment:
          "e679a2a971748ccfaabead4dbe8ac1def61275c186c79d471e1e45091ad1e687",
        binding_nonce_commitment:
          "b2a942478453fabb6bd3181c56ba657413447b4136e1daea2484d396d1a516b3",
        binding_factor_input:
          "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc93df7739fd1223d8697dfc21b1679435bafda1f92815944f28d2faf21ded33ae94a16100090ae7d83555c9b2d961e3d5d1b62828e8cb58a88a73cda404f8f725a0300000000000000000000000000000000000000000000000000000000000000",
        binding_factor:
          "279d48ec56f16d234c09ea62f3d02ab776ee38e03f66b20f939f1316e13df10f",
      },
    ],
  },
  round_two_outputs: {
    outputs: [
      {
        identifier: 1,
        sig_share:
          "60997f0142e43e8005027fe5ab7447dac00d22c2d7ddd9571a02613ba7d81c08",
      },
      {
        identifier: 3,
        sig_share:
          "79390e78bc59699c7af831f8f5fb478ec871a85f561a8641b5670ac4443f720f",
      },
    ],
  },
  final_output: {
    sig: "154fb694ee7fcb37bf2381d94488c2a84b03b3352ad085feca81ad26d45852b7ecfe971ce4da95c4a95db93ac376b053897fca212ef85f99cf696bffeb178f07",
  },
} as const;

/**
 * Ciphersuite name for Ed25519-SHA512.
 */
export const CIPHERSUITE_NAME = "FROST-ED25519-SHA512-v1";

/**
 * Scalar byte length for Ed25519.
 */
export const SCALAR_LENGTH = 32;

/**
 * Element byte length for Ed25519.
 */
export const ELEMENT_LENGTH = 32;

/**
 * Verify a FROST Ed25519-SHA512 signature using @noble/curves/ed25519.
 * Ported from frost-ed25519/tests/helpers/mod.rs verify_signature().
 *
 * This function is used in interoperability tests to verify that
 * FROST signatures can be verified by standard Ed25519 libraries.
 *
 * @param msg - The message that was signed
 * @param groupSignature - The FROST group signature (object with serialize method)
 * @param groupPubkey - The FROST group public key (object with serialize method)
 * @returns true if the signature is valid
 * @throws Error if signature or public key format is invalid
 */
export function verifySignature(
  msg: Uint8Array,
  groupSignature: { serialize: () => Uint8Array },
  groupPubkey: { serialize: () => Uint8Array },
): boolean {
  const sigBytes = groupSignature.serialize();
  const pubkeyBytes = groupPubkey.serialize();

  // Verify signature length (Ed25519 signatures are 64 bytes: R || s)
  if (sigBytes.length !== 64) {
    throw new Error(`Invalid signature length: ${sigBytes.length}, expected 64`);
  }

  // Verify public key length (Ed25519 public keys are 32 bytes)
  if (pubkeyBytes.length !== 32) {
    throw new Error(`Invalid public key length: ${pubkeyBytes.length}, expected 32`);
  }

  // Use @noble/curves ed25519 verification
  return ed25519.verify(sigBytes, msg, pubkeyBytes);
}

/**
 * Verify a FROST Ed25519-SHA512 signature from raw bytes.
 * Alternative signature for verifySignature that accepts raw byte arrays.
 *
 * @param msg - The message that was signed
 * @param signature - The 64-byte serialized signature (R || s)
 * @param publicKey - The 32-byte compressed public key
 * @returns true if the signature is valid
 * @throws Error if signature or public key format is invalid
 */
export function verifySignatureBytes(
  msg: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (signature.length !== 64) {
    throw new Error(`Invalid signature length: expected 64 bytes, got ${signature.length}`);
  }
  if (publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKey.length}`);
  }

  // Use @noble/curves ed25519 verification
  return ed25519.verify(signature, msg, publicKey);
}
