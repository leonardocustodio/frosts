/**
 * VerifiableSecretSharingCommitment functions tests.
 * Ported from frost-core/src/tests/vss_commitment.rs
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  Ristretto255Sha512,
  CoefficientCommitment,
  VerifiableSecretSharingCommitment,
  generateWithDealer,
  PublicKeyPackage,
  identifierToString,
} from "@frosts/ristretto255";
import type { CryptoRng, Ciphersuite, IdentifierList } from "../src/index.js";
import { FrostError, FrostErrorType } from "../src/error.js";
import { createSecureRng, generateElement, hexToBytes } from "./helpers.js";

/**
 * Invalid element for testing deserialization errors.
 * This is a known invalid ristretto255 point encoding.
 */
const INVALID_ELEMENT = "abcdef7de8baf62d57fe0452581b147b152f776e830c346d1119cee0bc954a59";

describe("VerifiableSecretSharingCommitment", () => {
  let rng: CryptoRng;
  const ciphersuite = Ristretto255Sha512;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize VSS commitment correctly", () => {
      // Test logic from Rust:
      // 1. Generate 3 random elements
      // 2. Create CoefficientCommitments from them
      // 3. Serialize each element individually
      // 4. Create VSS commitment and serialize
      // 5. Verify lengths match and elements match

      const input1 = generateElement(ciphersuite, rng);
      const input2 = generateElement(ciphersuite, rng);
      const input3 = generateElement(ciphersuite, rng);

      const coeffComms = [
        new CoefficientCommitment(ciphersuite, input1),
        new CoefficientCommitment(ciphersuite, input2),
        new CoefficientCommitment(ciphersuite, input3),
      ];

      const expected = [
        ciphersuite.serializeElement(input1),
        ciphersuite.serializeElement(input2),
        ciphersuite.serializeElement(input3),
      ];

      const vssCommitment = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);
      const serialized = vssCommitment.serialize();

      expect(serialized.length).toBe(expected.length);
      expected.forEach((e, i) => expect(e).toEqual(serialized[i]));
    });

    it("should serialize whole VSS commitment correctly", () => {
      // Test logic from Rust:
      // Similar to above, but use serializeWhole() which concatenates all elements

      const input1 = generateElement(ciphersuite, rng);
      const input2 = generateElement(ciphersuite, rng);
      const input3 = generateElement(ciphersuite, rng);

      const coeffComms = [
        new CoefficientCommitment(ciphersuite, input1),
        new CoefficientCommitment(ciphersuite, input2),
        new CoefficientCommitment(ciphersuite, input3),
      ];

      const expected = new Uint8Array([
        ...ciphersuite.serializeElement(input1),
        ...ciphersuite.serializeElement(input2),
        ...ciphersuite.serializeElement(input3),
      ]);

      const vssCommitment = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);
      const serialized = vssCommitment.serializeWhole();

      expect(serialized).toEqual(expected);
    });
  });

  describe("Deserialization", () => {
    it("should deserialize VSS commitment correctly", () => {
      // Test logic from Rust:
      // 1. Generate elements and create expected VSS commitment
      // 2. Serialize elements into array
      // 3. Deserialize to VSS commitment
      // 4. Verify they match

      const input1 = generateElement(ciphersuite, rng);
      const input2 = generateElement(ciphersuite, rng);
      const input3 = generateElement(ciphersuite, rng);

      const coeffComms = [
        new CoefficientCommitment(ciphersuite, input1),
        new CoefficientCommitment(ciphersuite, input2),
        new CoefficientCommitment(ciphersuite, input3),
      ];

      const expected = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);

      const data = [
        ciphersuite.serializeElement(input1),
        ciphersuite.serializeElement(input2),
        ciphersuite.serializeElement(input3),
      ];

      const result = VerifiableSecretSharingCommitment.deserialize(ciphersuite, data);
      expect(result.equals(expected)).toBe(true);
    });

    it("should deserialize whole VSS commitment correctly", () => {
      // Similar to above but using deserializeWhole with concatenated bytes

      const input1 = generateElement(ciphersuite, rng);
      const input2 = generateElement(ciphersuite, rng);
      const input3 = generateElement(ciphersuite, rng);

      const coeffComms = [
        new CoefficientCommitment(ciphersuite, input1),
        new CoefficientCommitment(ciphersuite, input2),
        new CoefficientCommitment(ciphersuite, input3),
      ];

      const expected = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);

      const data = new Uint8Array([
        ...ciphersuite.serializeElement(input1),
        ...ciphersuite.serializeElement(input2),
        ...ciphersuite.serializeElement(input3),
      ]);

      const result = VerifiableSecretSharingCommitment.deserializeWhole(ciphersuite, data);
      expect(result.equals(expected)).toBe(true);
    });
  });

  describe("Deserialization Errors", () => {
    it("should fail to deserialize with invalid element", () => {
      // Test logic from Rust:
      // Include an invalid element in the serialized data
      // Verify deserialization fails

      const input1 = generateElement(ciphersuite, rng);
      const input2 = generateElement(ciphersuite, rng);
      const input3 = generateElement(ciphersuite, rng);
      const invalidBytes = hexToBytes(INVALID_ELEMENT);

      const data = [
        ciphersuite.serializeElement(input1),
        ciphersuite.serializeElement(input2),
        ciphersuite.serializeElement(input3),
        invalidBytes,
      ];

      expect(() => {
        VerifiableSecretSharingCommitment.deserialize(ciphersuite, data);
      }).toThrow();
    });

    it("should fail to deserialize whole with invalid element", () => {
      // Similar to above but with concatenated bytes

      const input1 = generateElement(ciphersuite, rng);
      const input2 = generateElement(ciphersuite, rng);
      const input3 = generateElement(ciphersuite, rng);
      const invalidBytes = hexToBytes(INVALID_ELEMENT);

      const data = new Uint8Array([
        ...ciphersuite.serializeElement(input1),
        ...ciphersuite.serializeElement(input2),
        ...ciphersuite.serializeElement(input3),
        ...invalidBytes,
      ]);

      expect(() => {
        VerifiableSecretSharingCommitment.deserializeWhole(ciphersuite, data);
      }).toThrow();
    });

    it("should fail to deserialize whole with invalid length", () => {
      // Test logic from Rust:
      // Add an extra byte to make the length invalid
      // Should return InvalidCoefficient error

      const input1 = generateElement(ciphersuite, rng);
      const input2 = generateElement(ciphersuite, rng);
      const input3 = generateElement(ciphersuite, rng);

      const data = new Uint8Array([
        ...ciphersuite.serializeElement(input1),
        ...ciphersuite.serializeElement(input2),
        ...ciphersuite.serializeElement(input3),
        0x00, // extra byte
      ]);

      let caughtError: Error | null = null;
      try {
        VerifiableSecretSharingCommitment.deserializeWhole(ciphersuite, data);
      } catch (e) {
        caughtError = e as Error;
      }

      expect(caughtError).not.toBeNull();
      // Check error name since instanceof may fail across module boundaries
      expect(caughtError!.name).toBe("FrostError");
      expect((caughtError as unknown as { type: string }).type).toBe(FrostErrorType.InvalidCoefficient);
    });
  });

  describe("Public Key Package Computation", () => {
    it("should compute public key package from list of commitments", async () => {
      // Test logic from Rust:
      // 1. Generate shares with dealer
      // 2. Get members and group commitment
      // 3. Compute public key package from commitment
      // 4. Verify it matches the dealer's public key package

      const maxSigners = 3;
      const minSigners = 2;
      const identifiers: IdentifierList<typeof ciphersuite> = { type: "Default" };

      const [secretShares, publicKeyPackage] = await generateWithDealer(
        ciphersuite,
        maxSigners,
        minSigners,
        identifiers,
        rng,
      );

      // Get members (identifier strings) and group commitment
      const members = new Set(secretShares.keys());
      const firstShare = secretShares.values().next().value!;
      const groupCommitment = firstShare.commitment;

      // Compute public key package from commitment
      const computed = await PublicKeyPackage.fromCommitment(
        ciphersuite,
        members,
        groupCommitment,
      );

      expect(computed.equals(publicKeyPackage)).toBe(true);
    });
  });
});

// Export generic test functions for use with specific ciphersuites

/**
 * Test serialize VerifiableSecretSharingCommitment.
 */
export function checkSerializeVssCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const input1 = generateElement(ciphersuite, rng);
  const input2 = generateElement(ciphersuite, rng);
  const input3 = generateElement(ciphersuite, rng);

  const coeffComms = [
    new CoefficientCommitment(ciphersuite, input1),
    new CoefficientCommitment(ciphersuite, input2),
    new CoefficientCommitment(ciphersuite, input3),
  ];

  const expected = [
    ciphersuite.serializeElement(input1),
    ciphersuite.serializeElement(input2),
    ciphersuite.serializeElement(input3),
  ];

  const vssCommitment = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);
  const serialized = vssCommitment.serialize();

  expect(serialized.length).toBe(expected.length);
  expected.forEach((e, i) => expect(e).toEqual(serialized[i]));
}

/**
 * Test serialize_whole VerifiableSecretSharingCommitment.
 */
export function checkSerializeWholeVssCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const input1 = generateElement(ciphersuite, rng);
  const input2 = generateElement(ciphersuite, rng);
  const input3 = generateElement(ciphersuite, rng);

  const coeffComms = [
    new CoefficientCommitment(ciphersuite, input1),
    new CoefficientCommitment(ciphersuite, input2),
    new CoefficientCommitment(ciphersuite, input3),
  ];

  const expected = new Uint8Array([
    ...ciphersuite.serializeElement(input1),
    ...ciphersuite.serializeElement(input2),
    ...ciphersuite.serializeElement(input3),
  ]);

  const vssCommitment = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);
  const serialized = vssCommitment.serializeWhole();

  expect(serialized).toEqual(expected);
}

/**
 * Test deserialize VerifiableSecretSharingCommitment.
 */
export function checkDeserializeVssCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const input1 = generateElement(ciphersuite, rng);
  const input2 = generateElement(ciphersuite, rng);
  const input3 = generateElement(ciphersuite, rng);

  const coeffComms = [
    new CoefficientCommitment(ciphersuite, input1),
    new CoefficientCommitment(ciphersuite, input2),
    new CoefficientCommitment(ciphersuite, input3),
  ];

  const expected = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);

  const data = [
    ciphersuite.serializeElement(input1),
    ciphersuite.serializeElement(input2),
    ciphersuite.serializeElement(input3),
  ];

  const result = VerifiableSecretSharingCommitment.deserialize(ciphersuite, data);
  expect(result.equals(expected)).toBe(true);
}

/**
 * Test deserialize_whole VerifiableSecretSharingCommitment.
 */
export function checkDeserializeWholeVssCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const input1 = generateElement(ciphersuite, rng);
  const input2 = generateElement(ciphersuite, rng);
  const input3 = generateElement(ciphersuite, rng);

  const coeffComms = [
    new CoefficientCommitment(ciphersuite, input1),
    new CoefficientCommitment(ciphersuite, input2),
    new CoefficientCommitment(ciphersuite, input3),
  ];

  const expected = new VerifiableSecretSharingCommitment(ciphersuite, coeffComms);

  const data = new Uint8Array([
    ...ciphersuite.serializeElement(input1),
    ...ciphersuite.serializeElement(input2),
    ...ciphersuite.serializeElement(input3),
  ]);

  const result = VerifiableSecretSharingCommitment.deserializeWhole(ciphersuite, data);
  expect(result.equals(expected)).toBe(true);
}

/**
 * Test deserialize VerifiableSecretSharingCommitment error.
 */
export function checkDeserializeVssCommitmentError<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
  commitmentHelpers: { elements: { invalid_element: string } },
): void {
  const input1 = generateElement(ciphersuite, rng);
  const input2 = generateElement(ciphersuite, rng);
  const input3 = generateElement(ciphersuite, rng);
  const invalidBytes = hexToBytes(commitmentHelpers.elements.invalid_element);

  const data = [
    ciphersuite.serializeElement(input1),
    ciphersuite.serializeElement(input2),
    ciphersuite.serializeElement(input3),
    invalidBytes,
  ];

  expect(() => {
    VerifiableSecretSharingCommitment.deserialize(ciphersuite, data);
  }).toThrow();
}

/**
 * Test deserialize_whole VerifiableSecretSharingCommitment error.
 */
export function checkDeserializeWholeVssCommitmentError<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
  commitmentHelpers: { elements: { invalid_element: string } },
): void {
  const input1 = generateElement(ciphersuite, rng);
  const input2 = generateElement(ciphersuite, rng);
  const input3 = generateElement(ciphersuite, rng);
  const invalidBytes = hexToBytes(commitmentHelpers.elements.invalid_element);

  const data = new Uint8Array([
    ...ciphersuite.serializeElement(input1),
    ...ciphersuite.serializeElement(input2),
    ...ciphersuite.serializeElement(input3),
    ...invalidBytes,
  ]);

  expect(() => {
    VerifiableSecretSharingCommitment.deserializeWhole(ciphersuite, data);
  }).toThrow();
}

/**
 * Test computing the public key package from a list of commitments.
 */
export async function checkComputePublicKeyPackage<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 3;
  const minSigners = 2;
  const identifiers: IdentifierList<C> = { type: "Default" };

  const [secretShares, publicKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    identifiers,
    rng,
  );

  const members = new Set(secretShares.keys());
  const firstShare = secretShares.values().next().value!;
  const groupCommitment = firstShare.commitment;

  const computed = await PublicKeyPackage.fromCommitment(
    ciphersuite,
    members,
    groupCommitment,
  );

  expect(computed.equals(publicKeyPackage)).toBe(true);
}
