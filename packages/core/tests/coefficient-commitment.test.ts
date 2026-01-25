/**
 * CoefficientCommitment functions tests.
 * Ported from frost-core/src/tests/coefficient_commitment.rs
 */

import { describe, it, expect, beforeEach } from "vitest";
import { Ristretto255Sha512, CoefficientCommitment } from "@frosts/ristretto255";
import type { CryptoRng, Ciphersuite } from "../src/index.js";
import { createSecureRng, generateElement, hexToBytes } from "./helpers.js";

/**
 * Invalid element for testing deserialization errors.
 * This is a known invalid ristretto255 point encoding.
 */
const INVALID_ELEMENT = "abcdef7de8baf62d57fe0452581b147b152f776e830c346d1119cee0bc954a59";

describe("CoefficientCommitment", () => {
  let rng: CryptoRng;
  const ciphersuite = Ristretto255Sha512;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize a CoefficientCommitment correctly", () => {
      // Test logic from Rust:
      // 1. Generate a random element
      // 2. Serialize the element directly
      // 3. Create a CoefficientCommitment from the element
      // 4. Serialize the CoefficientCommitment
      // 5. Verify both serializations match

      const element = generateElement(ciphersuite, rng);
      const expected = ciphersuite.serializeElement(element);
      const commitment = new CoefficientCommitment(ciphersuite, element);
      const data = commitment.serialize();

      expect(data).toEqual(expected);
    });
  });

  describe("Creation", () => {
    it("should create a CoefficientCommitment from serialized element", () => {
      // Test logic from Rust:
      // 1. Generate a random element
      // 2. Create expected CoefficientCommitment directly
      // 3. Serialize the element
      // 4. Deserialize to create CoefficientCommitment
      // 5. Verify they are equal

      const element = generateElement(ciphersuite, rng);
      const expected = new CoefficientCommitment(ciphersuite, element);
      const serializedElement = ciphersuite.serializeElement(element);
      const commitment = CoefficientCommitment.deserialize(ciphersuite, serializedElement);

      expect(commitment.equals(expected)).toBe(true);
    });
  });

  describe("Error Handling", () => {
    it("should fail to deserialize an invalid element", () => {
      // Test logic from Rust:
      // Use the invalid_element from test helpers
      // Attempt to deserialize it
      // Verify it throws an error

      const serialized = hexToBytes(INVALID_ELEMENT);

      expect(() => {
        CoefficientCommitment.deserialize(ciphersuite, serialized);
      }).toThrow();
    });
  });

  describe("Value Retrieval", () => {
    it("should retrieve the element value from CoefficientCommitment", () => {
      // Test logic from Rust:
      // 1. Generate a random element
      // 2. Create a CoefficientCommitment
      // 3. Get the value back
      // 4. Verify it matches the original element

      const element = generateElement(ciphersuite, rng);
      const commitment = new CoefficientCommitment(ciphersuite, element);
      const value = commitment.value();

      expect(ciphersuite.elementsEqual(value, element)).toBe(true);
    });
  });
});

// Export generic test functions for use with specific ciphersuites

/**
 * Test serialization of CoefficientCommitment.
 */
export function checkSerializationOfCoefficientCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const element = generateElement(ciphersuite, rng);
  const expected = ciphersuite.serializeElement(element);
  const commitment = new CoefficientCommitment(ciphersuite, element);
  const data = commitment.serialize();

  expect(expected).toEqual(data);
}

/**
 * Test creating a CoefficientCommitment.
 */
export function checkCreateCoefficientCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const element = generateElement(ciphersuite, rng);
  const expected = new CoefficientCommitment(ciphersuite, element);
  const serializedElement = ciphersuite.serializeElement(element);
  const commitment = CoefficientCommitment.deserialize(ciphersuite, serializedElement);

  expect(commitment.equals(expected)).toBe(true);
}

/**
 * Test error handling for CoefficientCommitment creation.
 */
export function checkCreateCoefficientCommitmentError<C extends Ciphersuite>(
  ciphersuite: C,
  commitmentHelpers: { elements: { invalid_element: string } },
): void {
  const invalidHex = commitmentHelpers.elements.invalid_element;
  const serialized = hexToBytes(invalidHex);

  expect(() => {
    CoefficientCommitment.deserialize(ciphersuite, serialized);
  }).toThrow();
}

/**
 * Test retrieving element value from CoefficientCommitment.
 */
export function checkGetValueOfCoefficientCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const element = generateElement(ciphersuite, rng);
  const commitment = new CoefficientCommitment(ciphersuite, element);
  const value = commitment.value();

  expect(ciphersuite.elementsEqual(value, element)).toBe(true);
}
