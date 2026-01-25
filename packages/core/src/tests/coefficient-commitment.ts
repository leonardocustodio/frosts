/**
 * Generic CoefficientCommitment test functions.
 * Ported from frost-core/src/tests/coefficient_commitment.rs
 *
 * These functions accept a Ciphersuite type parameter and can be used
 * by ciphersuite-specific packages to test their implementations.
 */

import { expect } from "vitest";
import type { Ciphersuite, CryptoRng } from "../index.js";
import { CoefficientCommitment } from "../keys.js";
import { generateElement, hexToBytes } from "./helpers.js";

/**
 * Test serialization of CoefficientCommitment.
 * Verifies that serializing a CoefficientCommitment produces the same
 * bytes as serializing the underlying element directly.
 */
export function checkSerializationOfCoefficientCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const element = generateElement(ciphersuite, rng);
  const expected = ciphersuite.serializeElement(element);
  const commitment = new CoefficientCommitment(ciphersuite, element);
  const data = commitment.serialize();

  expect(data).toEqual(expected);
}

/**
 * Test creating a CoefficientCommitment from serialized element.
 * Verifies round-trip serialization/deserialization.
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
 * Verifies that deserializing an invalid element throws an error.
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
 * Verifies that the value() method returns the original element.
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
