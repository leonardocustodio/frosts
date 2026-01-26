/**
 * Generic VerifiableSecretSharingCommitment test functions.
 * Ported from frost-core/src/tests/vss_commitment.rs
 *
 * These functions accept a Ciphersuite type parameter and can be used
 * by ciphersuite-specific packages to test their implementations.
 */

import { expect } from "vitest";
import type { Ciphersuite, CryptoRng } from "../index.js";
import type { IdentifierList } from "../keys.js";
import {
  CoefficientCommitment,
  VerifiableSecretSharingCommitment,
  generateWithDealer,
  PublicKeyPackage,
} from "../keys.js";
import { FrostErrorType } from "../error.js";
import { generateElement, hexToBytes } from "./helpers.js";

/**
 * Helper to unwrap nullable values with an error message.
 */
function unwrap<T>(value: T | undefined | null, message = "Value is undefined"): T {
  if (value === undefined || value === null) {
    throw new Error(message);
  }
  return value;
}

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
 * Test deserialize_whole with invalid length.
 */
export function checkDeserializeWholeVssCommitmentInvalidLength<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const input1 = generateElement(ciphersuite, rng);
  const input2 = generateElement(ciphersuite, rng);
  const input3 = generateElement(ciphersuite, rng);

  const data = new Uint8Array([
    ...ciphersuite.serializeElement(input1),
    ...ciphersuite.serializeElement(input2),
    ...ciphersuite.serializeElement(input3),
    0x00, // extra byte to make length invalid
  ]);

  let caughtError: Error | null = null;
  try {
    VerifiableSecretSharingCommitment.deserializeWhole(ciphersuite, data);
  } catch (e) {
    caughtError = e as Error;
  }

  expect(caughtError).not.toBeNull();
  expect(unwrap(caughtError).name).toBe("FrostError");
  expect((caughtError as unknown as { type: string }).type).toBe(FrostErrorType.InvalidCoefficient);
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
  const firstShare = unwrap(secretShares.values().next().value);
  const groupCommitment = firstShare.commitment;

  const computed = await PublicKeyPackage.fromCommitment(ciphersuite, members, groupCommitment);

  expect(computed.equals(publicKeyPackage)).toBe(true);
}
