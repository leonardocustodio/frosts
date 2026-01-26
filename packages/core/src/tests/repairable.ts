/**
 * Repairable Threshold Scheme test functions.
 * Ported from frost-core/src/tests/repairable.rs
 *
 * These are generic test functions that can be used by ciphersuite-specific
 * packages to test their RTS implementations.
 *
 * @module @frosts/core/tests/repairable
 */

import { expect } from "vitest";
import type { Ciphersuite } from "../types.js";
import type { Identifier } from "../identifier.js";
import { Identifier as IdentifierClass } from "../identifier.js";
import { FrostError } from "../error.js";
import {
  generateWithDealer,
  type KeyPackage,
  computeLagrangeCoefficient,
  identifierToString,
} from "../keys.js";
import {
  Delta,
  Sigma,
  repairShareStep1,
  repairShareStep2,
  repairShareStep3,
} from "../keys/repairable.js";
import type { CryptoRng } from "./helpers.js";
import { hexToBytes } from "./helpers.js";

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
 * Test that recovered share matches the original share.
 * Ported from check_rts in Rust.
 *
 * This test simulates:
 * 1. Key generation with 5 signers, threshold 3
 * 2. Signer 2 loses their share
 * 3. Signers 1, 4, 5 help signer 2 recover
 * 4. Verify the recovered share matches the original
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRts<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation
  const [shares, publicKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idStr, share] of shares) {
    keyPackages.set(idStr, share.toKeyPackage());
  }

  // Signer 2 will lose their share
  // Signers 1, 4, 5 will help signer 2 recover
  const id1 = IdentifierClass.fromU16(ciphersuite, 1);
  const id2 = IdentifierClass.fromU16(ciphersuite, 2);
  const id4 = IdentifierClass.fromU16(ciphersuite, 4);
  const id5 = IdentifierClass.fromU16(ciphersuite, 5);

  const helper1 = unwrap(keyPackages.get(identifierToString(id1)));
  const helper4 = unwrap(keyPackages.get(identifierToString(id4)));
  const helper5 = unwrap(keyPackages.get(identifierToString(id5)));
  const participant = unwrap(keyPackages.get(identifierToString(id2)));

  const helpers: Identifier<C>[] = [helper1.identifier, helper4.identifier, helper5.identifier];

  // Step 1: Each helper generates random values (deltas)
  const helper1Deltas = repairShareStep1(
    ciphersuite,
    helpers,
    helper1,
    rng,
    participant.identifier,
  );
  const helper4Deltas = repairShareStep1(
    ciphersuite,
    helpers,
    helper4,
    rng,
    participant.identifier,
  );
  const helper5Deltas = repairShareStep1(
    ciphersuite,
    helpers,
    helper5,
    rng,
    participant.identifier,
  );

  // Step 2: Each helper calculates sigma from the deltas received from other helpers
  // Each helper gets deltas destined for them from all helpers
  const helper1IdStr = identifierToString(helpers[0]);
  const helper4IdStr = identifierToString(helpers[1]);
  const helper5IdStr = identifierToString(helpers[2]);

  const helper1Sigma = repairShareStep2(ciphersuite, [
    unwrap(helper1Deltas.get(helper1IdStr)),
    unwrap(helper4Deltas.get(helper1IdStr)),
    unwrap(helper5Deltas.get(helper1IdStr)),
  ]);

  const helper4Sigma = repairShareStep2(ciphersuite, [
    unwrap(helper1Deltas.get(helper4IdStr)),
    unwrap(helper4Deltas.get(helper4IdStr)),
    unwrap(helper5Deltas.get(helper4IdStr)),
  ]);

  const helper5Sigma = repairShareStep2(ciphersuite, [
    unwrap(helper1Deltas.get(helper5IdStr)),
    unwrap(helper4Deltas.get(helper5IdStr)),
    unwrap(helper5Deltas.get(helper5IdStr)),
  ]);

  // Step 3: The participant recovers their share from all sigmas
  const participantRecoveredShare = repairShareStep3(
    ciphersuite,
    [helper1Sigma, helper4Sigma, helper5Sigma],
    participant.identifier,
    publicKeyPackage,
  );

  // Verify the recovered share matches the original
  expect(participant.signingShare.equals(participantRecoveredShare.signingShare)).toBe(true);
}

/**
 * Test repair_share_step_1.
 * Ported from check_repair_share_step_1 in Rust.
 *
 * This test verifies that the sum of all deltas equals
 * the Lagrange coefficient times the helper's signing share.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRepairShareStep1<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation
  const [shares, _publicKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idStr, share] of shares) {
    keyPackages.set(idStr, share.toKeyPackage());
  }

  // Signer 2 will lose their share
  // Signers 1, 4, 5 are helpers
  const id1 = IdentifierClass.fromU16(ciphersuite, 1);
  const id2 = IdentifierClass.fromU16(ciphersuite, 2);
  const id4 = IdentifierClass.fromU16(ciphersuite, 4);
  const id5 = IdentifierClass.fromU16(ciphersuite, 5);

  const helper1 = unwrap(keyPackages.get(identifierToString(id1)));
  const helper4 = unwrap(keyPackages.get(identifierToString(id4)));
  const helper5 = unwrap(keyPackages.get(identifierToString(id5)));
  const participant = unwrap(keyPackages.get(identifierToString(id2)));

  const helpers: Identifier<C>[] = [helper1.identifier, helper4.identifier, helper5.identifier];

  // Generate deltas for helper 4
  const deltas = repairShareStep1(ciphersuite, helpers, helper4, rng, participant.identifier);

  // Compute the Lagrange coefficient for helper 4
  const lagrangeCoefficient = computeLagrangeCoefficient(
    ciphersuite,
    helpers,
    participant.identifier,
    helpers[1], // helper4's identifier
  );

  // Sum all deltas
  let rhs = ciphersuite.scalarZero();
  for (const [_k, v] of deltas) {
    rhs = ciphersuite.scalarAdd(rhs, v.toScalar());
  }

  // Compute expected: lagrange_coefficient * helper4's signing share
  const lhs = ciphersuite.scalarMul(lagrangeCoefficient, helper4.signingShare.toScalar());

  // Verify: sum(deltas) == lagrange_coefficient * signing_share
  expect(ciphersuite.scalarsEqual(lhs, rhs)).toBe(true);
}

/**
 * Repair share step 2 test vector data.
 */
export interface RepairShareStep2TestData {
  scalar_generation: {
    random_scalar_1: string;
    random_scalar_2: string;
    random_scalar_3: string;
    random_scalar_sum: string;
  };
}

/**
 * Test repair_share_step_2.
 * Ported from check_repair_share_step_2 in Rust.
 *
 * This test verifies that step 2 correctly sums the delta values
 * to produce a sigma value.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param repairShareHelpers - Test vector data with scalar_generation values
 */
export function checkRepairShareStep2<C extends Ciphersuite>(
  ciphersuite: C,
  repairShareHelpers: RepairShareStep2TestData,
): void {
  const values = repairShareHelpers.scalar_generation;

  // Parse the random scalars from hex strings
  const scalar1 = ciphersuite.deserializeScalar(hexToBytes(values.random_scalar_1));
  const scalar2 = ciphersuite.deserializeScalar(hexToBytes(values.random_scalar_2));
  const scalar3 = ciphersuite.deserializeScalar(hexToBytes(values.random_scalar_3));

  // Create Delta values
  const value1 = new Delta(ciphersuite, scalar1);
  const value2 = new Delta(ciphersuite, scalar2);
  const value3 = new Delta(ciphersuite, scalar3);

  // Run step 2
  const expected = repairShareStep2(ciphersuite, [value1, value2, value3]);

  // Parse the expected sum
  const expectedScalar = ciphersuite.deserializeScalar(hexToBytes(values.random_scalar_sum));
  const actual = new Sigma(ciphersuite, expectedScalar);

  // Verify the result matches
  expect(actual.equals(expected)).toBe(true);
}

/**
 * Repair share step 3 test vector data.
 */
export interface RepairShareStep3TestData {
  sigma_generation: {
    sigma_1: string;
    sigma_2: string;
    sigma_3: string;
    sigma_4: string;
    sigma_sum: string;
  };
}

/**
 * Test repair_share_step_3.
 * Ported from check_repair_share_step_3 in Rust.
 *
 * This test verifies that step 3 correctly recovers the share
 * from the sigma values.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 * @param repairShareHelpers - Test vector data with sigma_generation values
 */
export async function checkRepairShareStep3<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
  repairShareHelpers: RepairShareStep3TestData,
): Promise<void> {
  // We need a dummy public key package to call the function
  const maxSigners = 5;
  const minSigners = 3;

  const [_shares, publicKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  const sigmas = repairShareHelpers.sigma_generation;

  // Parse sigma values from hex strings
  const sigma1 = new Sigma(ciphersuite, ciphersuite.deserializeScalar(hexToBytes(sigmas.sigma_1)));
  const sigma2 = new Sigma(ciphersuite, ciphersuite.deserializeScalar(hexToBytes(sigmas.sigma_2)));
  const sigma3 = new Sigma(ciphersuite, ciphersuite.deserializeScalar(hexToBytes(sigmas.sigma_3)));
  const sigma4 = new Sigma(ciphersuite, ciphersuite.deserializeScalar(hexToBytes(sigmas.sigma_4)));

  // Run step 3 to recover the share
  const actual = repairShareStep3(
    ciphersuite,
    [sigma1, sigma2, sigma3, sigma4],
    IdentifierClass.fromU16(ciphersuite, 2),
    publicKeyPackage,
  );

  // Parse the expected signing share scalar
  const expected = ciphersuite.deserializeScalar(hexToBytes(sigmas.sigma_sum));

  // Verify the recovered share's scalar equals the expected value
  expect(ciphersuite.scalarsEqual(expected, actual.signingShare.toScalar())).toBe(true);
}

/**
 * Test repair share step 1 fails with invalid numbers of signers.
 * Ported from check_repair_share_step_1_fails_with_invalid_min_signers in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRepairShareStep1FailsWithInvalidMinSigners<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  // Generate shares with min_signers = 2
  const maxSigners = 3;
  const minSigners = 2; // This ensures the test fails at the right point

  const [shares, _publicKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idStr, share] of shares) {
    keyPackages.set(idStr, share.toKeyPackage());
  }

  const id2 = IdentifierClass.fromU16(ciphersuite, 2);
  const id3 = IdentifierClass.fromU16(ciphersuite, 3);

  const helper = id3;
  const helperKeyPackage = unwrap(keyPackages.get(identifierToString(id3)));

  // Attempt repair with only 1 helper (less than min_signers = 2)
  // This should fail with IncorrectNumberOfIdentifiers
  expect(() => {
    repairShareStep1(ciphersuite, [helper], helperKeyPackage, rng, id2);
  }).toThrow(FrostError.incorrectNumberOfIdentifiers());
}
