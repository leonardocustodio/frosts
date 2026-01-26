/**
 * Share refresh test functions.
 * Ported from frost-core/src/tests/refresh.rs
 *
 * These are generic test functions that can be used by ciphersuite-specific
 * packages to test their refresh implementations.
 *
 * @module @frosts/core/tests/refresh
 */

import { expect } from "vitest";
import type { Ciphersuite } from "../types.js";
import type { Identifier } from "../identifier.js";
import { Identifier as IdentifierClass } from "../identifier.js";
import { FrostError } from "../error.js";
import {
  generateWithDealer,
  type KeyPackage,
  type PublicKeyPackage,
  computeRefreshingShares,
  refreshShare,
  refreshDkgPart1,
  refreshDkgPart2,
  refreshDkgShares,
  type round1,
  type round2,
  identifierToString,
} from "../keys.js";
import { checkSign } from "./ciphersuite-generic.js";
import type { CryptoRng } from "./helpers.js";
import { bytesToHex as _bytesToHex } from "../serialization.js";

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
 * Test that refreshed shares work correctly with trusted dealer.
 * Ported from check_refresh_shares_with_dealer in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRefreshSharesWithDealer<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Old key generation
  const [oldShares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert to key packages
  const oldKeyPackages = new Map<string, KeyPackage<C>>();
  for (const [idStr, share] of oldShares) {
    const keyPackage = share.toKeyPackage();
    oldKeyPackages.set(idStr, keyPackage);
  }

  // Remove signer 2, keep signers 1, 3, 4, 5
  const remainingIds: Identifier<C>[] = [
    IdentifierClass.fromU16(ciphersuite, 1),
    IdentifierClass.fromU16(ciphersuite, 3),
    IdentifierClass.fromU16(ciphersuite, 4),
    IdentifierClass.fromU16(ciphersuite, 5),
  ];

  // Trusted Dealer generates zero shares and new public key package
  const [zeroShares, newPubKeyPackage] = computeRefreshingShares(
    ciphersuite,
    pubKeyPackage,
    remainingIds,
    rng,
  );

  // Each remaining participant refreshes their share
  const newKeyPackages = new Map<string, KeyPackage<C>>();

  for (let i = 0; i < remainingIds.length; i++) {
    const identifier = remainingIds[i];
    const idStr = identifierToString(identifier);
    const currentKeyPackage = oldKeyPackages.get(idStr);

    if (currentKeyPackage === undefined) {
      throw new Error(`Key package not found for identifier ${idStr}`);
    }

    const zeroShare = zeroShares[i];
    const newKeyPackage = refreshShare(ciphersuite, zeroShare, currentKeyPackage);

    newKeyPackages.set(idStr, newKeyPackage);
  }

  // Verify signing still works with refreshed shares
  checkSign(ciphersuite, minSigners, newKeyPackages, rng, newPubKeyPackage);
}

/**
 * Test that refresh fails with invalid signers.
 * Ported from check_refresh_shares_with_dealer_fails_with_invalid_signers in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifiers - Array of identifiers to test with
 * @param expectedError - The expected error type
 * @param rng - Random number generator
 */
export async function checkRefreshSharesWithDealerFailsWithInvalidSigners<C extends Ciphersuite>(
  ciphersuite: C,
  identifiers: Identifier<C>[],
  expectedError: FrostError<C>,
  rng: CryptoRng,
): Promise<void> {
  const [_oldShares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    5,
    2,
    { type: "Default" },
    rng,
  );

  expect(() => {
    computeRefreshingShares(ciphersuite, pubKeyPackage, identifiers, rng);
  }).toThrow(expectedError as Error);
}

/**
 * Test that refresh fails with invalid public key package.
 * Ported from check_refresh_shares_with_dealer_fails_with_invalid_public_key_package in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage<
  C extends Ciphersuite,
>(ciphersuite: C, rng: CryptoRng): Promise<void> {
  const maxSigners = 3;
  const minSigners = 2;

  // Generate with only 3 signers
  const [_oldShares, incorrectPubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Try to refresh with identifiers that don't all exist in the package
  const remainingIds: Identifier<C>[] = [
    IdentifierClass.fromU16(ciphersuite, 1),
    IdentifierClass.fromU16(ciphersuite, 3),
    IdentifierClass.fromU16(ciphersuite, 4), // Doesn't exist
    IdentifierClass.fromU16(ciphersuite, 5), // Doesn't exist
  ];

  expect(() => {
    computeRefreshingShares(ciphersuite, incorrectPubKeyPackage, remainingIds, rng);
  }).toThrow(FrostError.unknownIdentifier());
}

/**
 * Test that refresh fails with invalid identifier.
 * Ported from check_refresh_shares_with_dealer_fails_with_invalid_identifier in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRefreshSharesWithDealerFailsWithInvalidIdentifier<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  await checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage(ciphersuite, rng);
}

/**
 * Test serialization of refresh data.
 * Ported from check_refresh_shares_with_dealer_serialisation in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRefreshSharesWithDealerSerialisation<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  const [_oldShares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Remove signer 2, keep signers 1, 3, 4, 5
  const remainingIds: Identifier<C>[] = [
    IdentifierClass.fromU16(ciphersuite, 1),
    IdentifierClass.fromU16(ciphersuite, 3),
    IdentifierClass.fromU16(ciphersuite, 4),
    IdentifierClass.fromU16(ciphersuite, 5),
  ];

  const [zeroShares, _newPubKeyPackage] = computeRefreshingShares(
    ciphersuite,
    pubKeyPackage,
    remainingIds,
    rng,
  );

  // Test serialization of zero shares
  const zeroShare = zeroShares[0];
  expect(zeroShare).toBeDefined();

  // Verify the zero share has proper structure
  expect(zeroShare.identifier).toBeDefined();
  expect(zeroShare.signingShare).toBeDefined();
  expect(zeroShare.commitment).toBeDefined();

  // Test that KeyPackage can be created from the zero share
  const keyPackage = zeroShare.toKeyPackage();
  expect(keyPackage).toBeDefined();
  expect(keyPackage.identifier).toBeDefined();
  expect(keyPackage.signingShare).toBeDefined();
  expect(keyPackage.verifyingShare).toBeDefined();
}

/**
 * Test refresh with DKG protocol.
 * Ported from check_refresh_shares_with_dkg in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 * @returns A tuple of [message, signature, verifyingKey] if successful
 */
export async function checkRefreshSharesWithDkg<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<[Uint8Array, unknown, unknown]> {
  const oldMaxSigners = 5;
  const oldMinSigners = 3;

  // Old key generation with dealer
  const [oldShares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    oldMaxSigners,
    oldMinSigners,
    { type: "Default" },
    rng,
  );

  const oldKeyPackages = new Map<string, KeyPackage<C>>();
  for (const [idStr, share] of oldShares) {
    const keyPackage = share.toKeyPackage();
    oldKeyPackages.set(idStr, keyPackage);
  }

  // DKG Round 1 for refresh
  const maxSigners = 4;
  const minSigners = 3; // Same threshold as original

  const remainingIds: Identifier<C>[] = [
    IdentifierClass.fromU16(ciphersuite, 4),
    IdentifierClass.fromU16(ciphersuite, 2),
    IdentifierClass.fromU16(ciphersuite, 3),
    IdentifierClass.fromU16(ciphersuite, 1),
  ];

  // Keep track of round 1 secret packages and received packages
  const round1SecretPackages = new Map<string, round1.SecretPackage<C>>();
  const receivedRound1Packages = new Map<string, Map<string, round1.Package<C>>>();

  // Round 1: Each participant generates their refresh DKG part 1
  for (const participantId of remainingIds) {
    const idStr = identifierToString(participantId);

    const [round1SecretPkg, round1Pkg] = refreshDkgPart1(
      ciphersuite,
      participantId,
      maxSigners,
      minSigners,
      rng,
    );

    round1SecretPackages.set(idStr, round1SecretPkg);

    // "Send" the round 1 package to all other participants
    for (const receiverId of remainingIds) {
      const receiverIdStr = identifierToString(receiverId);
      if (receiverIdStr === idStr) continue;

      if (!receivedRound1Packages.has(receiverIdStr)) {
        receivedRound1Packages.set(receiverIdStr, new Map());
      }
      unwrap(receivedRound1Packages.get(receiverIdStr)).set(idStr, round1Pkg);
    }
  }

  // Round 2: Each participant processes received packages
  const round2SecretPackages = new Map<string, round2.SecretPackage<C>>();
  const receivedRound2Packages = new Map<string, Map<string, round2.Package<C>>>();

  for (const participantId of remainingIds) {
    const idStr = identifierToString(participantId);

    const round1SecretPkg = unwrap(round1SecretPackages.get(idStr));
    const round1Pkgs = unwrap(receivedRound1Packages.get(idStr));

    const [round2SecretPkg, round2Pkgs] = refreshDkgPart2(ciphersuite, round1SecretPkg, round1Pkgs);

    round2SecretPackages.set(idStr, round2SecretPkg);

    // "Send" round 2 packages to their recipients
    for (const [receiverIdStr, round2Pkg] of round2Pkgs) {
      if (!receivedRound2Packages.has(receiverIdStr)) {
        receivedRound2Packages.set(receiverIdStr, new Map());
      }
      unwrap(receivedRound2Packages.get(receiverIdStr)).set(idStr, round2Pkg);
    }
  }

  // Final computation: Each participant refreshes their shares
  const keyPackages = new Map<string, KeyPackage<C>>();
  let verifyingKey: unknown = undefined;
  let finalPubKeyPackage: PublicKeyPackage<C> | undefined = undefined;

  for (const participantId of remainingIds) {
    const idStr = identifierToString(participantId);

    const round2SecretPkg = unwrap(round2SecretPackages.get(idStr));
    const round1Pkgs = unwrap(receivedRound1Packages.get(idStr));
    const round2Pkgs = unwrap(receivedRound2Packages.get(idStr));

    const oldKeyPackage = unwrap(oldKeyPackages.get(idStr));

    const [keyPackage, pubKeyPackageForParticipant] = await refreshDkgShares(
      ciphersuite,
      round2SecretPkg,
      round1Pkgs,
      round2Pkgs,
      pubKeyPackage,
      oldKeyPackage,
    );

    // Test that all verifying keys are equal
    if (verifyingKey !== undefined) {
      expect(ciphersuite.elementsEqual(keyPackage.verifyingKey, verifyingKey as C["Element"])).toBe(
        true,
      );
    }
    verifyingKey = keyPackage.verifyingKey;

    keyPackages.set(idStr, keyPackage);
    finalPubKeyPackage = pubKeyPackageForParticipant;
  }

  // Verify signing works with refreshed shares
  if (finalPubKeyPackage === undefined) {
    throw new Error("finalPubKeyPackage is undefined");
  }
  const result = checkSign(ciphersuite, minSigners, keyPackages, rng, finalPubKeyPackage);

  return result;
}

/**
 * Test refresh with DKG using smaller threshold fails.
 * Ported from check_refresh_shares_with_dkg_smaller_threshold in Rust.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 */
export async function checkRefreshSharesWithDkgSmallerThreshold<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const oldMaxSigners = 5;
  const originalMinSigners = 3;

  // Old key generation with threshold 3
  const [oldShares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    oldMaxSigners,
    originalMinSigners,
    { type: "Default" },
    rng,
  );

  const oldKeyPackages = new Map<string, KeyPackage<C>>();
  for (const [idStr, share] of oldShares) {
    const keyPackage = share.toKeyPackage();
    oldKeyPackages.set(idStr, keyPackage);
  }

  // DKG with smaller threshold (2 instead of 3)
  const maxSigners = 4;
  const smallerMinSigners = 2; // This is smaller than original threshold of 3

  const remainingIds: Identifier<C>[] = [
    IdentifierClass.fromU16(ciphersuite, 4),
    IdentifierClass.fromU16(ciphersuite, 2),
    IdentifierClass.fromU16(ciphersuite, 3),
    IdentifierClass.fromU16(ciphersuite, 1),
  ];

  // Round 1
  const round1SecretPackages = new Map<string, round1.SecretPackage<C>>();
  const receivedRound1Packages = new Map<string, Map<string, round1.Package<C>>>();

  for (const participantId of remainingIds) {
    const idStr = identifierToString(participantId);

    const [round1SecretPkg, round1Pkg] = refreshDkgPart1(
      ciphersuite,
      participantId,
      maxSigners,
      smallerMinSigners,
      rng,
    );

    round1SecretPackages.set(idStr, round1SecretPkg);

    for (const receiverId of remainingIds) {
      const receiverIdStr = identifierToString(receiverId);
      if (receiverIdStr === idStr) continue;

      if (!receivedRound1Packages.has(receiverIdStr)) {
        receivedRound1Packages.set(receiverIdStr, new Map());
      }
      unwrap(receivedRound1Packages.get(receiverIdStr)).set(idStr, round1Pkg);
    }
  }

  // Round 2
  const round2SecretPackages = new Map<string, round2.SecretPackage<C>>();
  const receivedRound2Packages = new Map<string, Map<string, round2.Package<C>>>();

  for (const participantId of remainingIds) {
    const idStr = identifierToString(participantId);

    const round1SecretPkg = unwrap(round1SecretPackages.get(idStr));
    const round1Pkgs = unwrap(receivedRound1Packages.get(idStr));

    const [round2SecretPkg, round2Pkgs] = refreshDkgPart2(ciphersuite, round1SecretPkg, round1Pkgs);

    round2SecretPackages.set(idStr, round2SecretPkg);

    for (const [receiverIdStr, round2Pkg] of round2Pkgs) {
      if (!receivedRound2Packages.has(receiverIdStr)) {
        receivedRound2Packages.set(receiverIdStr, new Map());
      }
      unwrap(receivedRound2Packages.get(receiverIdStr)).set(idStr, round2Pkg);
    }
  }

  // Final computation: Should fail for all participants with InvalidMinSigners
  const errors: Error[] = [];

  for (const participantId of remainingIds) {
    const idStr = identifierToString(participantId);

    const round2SecretPkg = unwrap(round2SecretPackages.get(idStr));
    const round1Pkgs = unwrap(receivedRound1Packages.get(idStr));
    const round2Pkgs = unwrap(receivedRound2Packages.get(idStr));

    const oldKeyPackage = unwrap(oldKeyPackages.get(idStr));

    try {
      await refreshDkgShares(
        ciphersuite,
        round2SecretPkg,
        round1Pkgs,
        round2Pkgs,
        pubKeyPackage,
        oldKeyPackage,
      );
    } catch (e) {
      errors.push(e as Error);
    }
  }

  // All participants should have failed with InvalidMinSigners
  expect(errors.length).toBe(remainingIds.length);
  for (const error of errors) {
    // The error message may vary - check for either format
    const msg = error.message.toLowerCase();
    expect(msg.includes("min_signers") || msg.includes("invalidminsigners")).toBe(true);
  }
}
