/**
 * Test for Refreshing shares.
 * Ported from frost-core/src/tests/refresh.rs
 *
 * This module tests share refresh functionality that allows participants
 * to update their shares while maintaining the same group public key.
 * This is useful for:
 * - Rotating shares for security
 * - Changing the set of participants
 * - Changing the threshold
 */

import { describe, it, expect, beforeEach } from "vitest";
import type { CryptoRng } from "./helpers.js";
import { createSecureRng } from "./helpers.js";
import { checkPart3DifferentParticipants } from "./ciphersuite-generic.test.js";

// Types will be imported from actual implementation once available
import type {
  Ciphersuite,
  Identifier,
  KeyPackage,
  SecretShare,
  PublicKeyPackage,
  Signature,
  VerifyingKey,
  Error as FrostError,
} from "../src/index.js";

describe("Share Refresh", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Refresh with Trusted Dealer", () => {
    it.skip("should refresh shares and maintain valid signing", () => {
      // Test logic from Rust check_refresh_shares_with_dealer:
      //
      // 1. Old Key Generation (5 max, 3 min signers)
      //    - Generate shares with dealer
      //    - Convert to key packages
      //
      // 2. New Key Generation
      //    - Remove signer 2, keep signers 1, 3, 4, 5
      //    - Dealer generates zero shares and new public key package
      //
      // 3. Each remaining participant refreshes their share
      //    - Combine old share with zero share
      //
      // 4. Verify signing still works with refreshed shares

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should serialize and deserialize refresh data correctly", () => {
      // Test serialization roundtrip for:
      // - Zero shares
      // - New public key package
      // - Refreshed key packages

      expect(true).toBe(true); // Placeholder
    });
  });

  describe("Refresh with DKG", () => {
    it.skip("should complete refresh flow using DKG protocol", () => {
      // Test logic from Rust check_refresh_shares_with_dkg:
      //
      // 1. Old Key Generation with dealer
      //
      // 2. DKG Round 1 for refresh
      //    - Each remaining participant runs refresh_dkg_part1
      //    - Broadcast round 1 packages
      //
      // 3. DKG Round 2 for refresh
      //    - Each participant runs refresh_dkg_part2
      //    - Send round 2 packages
      //
      // 4. Final computation
      //    - Each participant runs refresh_dkg_shares
      //    - Combines DKG output with old share
      //
      // 5. Verify all participants have same verifying key
      // 6. Verify signing works with refreshed shares

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should fail with different participant sets in DKG round 3", () => {
      // Test that using different participant sets fails correctly

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should fail when using smaller threshold than original", () => {
      // Test logic from Rust check_refresh_shares_with_dkg_smaller_threshold:
      //
      // 1. Generate with threshold 3
      // 2. Attempt refresh with threshold 2
      // 3. Should fail with InvalidMinSigners error

      expect(true).toBe(true); // Placeholder
    });
  });

  describe("Error Cases", () => {
    it.skip("should fail with duplicate identifiers", () => {
      // const identifiers = [id1, id1, id3, id4]; // duplicate id1
      // const result = computeRefreshingShares(pubKeyPackage, identifiers, rng);
      // expect(result.error).toEqual(FrostError.DuplicatedIdentifier);

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should fail with unknown identifier", () => {
      // Use identifiers not in the original public key package
      // Should fail with UnknownIdentifier error

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should fail with insufficient signers", () => {
      // const result = computeRefreshingShares(pubKeyPackage, [id1], rng); // only 1
      // expect(result.error).toEqual(FrostError.InvalidMinSigners);

      expect(true).toBe(true); // Placeholder
    });
  });
});

// Export generic test functions for use with specific ciphersuites

/**
 * Test that refreshed shares work correctly with trusted dealer.
 */
export function checkRefreshSharesWithDealer<C extends Ciphersuite>(
  _ciphersuite: C,
  _rng: CryptoRng,
): void {
  // Implementation will be added when types are available
  // const maxSigners = 5;
  // const minSigners = 3;
  // // Old key generation
  // const [oldShares, pubKeyPackage] = frost.keys.generateWithDealer(
  //   maxSigners, minSigners, IdentifierList.Default, rng
  // );
  // const oldKeyPackages = new Map(
  //   [...oldShares].map(([id, share]) => [id, share.toKeyPackage()])
  // );
  // // Remove signer 2, keep 1, 3, 4, 5
  // const remainingIds = [
  //   Identifier.tryFrom(1),
  //   Identifier.tryFrom(3),
  //   Identifier.tryFrom(4),
  //   Identifier.tryFrom(5),
  // ];
  // // Generate zero shares and new public key package
  // const [zeroShares, newPubKeyPackage] = frost.keys.refresh.computeRefreshingShares(
  //   pubKeyPackage, remainingIds, rng
  // );
  // // Serialization roundtrip
  // const newPubKeyPackageRoundtrip = PublicKeyPackage.deserialize(
  //   newPubKeyPackage.serialize()
  // );
  // // Each participant refreshes their share
  // const newShares = new Map();
  // for (let i = 0; i < remainingIds.length; i++) {
  //   const id = remainingIds[i];
  //   const currentShare = oldKeyPackages.get(id);
  //   const zeroShare = SecretShare.deserialize(zeroShares[i].serialize());
  //   const newShare = frost.keys.refresh.refreshShare(zeroShare, currentShare);
  //   newShares.set(id, newShare);
  // }
  // // Convert to key packages
  // const keyPackages = new Map(
  //   [...newShares].map(([id, share]) => [id, KeyPackage.deserialize(share.serialize())])
  // );
  // // Verify signing works
  // checkSign(minSigners, keyPackages, rng, newPubKeyPackageRoundtrip);
}

/**
 * Test that refresh fails with invalid signers.
 */
export function checkRefreshSharesWithDealerFailsWithInvalidSigners<C extends Ciphersuite>(
  _ciphersuite: C,
  _identifiers: Identifier<C>[],
  _expectedError: FrostError,
  _rng: CryptoRng,
): void {
  // Implementation will be added when types are available
  // const [_oldShares, pubKeyPackage] = frost.keys.generateWithDealer(
  //   5, 2, IdentifierList.Default, rng
  // );
  // const result = frost.keys.refresh.computeRefreshingShares(
  //   pubKeyPackage, identifiers, rng
  // );
  // expect(result.ok).toBe(false);
  // expect(result.error).toEqual(expectedError);
}

/**
 * Test that refresh fails with invalid public key package.
 */
export function checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage<C extends Ciphersuite>(
  _ciphersuite: C,
  _rng: CryptoRng,
): void {
  // Implementation will be added when types are available
  // // Generate with 3 signers
  // const [_oldShares, incorrectPubKeyPackage] = frost.keys.generateWithDealer(
  //   3, 2, IdentifierList.Default, rng
  // );
  // // Try to refresh with identifiers 1, 3, 4, 5 (4 and 5 don't exist in the package)
  // const remainingIds = [
  //   Identifier.tryFrom(1),
  //   Identifier.tryFrom(3),
  //   Identifier.tryFrom(4),
  //   Identifier.tryFrom(5),
  // ];
  // const result = frost.keys.refresh.computeRefreshingShares(
  //   incorrectPubKeyPackage, remainingIds, rng
  // );
  // expect(result.error).toEqual(FrostError.UnknownIdentifier);
}

/**
 * Test serialization of refresh data.
 */
export function checkRefreshSharesWithDealerSerialisation<C extends Ciphersuite>(
  _ciphersuite: C,
  _rng: CryptoRng,
): void {
  // Implementation will be added when types are available
  // const [_oldShares, pubKeyPackage] = frost.keys.generateWithDealer(
  //   5, 3, IdentifierList.Default, rng
  // );
  // const remainingIds = [
  //   Identifier.tryFrom(1),
  //   Identifier.tryFrom(3),
  //   Identifier.tryFrom(4),
  //   Identifier.tryFrom(5),
  // ];
  // const [zeroShares, newPubKeyPackage] = frost.keys.refresh.computeRefreshingShares(
  //   pubKeyPackage, remainingIds, rng
  // );
  // // Test serialization
  // const zeroShareSerialized = zeroShares[0].serialize();
  // expect(zeroShareSerialized.ok).toBe(true);
  // const newPubKeyPackageSerialized = newPubKeyPackage.serialize();
  // expect(newPubKeyPackageSerialized.ok).toBe(true);
  // // Test deserialization
  // const zeroShare = SecretShare.deserialize(zeroShareSerialized.value);
  // expect(zeroShare.ok).toBe(true);
  // const deserializedPubKeyPackage = PublicKeyPackage.deserialize(newPubKeyPackageSerialized.value);
  // expect(deserializedPubKeyPackage.ok).toBe(true);
  // // Test KeyPackage creation from SecretShare
  // const keyPackage = KeyPackage.tryFrom(zeroShare.value);
  // expect(keyPackage.ok).toBe(true);
}

/**
 * Test refresh with DKG protocol.
 */
export function checkRefreshSharesWithDkg<C extends Ciphersuite>(
  _ciphersuite: C,
  _rng: CryptoRng,
): { message: Uint8Array; signature: Signature<C>; verifyingKey: VerifyingKey<C> } | undefined {
  // Implementation will be added when types are available
  return undefined;
}

/**
 * Test refresh with DKG using smaller threshold fails.
 */
export function checkRefreshSharesWithDkgSmallerThreshold<C extends Ciphersuite>(
  _ciphersuite: C,
  _rng: CryptoRng,
): void {
  // Implementation will be added when types are available
  // // Old key generation with threshold 3
  // const [oldShares, pubKeyPackage] = frost.keys.generateWithDealer(
  //   5, 3, IdentifierList.Default, rng
  // );
  // const oldKeyPackages = new Map(
  //   [...oldShares].map(([id, share]) => [id, share.toKeyPackage()])
  // );
  // // DKG for refresh with smaller threshold (2 instead of 3)
  // const maxSigners = 4;
  // const minSigners = 2;  // Smaller than original threshold of 3
  // const remainingIds = [
  //   Identifier.tryFrom(4),
  //   Identifier.tryFrom(2),
  //   Identifier.tryFrom(3),
  //   Identifier.tryFrom(1),
  // ];
  // // Run DKG rounds...
  // // (implementation details similar to check_refresh_shares_with_dkg)
  // // Final step should fail
  // for (const participantId of remainingIds) {
  //   const result = frost.keys.refresh.refreshDkgShares(
  //     round2SecretPackages.get(participantId),
  //     receivedRound1Packages.get(participantId),
  //     receivedRound2Packages.get(participantId),
  //     pubKeyPackage,
  //     oldKeyPackages.get(participantId)
  //   );
  //   expect(result.error).toEqual(FrostError.InvalidMinSigners);
  // }
}
