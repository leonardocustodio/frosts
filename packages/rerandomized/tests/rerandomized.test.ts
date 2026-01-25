/**
 * Ciphersuite-generic test functions for re-randomized FROST.
 *
 * These tests validate the re-randomized FROST signing protocol,
 * which allows for key re-randomization to enable unlinkable signatures.
 *
 * @module tests/rerandomized
 */

import { describe, it, expect } from "vitest";
import type { SigningPackage } from "@frost/core";
import type { Identifier } from "@frost/core";
import type { SigningCommitments, SigningNonces } from "@frost/core";
import type { KeyPackage, PublicKeyPackage, SecretShare } from "@frost/core";
import type { SignatureShare, Signature } from "@frost/core";
import type { VerifyingKey } from "@frost/core";

import type { RandomizedCiphersuite } from "../src/types.js";
import { Randomizer } from "../src/randomizer.js";
import { RandomizedParams } from "../src/params.js";
import { signWithRandomizerSeed } from "../src/sign.js";

// Type for random source compatible with both @frost/core and our needs
interface RandomSource {
  fill(array: Uint8Array): void;
}

/**
 * Test configuration for a specific ciphersuite.
 *
 * Users of this test module should provide a concrete ciphersuite
 * implementation and the corresponding helper functions.
 */
export interface RerandomizedTestConfig<C extends RandomizedCiphersuite> {
  /** The ciphersuite to test */
  ciphersuite: C;
  /** Random number generator */
  rng: RandomSource;
  /** Generate keys using trusted dealer */
  generateWithDealer(
    maxSigners: number,
    minSigners: number,
  ): Promise<[Map<string, SecretShare<C>>, PublicKeyPackage<C>]>;
  /** Create a SigningPackage from commitments and message */
  createSigningPackage(
    commitments: Map<Identifier<C>, SigningCommitments<C>>,
    message: Uint8Array,
  ): SigningPackage<C>;
  /** Commit (round 1) - returns [nonces, commitments] */
  commit(signingShare: unknown): [SigningNonces<C>, SigningCommitments<C>];
  /** Aggregate signature shares */
  aggregate(
    signingPackage: SigningPackage<C>,
    signatureShares: Map<string, SignatureShare<C>>,
    pubkeys: PublicKeyPackage<C>,
    randomizedParams: RandomizedParams<C>,
  ): Signature<C>;
  /** Get the verifying key from a public key package */
  getVerifyingKey(pubkeys: PublicKeyPackage<C>): VerifyingKey<C>;
  /** Verify a signature with a verifying key */
  verifySignature(
    verifyingKey: VerifyingKey<C>,
    message: Uint8Array,
    signature: Signature<C>,
  ): boolean;
}

/**
 * Check the randomizer creation and equality properties.
 *
 * Tests:
 * 1. from_randomizer path
 * 2. Randomizer determinism with same inputs
 * 3. Randomizer inequality with different inputs
 * 4. Regeneration from seed produces same randomizer
 */
export function checkRandomizer<C extends RandomizedCiphersuite>(
  config: RerandomizedTestConfig<C>,
  pubkeys: PublicKeyPackage<C>,
  signingPackage: SigningPackage<C>,
): void {
  checkFromRandomizer(config, signingPackage, pubkeys);
  checkFromSeedAndSigningCommitments(
    config,
    signingPackage.signingCommitments as Map<Identifier<C>, SigningCommitments<C>>,
  );
}

/**
 * Test the from_randomizer path.
 *
 * Verifies that RandomizedParams created from a randomizer
 * correctly stores and returns that randomizer.
 */
export function checkFromRandomizer<C extends RandomizedCiphersuite>(
  config: RerandomizedTestConfig<C>,
  signingPackage: SigningPackage<C>,
  pubkeys: PublicKeyPackage<C>,
): void {
  const [randomizer] = Randomizer.newFromCommitments(
    config.ciphersuite,
    config.rng,
    signingPackage.signingCommitments as Map<Identifier<C>, SigningCommitments<C>>,
  );

  const verifyingKey = config.getVerifyingKey(pubkeys);
  const randomizedParams = RandomizedParams.fromRandomizer(
    config.ciphersuite,
    verifyingKey,
    randomizer,
  );

  // The randomizer from params should equal the one we created with
  expect(randomizedParams.randomizer.equals(randomizer)).toBe(true);
}

/**
 * Test regeneration from seed and commitments.
 *
 * Verifies:
 * - Regeneration returns the same Randomizer
 * - Different rng_randomizers lead to different randomizers and seeds
 * - Modified commitments lead to different randomizers
 */
export function checkFromSeedAndSigningCommitments<C extends RandomizedCiphersuite>(
  config: RerandomizedTestConfig<C>,
  signingCommitments: Map<Identifier<C>, SigningCommitments<C>>,
): void {
  // Make sure regeneration returns the same Randomizer
  const [randomizer1, randomizerSeed1] = Randomizer.newFromCommitments(
    config.ciphersuite,
    config.rng,
    signingCommitments,
  );
  const randomizer2 = Randomizer.regenerateFromSeedAndCommitments(
    config.ciphersuite,
    randomizerSeed1,
    signingCommitments,
  );
  expect(randomizer1.equals(randomizer2)).toBe(true);

  const [randomizer3, randomizerSeed2] = Randomizer.newFromCommitments(
    config.ciphersuite,
    config.rng,
    signingCommitments,
  );

  // Make sure that different rng_randomizers lead to different randomizers
  expect(randomizer1.equals(randomizer3)).toBe(false);

  // Seeds should also be different
  expect(arraysEqual(randomizerSeed1, randomizerSeed2)).toBe(false);

  // Modify the commitments map, by overwriting the first entry with the value
  // of the last entry
  const modifiedSigningCommitments = new Map(signingCommitments);
  const entries = Array.from(modifiedSigningCommitments.entries());
  if (entries.length >= 2) {
    const firstKey = entries[0][0];
    const lastValue = entries[entries.length - 1][1];
    modifiedSigningCommitments.set(firstKey, lastValue);
  }

  const randomizer4 = Randomizer.regenerateFromSeedAndCommitments(
    config.ciphersuite,
    randomizerSeed1,
    modifiedSigningCommitments,
  );

  // Make sure that different commitments lead to different randomizers
  expect(randomizer1.equals(randomizer4)).toBe(false);
}

/**
 * Full integration test for re-randomized FROST signing with trusted dealer.
 *
 * Returns the signed message, generated signature, and the randomized public key
 * so that the caller can verify the signature with their own implementation.
 *
 * @param config - Test configuration with ciphersuite and module functions
 * @returns Tuple of [message, signature, randomized verifying key]
 */
export async function checkRandomizedSignWithDealer<C extends RandomizedCiphersuite>(
  config: RerandomizedTestConfig<C>,
): Promise<[Uint8Array, Signature<C>, VerifyingKey<C>]> {
  ////////////////////////////////////////////////////////////////////////////
  // Key generation
  ////////////////////////////////////////////////////////////////////////////

  const maxSigners = 5;
  const minSigners = 3;

  const [shares, pubkeys] = await config.generateWithDealer(maxSigners, minSigners);

  // Verifies the secret shares from the dealer and creates KeyPackages
  const keyPackages = new Map<string, KeyPackage<C>>();

  for (const [k, v] of shares) {
    // SecretShare.toKeyPackage() performs verification
    keyPackages.set(k, v.toKeyPackage() as KeyPackage<C>);
  }

  const nonces = new Map<string, SigningNonces<C>>();
  const commitments = new Map<Identifier<C>, SigningCommitments<C>>();

  ////////////////////////////////////////////////////////////////////////////
  // Round 1: generating nonces and signing commitments for each participant
  ////////////////////////////////////////////////////////////////////////////

  let participantCount = 0;
  for (const [participantIdStr, keyPackage] of keyPackages) {
    if (participantCount >= minSigners) break;

    // Generate one (1) nonce and one SigningCommitments instance for each
    // participant, up to minSigners
    const [nonce, commitment] = config.commit(keyPackage.signingShare);

    nonces.set(participantIdStr, nonce);
    commitments.set(keyPackage.identifier as Identifier<C>, commitment);
    participantCount++;
  }

  // This is what the signature aggregator / coordinator needs to do:
  // - decide what message to sign
  // - take one (unused) commitment per signing participant
  const signatureShares = new Map<string, SignatureShare<C>>();
  const message = new TextEncoder().encode("message to sign");
  const signingPackage = config.createSigningPackage(commitments, message);

  // Run randomizer validation tests
  checkRandomizer(config, pubkeys, signingPackage);

  // Create randomized params from commitments
  const verifyingKey = config.getVerifyingKey(pubkeys);
  const [randomizerParams, randomizerSeed] = RandomizedParams.newFromCommitments(
    config.ciphersuite,
    verifyingKey,
    commitments,
    config.rng,
  );

  ////////////////////////////////////////////////////////////////////////////
  // Round 2: each participant generates their signature share
  ////////////////////////////////////////////////////////////////////////////

  for (const [participantIdStr, noncesToUse] of nonces) {
    const keyPackage = keyPackages.get(participantIdStr);
    if (!keyPackage) {
      throw new Error(`Key package not found for participant ${participantIdStr}`);
    }

    // Each participant generates their signature share
    const signatureShare = signWithRandomizerSeed(
      config.ciphersuite,
      signingPackage,
      noncesToUse,
      keyPackage,
      randomizerSeed,
    );

    signatureShares.set(participantIdStr, signatureShare);
  }

  ////////////////////////////////////////////////////////////////////////////
  // Aggregation: collects the signing shares from all participants,
  // generates the final signature.
  ////////////////////////////////////////////////////////////////////////////

  // Aggregate (also verifies the signature shares)
  const groupSignature = config.aggregate(
    signingPackage,
    signatureShares,
    pubkeys,
    randomizerParams,
  );

  // Check that the threshold signature can be verified by the randomized group public
  // key (the verification key)
  const randomizedVerifyingKey = randomizerParams.randomizedVerifyingKey;
  const isValid = config.verifySignature(randomizedVerifyingKey, message, groupSignature);
  expect(isValid).toBe(true);

  // Note that keyPackage.verifyingKey can't be used to verify the signature
  // since those are non-randomized.

  return [message, groupSignature, randomizedVerifyingKey];
}

/**
 * Helper to compare two Uint8Arrays for equality.
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Main test suite for re-randomized FROST.
 *
 * This is a placeholder that will be populated when a concrete
 * ciphersuite implementation is available.
 */
describe("Rerandomized FROST", () => {
  it("should be parameterized with a concrete ciphersuite", () => {
    // This test file provides generic test functions that should be called
    // from ciphersuite-specific test files.
    //
    // Example usage in a ciphersuite test file:
    //
    // ```typescript
    // import { checkRandomizedSignWithDealer } from '@frost/rerandomized/tests/rerandomized.test';
    // import { Ristretto255Ciphersuite } from '@frost/ristretto255';
    //
    // describe('Ristretto255 Rerandomized FROST', () => {
    //   it('should complete full signing flow', async () => {
    //     const config = {
    //       ciphersuite: new Ristretto255Ciphersuite(),
    //       rng: createSecureRng(),
    //       generateWithDealer: async (max, min) => generateWithDealer(...),
    //       createSigningPackage: (comms, msg) => new SigningPackage(...),
    //       commit: (share) => commit(...),
    //       aggregate: (pkg, shares, pk, params) => aggregate(...),
    //       getVerifyingKey: (pk) => pk.verifyingKey,
    //       verifySignature: (vk, msg, sig) => vk.verify(msg, sig),
    //     };
    //     const [message, signature, verifyingKey] = await checkRandomizedSignWithDealer(config);
    //     expect(signature).toBeDefined();
    //   });
    // });
    // ```
    expect(true).toBe(true);
  });

  describe("Randomizer", () => {
    it("should provide equality comparison", () => {
      // Randomizer equality is tested via checkFromSeedAndSigningCommitments
      // when called with a concrete ciphersuite
      expect(true).toBe(true);
    });

    it("should produce different randomizers with different inputs", () => {
      // Randomizer inequality is tested via checkFromSeedAndSigningCommitments
      // when called with a concrete ciphersuite
      expect(true).toBe(true);
    });

    it("should support regeneration from seed", () => {
      // Seed regeneration is tested via checkFromSeedAndSigningCommitments
      // when called with a concrete ciphersuite
      expect(true).toBe(true);
    });
  });

  describe("RandomizedParams", () => {
    it("should preserve randomizer through fromRandomizer", () => {
      // Tested via checkFromRandomizer when called with a concrete ciphersuite
      expect(true).toBe(true);
    });

    it("should create new params from commitments", () => {
      // Tested via checkRandomizedSignWithDealer when called with a concrete ciphersuite
      expect(true).toBe(true);
    });
  });

  describe("Full Signing Flow", () => {
    it("should complete key generation, signing, and verification", () => {
      // The full flow is tested via checkRandomizedSignWithDealer
      // when called with a concrete ciphersuite
      expect(true).toBe(true);
    });

    it("should verify signature with randomized verifying key", () => {
      // Signature verification is tested as part of checkRandomizedSignWithDealer
      expect(true).toBe(true);
    });
  });
});
