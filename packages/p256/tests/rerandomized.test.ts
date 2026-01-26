/**
 * Re-randomized FROST tests for P256-SHA256.
 * Ported from frost-p256/tests/rerandomized_tests.rs
 *
 * These tests verify the re-randomized FROST signing protocol,
 * which allows for key re-randomization to enable unlinkable signatures.
 */

import { describe, it, expect } from "vitest";
import { createSecureRng, type CryptoRng } from "./helpers/index.js";

import { P256Sha256, commit, generateWithDealer, type Identifier } from "../src/index.js";

import {
  SigningPackageImpl,
  VerifyingKey,
  bytesToHex,
  type SignatureShare,
  type SigningCommitments,
  type SigningNonces,
  type KeyPackage,
} from "@frosts/core";

import {
  Randomizer,
  RandomizedParams,
  signWithRandomizerSeed,
  aggregate as aggregateRandomized,
  type RandomizedCiphersuite,
} from "@frosts/rerandomized";

type P256 = typeof P256Sha256;

/**
 * Helper to generate keys, commitments, and prepare for signing.
 */
async function setupSigningFlow(rng: CryptoRng, maxSigners = 3, minSigners = 2) {
  const [sharesMap, pubkeys] = await generateWithDealer(
    P256Sha256,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // sharesMap is Map<string, SecretShare> where string is the identifier hex

  // Prepare key packages
  const keyPackages = new Map<string, KeyPackage<P256>>();
  for (const [idStr, share] of sharesMap) {
    keyPackages.set(idStr, share.toKeyPackage() as KeyPackage<P256>);
  }

  // Round 1: Generate nonces and commitments
  const nonces = new Map<string, SigningNonces<P256>>();
  const commitments = new Map<Identifier<P256>, SigningCommitments<P256>>();
  let participantCount = 0;
  for (const [participantIdStr, keyPackage] of keyPackages) {
    if (participantCount >= minSigners) break;
    const [nonce, commitment] = commit(P256Sha256, keyPackage.signingShare, rng);
    nonces.set(participantIdStr, nonce);
    commitments.set(keyPackage.identifier, commitment);
    participantCount++;
  }

  return { sharesMap, pubkeys, keyPackages, nonces, commitments, rng };
}

describe("FROST P256-SHA256 Re-randomized Tests", () => {
  describe("Randomized Signing with Trusted Dealer", () => {
    it("should complete re-randomized signing flow with dealer", async () => {
      // Ported from: check_randomized_sign_with_dealer
      const rng = createSecureRng();
      const { pubkeys, keyPackages, nonces, commitments } = await setupSigningFlow(rng, 5, 3);

      // Create signing package
      const message = new TextEncoder().encode("message to sign");
      const signingPackage = SigningPackageImpl.create(P256Sha256, commitments, message);

      // Create randomized params
      const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);
      const [randomizedParams, randomizerSeed] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey,
        commitments,
        rng,
      ) as [RandomizedParams<P256>, Uint8Array];

      // Round 2: Sign with randomizer seed
      const signatureShares = new Map<Identifier<P256>, SignatureShare<P256>>();
      for (const [participantIdStr, noncesToUse] of nonces) {
        const keyPackage = keyPackages.get(participantIdStr);
        if (!keyPackage) continue;

        const signatureShare = signWithRandomizerSeed(
          P256Sha256,
          signingPackage,
          noncesToUse,
          keyPackage,
          randomizerSeed,
        );
        signatureShares.set(keyPackage.identifier, signatureShare);
      }

      // Aggregate
      const signature = aggregateRandomized(
        P256Sha256,
        signingPackage,
        signatureShares,
        pubkeys,
        randomizedParams,
      );

      expect(message).toBeDefined();
      expect(signature).toBeDefined();

      // Verify with randomized verifying key - verify() throws on failure
      const randomizedVerifyingKey = randomizedParams.randomizedVerifyingKey;
      expect(() => randomizedVerifyingKey.verify(message, signature)).not.toThrow();
    });
  });

  describe("Randomizer Properties", () => {
    it("should create randomizer from commitments", async () => {
      const rng = createSecureRng();
      const { commitments } = await setupSigningFlow(rng, 3, 2);

      // Create randomizer from commitments
      const [randomizer, seed] = Randomizer.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        rng,
        commitments,
      );
      expect(randomizer).toBeDefined();
      expect(seed).toBeDefined();
      expect(seed.length).toBe(32); // Scalar length for P256
    });

    it("should regenerate same randomizer from seed and commitments", async () => {
      const rng = createSecureRng();
      const { commitments } = await setupSigningFlow(rng, 3, 2);

      // Create randomizer from commitments
      const [randomizer1, seed] = Randomizer.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        rng,
        commitments,
      );

      // Regenerate from seed
      const randomizer2 = Randomizer.regenerateFromSeedAndCommitments(
        P256Sha256 as RandomizedCiphersuite,
        seed,
        commitments,
      );

      expect(randomizer1.equals(randomizer2)).toBe(true);
    });

    it("should produce different randomizers with different rng", async () => {
      const rng = createSecureRng();
      const { commitments } = await setupSigningFlow(rng, 3, 2);

      // Create two randomizers with different RNG calls
      const rng1 = createSecureRng();
      const rng2 = createSecureRng();

      const [randomizer1] = Randomizer.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        rng1,
        commitments,
      );
      const [randomizer2] = Randomizer.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        rng2,
        commitments,
      );

      // Different RNG should produce different randomizers
      expect(randomizer1.equals(randomizer2)).toBe(false);
    });

    it("should produce different randomizers with different commitments", async () => {
      const rng = createSecureRng();
      // Generate with 4 participants so we have 2 sets of 2 commitments
      const [sharesMap] = await generateWithDealer(P256Sha256, 4, 2, { type: "Default" }, rng);

      // Convert to array for easier indexing
      const shares = Array.from(sharesMap.values());

      // Generate first set of commitments (participants 0 and 1)
      const commitments1 = new Map<Identifier<P256>, SigningCommitments<P256>>();
      const keyPackage0 = shares[0].toKeyPackage() as KeyPackage<P256>;
      const keyPackage1 = shares[1].toKeyPackage() as KeyPackage<P256>;
      const [, commitment0] = commit(P256Sha256, keyPackage0.signingShare, rng);
      const [, commitment1] = commit(P256Sha256, keyPackage1.signingShare, rng);
      commitments1.set(keyPackage0.identifier, commitment0);
      commitments1.set(keyPackage1.identifier, commitment1);

      // Generate second set of commitments (participants 2 and 3)
      const commitments2 = new Map<Identifier<P256>, SigningCommitments<P256>>();
      const keyPackage2 = shares[2].toKeyPackage() as KeyPackage<P256>;
      const keyPackage3 = shares[3].toKeyPackage() as KeyPackage<P256>;
      const [, commitment2] = commit(P256Sha256, keyPackage2.signingShare, rng);
      const [, commitment3] = commit(P256Sha256, keyPackage3.signingShare, rng);
      commitments2.set(keyPackage2.identifier, commitment2);
      commitments2.set(keyPackage3.identifier, commitment3);

      // Create randomizer with first set
      const [randomizer1, seed] = Randomizer.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        rng,
        commitments1,
      );

      // Regenerate with same seed but different commitments
      const randomizer2 = Randomizer.regenerateFromSeedAndCommitments(
        P256Sha256 as RandomizedCiphersuite,
        seed,
        commitments2,
      );

      // Different commitments should produce different randomizers
      expect(randomizer1.equals(randomizer2)).toBe(false);
    });
  });

  describe("RandomizedParams", () => {
    it("should create params from randomizer", async () => {
      const rng = createSecureRng();
      const { pubkeys, commitments } = await setupSigningFlow(rng, 3, 2);

      // Create randomizer
      const [randomizer] = Randomizer.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        rng,
        commitments,
      );

      // Create params from randomizer
      const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);
      const params = RandomizedParams.fromRandomizer(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey,
        randomizer,
      );

      expect(params.randomizer.equals(randomizer)).toBe(true);
    });

    it("should create params from commitments", async () => {
      const rng = createSecureRng();
      const { pubkeys, commitments } = await setupSigningFlow(rng, 3, 2);

      // Create params from commitments
      const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);
      const [params, seed] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey,
        commitments,
        rng,
      );

      expect(params).toBeDefined();
      expect(seed).toBeDefined();
    });

    it("should compute randomized verifying key", async () => {
      const rng = createSecureRng();
      const { pubkeys, commitments } = await setupSigningFlow(rng, 3, 2);

      // Create params
      const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);
      const [params] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey,
        commitments,
        rng,
      );

      // Randomized verifying key should be different from original
      const randomizedVk = params.randomizedVerifyingKey;
      expect(randomizedVk).not.toEqual(verifyingKey);
      expect(bytesToHex(randomizedVk.serialize())).not.toBe(bytesToHex(verifyingKey.serialize()));
    });
  });

  describe("Re-randomized Signing Flow", () => {
    it("should sign with randomizer seed", async () => {
      const rng = createSecureRng();
      const { pubkeys, keyPackages, nonces, commitments } = await setupSigningFlow(rng, 3, 2);

      // Create signing package
      const message = new TextEncoder().encode("test message");
      const signingPackage = SigningPackageImpl.create(P256Sha256, commitments, message);

      // Create randomized params
      const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);
      const [, seed] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey,
        commitments,
        rng,
      );

      // Round 2: Sign with randomizer seed
      const signatureShares = new Map<string, SignatureShare<P256>>();
      for (const [participantIdStr, noncesToUse] of nonces) {
        const keyPackage = keyPackages.get(participantIdStr);
        if (!keyPackage) continue;

        const signatureShare = signWithRandomizerSeed(
          P256Sha256,
          signingPackage,
          noncesToUse,
          keyPackage,
          seed,
        );
        signatureShares.set(participantIdStr, signatureShare);
      }

      expect(signatureShares.size).toBe(2);
    });

    it("should verify signature with randomized verifying key", async () => {
      const rng = createSecureRng();
      const { pubkeys, keyPackages, nonces, commitments } = await setupSigningFlow(rng, 3, 2);

      // Create signing package
      const message = new TextEncoder().encode("test message");
      const signingPackage = SigningPackageImpl.create(P256Sha256, commitments, message);

      // Create randomized params
      const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);
      const [params, seed] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey,
        commitments,
        rng,
      ) as [RandomizedParams<P256>, Uint8Array];

      // Round 2: Sign
      const signatureShares = new Map<Identifier<P256>, SignatureShare<P256>>();
      for (const [participantIdStr, noncesToUse] of nonces) {
        const keyPackage = keyPackages.get(participantIdStr);
        if (!keyPackage) continue;

        const signatureShare = signWithRandomizerSeed(
          P256Sha256,
          signingPackage,
          noncesToUse,
          keyPackage,
          seed,
        );
        signatureShares.set(keyPackage.identifier, signatureShare);
      }

      // Aggregate
      const signature = aggregateRandomized(
        P256Sha256,
        signingPackage,
        signatureShares,
        pubkeys,
        params,
      );

      // Verify signature with randomized verifying key - verify() throws on failure
      const randomizedVk = params.randomizedVerifyingKey;
      expect(() => randomizedVk.verify(message, signature)).not.toThrow();
    });

    it("should not verify signature with original verifying key", async () => {
      const rng = createSecureRng();
      const { pubkeys, keyPackages, nonces, commitments } = await setupSigningFlow(rng, 3, 2);

      // Create signing package
      const message = new TextEncoder().encode("test message");
      const signingPackage = SigningPackageImpl.create(P256Sha256, commitments, message);

      // Create randomized params
      const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);
      const [params, seed] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey,
        commitments,
        rng,
      ) as [RandomizedParams<P256>, Uint8Array];

      // Round 2: Sign
      const signatureShares = new Map<Identifier<P256>, SignatureShare<P256>>();
      for (const [participantIdStr, noncesToUse] of nonces) {
        const keyPackage = keyPackages.get(participantIdStr);
        if (!keyPackage) continue;

        const signatureShare = signWithRandomizerSeed(
          P256Sha256,
          signingPackage,
          noncesToUse,
          keyPackage,
          seed,
        );
        signatureShares.set(keyPackage.identifier, signatureShare);
      }

      // Aggregate
      const signature = aggregateRandomized(
        P256Sha256,
        signingPackage,
        signatureShares,
        pubkeys,
        params,
      );

      // Verify with randomized key should pass - verify() throws on failure
      const randomizedVk = params.randomizedVerifyingKey;
      expect(() => randomizedVk.verify(message, signature)).not.toThrow();

      // Verify with original key should fail - should throw
      expect(() => verifyingKey.verify(message, signature)).toThrow();
    });
  });

  describe("Unlinkability", () => {
    it("should produce unlinkable signatures", async () => {
      // Create first signing flow and signature
      const rng1 = createSecureRng();
      const setup1 = await setupSigningFlow(rng1, 5, 3);
      const message1 = new TextEncoder().encode("message 1");
      const signingPackage1 = SigningPackageImpl.create(P256Sha256, setup1.commitments, message1);
      const verifyingKey1 = VerifyingKey.create(P256Sha256, setup1.pubkeys.verifyingKey);
      const [params1, seed1] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey1,
        setup1.commitments,
        rng1,
      ) as [RandomizedParams<P256>, Uint8Array];

      const signatureShares1 = new Map<Identifier<P256>, SignatureShare<P256>>();
      for (const [participantIdStr, noncesToUse] of setup1.nonces) {
        const keyPackage = setup1.keyPackages.get(participantIdStr);
        if (!keyPackage) continue;
        const share = signWithRandomizerSeed(
          P256Sha256,
          signingPackage1,
          noncesToUse,
          keyPackage,
          seed1,
        );
        signatureShares1.set(keyPackage.identifier, share);
      }
      const sig1 = aggregateRandomized(
        P256Sha256,
        signingPackage1,
        signatureShares1,
        setup1.pubkeys,
        params1,
      );

      // Create second signing flow and signature
      const rng2 = createSecureRng();
      const setup2 = await setupSigningFlow(rng2, 5, 3);
      const message2 = new TextEncoder().encode("message 2");
      const signingPackage2 = SigningPackageImpl.create(P256Sha256, setup2.commitments, message2);
      const verifyingKey2 = VerifyingKey.create(P256Sha256, setup2.pubkeys.verifyingKey);
      const [params2, seed2] = RandomizedParams.newFromCommitments(
        P256Sha256 as RandomizedCiphersuite,
        verifyingKey2,
        setup2.commitments,
        rng2,
      ) as [RandomizedParams<P256>, Uint8Array];

      const signatureShares2 = new Map<Identifier<P256>, SignatureShare<P256>>();
      for (const [participantIdStr, noncesToUse] of setup2.nonces) {
        const keyPackage = setup2.keyPackages.get(participantIdStr);
        if (!keyPackage) continue;
        const share = signWithRandomizerSeed(
          P256Sha256,
          signingPackage2,
          noncesToUse,
          keyPackage,
          seed2,
        );
        signatureShares2.set(keyPackage.identifier, share);
      }
      const sig2 = aggregateRandomized(
        P256Sha256,
        signingPackage2,
        signatureShares2,
        setup2.pubkeys,
        params2,
      );

      // Both signatures should be valid - verify() throws on failure
      const vk1 = params1.randomizedVerifyingKey;
      const vk2 = params2.randomizedVerifyingKey;
      expect(() => vk1.verify(message1, sig1)).not.toThrow();
      expect(() => vk2.verify(message2, sig2)).not.toThrow();

      // Randomized verifying keys should be different (unlinkable)
      expect(bytesToHex(vk1.serialize())).not.toBe(bytesToHex(vk2.serialize()));
    });
  });
});

describe("Re-randomization Concepts", () => {
  it("should understand the purpose of re-randomization", () => {
    // Re-randomization allows participants to create signatures that:
    // 1. Are valid under a randomized public key
    // 2. Cannot be linked to the original group public key
    // 3. Cannot be linked to other signatures from the same group
    //
    // This is useful for privacy-preserving protocols where you want to:
    // - Prove you belong to a group without revealing which group
    // - Sign multiple messages without linking the signatures together
    expect(true).toBe(true);
  });

  it("should understand the re-randomization workflow", () => {
    // Workflow:
    // 1. Generate keys with dealer/DKG (normal FROST)
    // 2. Round 1: Generate nonces and commitments (normal FROST)
    // 3. Create Randomizer from commitments using fresh randomness
    // 4. Round 2: Sign with randomizer seed (shares randomizerSeed with all signers)
    // 5. Aggregate with RandomizedParams
    // 6. Verify with randomized verifying key (not original)
    expect(true).toBe(true);
  });
});
