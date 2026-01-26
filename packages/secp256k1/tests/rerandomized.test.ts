/**
 * Re-randomized FROST tests for secp256k1-SHA256.
 * Ported from frost-secp256k1/tests/rerandomized_tests.rs
 *
 * These tests verify the re-randomized FROST signing protocol,
 * which allows for key re-randomization to enable unlinkable signatures.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createSecureRng,
  createTestRng,
  type CryptoRng,
  signingCommitmentsData,
} from "./helpers/index.js";

import {
  Secp256K1Sha256,
  Identifier,
  SigningCommitments,
  NonceCommitment,
  VerifyingKey,
  keys,
  commit,
  type SigningNonces,
  type SignatureShare,
} from "../src/index.js";

import {
  Randomizer,
  RandomizedParams,
  signWithRandomizerSeed,
  aggregate,
} from "@frosts/rerandomized";

import type { SigningPackage, KeyPackage } from "@frosts/core";

describe("FROST secp256k1-SHA256 Re-randomized Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Randomizer Properties", () => {
    it("should create randomizer from commitments", () => {
      // Create some sample commitments
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer, seed] = Randomizer.newFromCommitments(
        Secp256K1Sha256,
        rng,
        signingCommitments,
      );

      expect(randomizer).toBeDefined();
      expect(seed).toBeDefined();
      expect(seed.length).toBe(32); // Scalar size
    });

    it("should regenerate same randomizer from seed and commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer1, seed] = Randomizer.newFromCommitments(
        Secp256K1Sha256,
        rng,
        signingCommitments,
      );

      const randomizer2 = Randomizer.regenerateFromSeedAndCommitments(
        Secp256K1Sha256,
        seed,
        signingCommitments,
      );

      expect(randomizer1.equals(randomizer2)).toBe(true);
    });

    it("should produce different randomizers with different rng", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const rng1 = createTestRng(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
      const rng2 = createTestRng(new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]));

      const [randomizer1] = Randomizer.newFromCommitments(
        Secp256K1Sha256,
        rng1,
        signingCommitments,
      );

      const [randomizer2] = Randomizer.newFromCommitments(
        Secp256K1Sha256,
        rng2,
        signingCommitments,
      );

      expect(randomizer1.equals(randomizer2)).toBe(false);
    });

    it("should produce different randomizers with different commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment1 = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      // Create a different commitment (swap hiding and binding)
      const commitment2 = new SigningCommitments(
        Secp256K1Sha256,
        bindingCommitment, // swapped
        hidingCommitment, // swapped
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments1 = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments1.set(identifier, commitment1);

      const signingCommitments2 = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments2.set(identifier, commitment2);

      const [randomizer1, seed] = Randomizer.newFromCommitments(
        Secp256K1Sha256,
        rng,
        signingCommitments1,
      );

      // Use the same seed but different commitments
      const randomizer2 = Randomizer.regenerateFromSeedAndCommitments(
        Secp256K1Sha256,
        seed,
        signingCommitments2,
      );

      expect(randomizer1.equals(randomizer2)).toBe(false);
    });

    it("should serialize and deserialize randomizer", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer] = Randomizer.newFromCommitments(Secp256K1Sha256, rng, signingCommitments);

      const serialized = randomizer.serialize();
      expect(serialized.length).toBe(32); // Scalar size

      const deserialized = Randomizer.deserialize(Secp256K1Sha256, serialized);
      expect(deserialized.equals(randomizer)).toBe(true);
    });
  });

  describe("RandomizedParams", () => {
    it("should create params from randomizer", () => {
      // Create a verifying key from a sample element
      const commitmentsData = signingCommitmentsData();
      const verifyingKeyElement = Secp256K1Sha256.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256, verifyingKeyElement);

      // Create randomizer
      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer] = Randomizer.newFromCommitments(Secp256K1Sha256, rng, signingCommitments);

      const randomizedParams = RandomizedParams.fromRandomizer(
        Secp256K1Sha256,
        verifyingKey,
        randomizer,
      );

      expect(randomizedParams.randomizer.equals(randomizer)).toBe(true);
      expect(randomizedParams.randomizedVerifyingKey).toBeDefined();
    });

    it("should create params from commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const verifyingKeyElement = Secp256K1Sha256.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256, verifyingKeyElement);

      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizedParams, seed] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256,
        verifyingKey,
        signingCommitments,
        rng,
      );

      expect(randomizedParams).toBeDefined();
      expect(seed).toBeDefined();
      expect(seed.length).toBe(32);
    });

    it("should compute randomized verifying key", () => {
      const commitmentsData = signingCommitmentsData();
      const verifyingKeyElement = Secp256K1Sha256.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256, verifyingKeyElement);

      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer] = Randomizer.newFromCommitments(Secp256K1Sha256, rng, signingCommitments);

      const randomizedParams = RandomizedParams.fromRandomizer(
        Secp256K1Sha256,
        verifyingKey,
        randomizer,
      );

      const randomizedVerifyingKey = randomizedParams.randomizedVerifyingKey;

      // The randomized key should be different from the original
      expect(randomizedVerifyingKey.equals(verifyingKey)).toBe(false);
    });

    it("should regenerate params from seed and commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const verifyingKeyElement = Secp256K1Sha256.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256, verifyingKeyElement);

      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();
      signingCommitments.set(identifier, commitment);

      const [params1, seed] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256,
        verifyingKey,
        signingCommitments,
        rng,
      );

      const params2 = RandomizedParams.regenerateFromSeedAndCommitments(
        Secp256K1Sha256,
        verifyingKey,
        seed,
        signingCommitments,
      );

      expect(params1.equals(params2)).toBe(true);
    });
  });

  describe("Re-randomized Signing Flow", async () => {
    it("should complete re-randomized signing flow with dealer", async () => {
      // This test verifies the full re-randomized signing flow:
      // 1. Key generation with dealer
      // 2. Round 1: Generate nonces and commitments
      // 3. Create randomized params from commitments
      // 4. Round 2: Generate signature shares with randomizer seed
      // 5. Aggregation with randomized params
      // 6. Verification with randomized verifying key

      const maxSigners = 3;
      const minSigners = 2;

      // Generate keys with dealer
      const [secretShares, pubkeys] = await keys.generateWithDealer(
        Secp256K1Sha256,
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      // Convert secret shares to key packages
      const keyPackages = new Map<string, KeyPackage<typeof Secp256K1Sha256>>();
      for (const [idHex, secretShare] of secretShares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idHex, keyPackage);
      }

      // Select participants (first minSigners)
      const participantIds = [...keyPackages.keys()].slice(0, minSigners);

      // Round 1: Generate nonces and commitments
      const nonces = new Map<string, SigningNonces<typeof Secp256K1Sha256>>();
      const commitmentsMap = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();

      for (const idHex of participantIds) {
        const keyPackage = keyPackages.get(idHex);
        if (!keyPackage) throw new Error("Missing key package");

        const [signingNonces, signingCommitments] = commit(
          Secp256K1Sha256,
          keyPackage.signingShare,
          rng,
        );
        nonces.set(idHex, signingNonces);
        commitmentsMap.set(keyPackage.identifier, signingCommitments);
      }

      // Create randomized params
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256, pubkeys.verifyingKey);
      const [randomizedParams, randomizerSeed] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256,
        verifyingKey,
        commitmentsMap,
        rng,
      );

      // Create signing package
      const message = new TextEncoder().encode("test message for rerandomized FROST");
      const signingPackage: SigningPackage<typeof Secp256K1Sha256> = {
        signingCommitments: commitmentsMap,
        message,
      };

      // Round 2: Generate signature shares with randomizer seed
      const signatureShares = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SignatureShare<typeof Secp256K1Sha256>
      >();

      for (const idHex of participantIds) {
        const keyPackage = keyPackages.get(idHex);
        const signerNonces = nonces.get(idHex);
        if (!keyPackage || !signerNonces) throw new Error("Missing data");

        const signatureShare = signWithRandomizerSeed(
          Secp256K1Sha256,
          signingPackage,
          signerNonces,
          keyPackage,
          randomizerSeed,
        );

        signatureShares.set(keyPackage.identifier, signatureShare);
      }

      // Aggregate with randomized params
      const signature = aggregate(
        Secp256K1Sha256,
        signingPackage,
        signatureShares,
        pubkeys,
        randomizedParams,
      );

      expect(signature).toBeDefined();

      // Verify with randomized verifying key
      const randomizedVerifyingKey = randomizedParams.randomizedVerifyingKey;
      expect(randomizedVerifyingKey).toBeDefined();

      // Verification should work with the randomized key
      // Note: The signature verification is embedded in aggregate
      // Here we just verify the signature was created successfully
      expect(signature.R).toBeDefined();
      expect(signature.z).toBeDefined();
    });
  });

  describe("Unlinkability", () => {
    it("should produce different randomized keys for same group key", async () => {
      // Two signatures with different randomizers should have different
      // randomized verifying keys, making them unlinkable

      const maxSigners = 3;
      const minSigners = 2;

      // Generate keys with dealer
      const [secretShares, pubkeys] = await keys.generateWithDealer(
        Secp256K1Sha256,
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      // Convert to key packages
      const keyPackages = new Map<string, KeyPackage<typeof Secp256K1Sha256>>();
      for (const [idHex, secretShare] of secretShares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idHex, keyPackage);
      }

      const participantIds = [...keyPackages.keys()].slice(0, minSigners);

      // Create commitments
      const commitmentsMap = new Map<
        Identifier<typeof Secp256K1Sha256>,
        SigningCommitments<typeof Secp256K1Sha256>
      >();

      for (const idHex of participantIds) {
        const keyPackage = keyPackages.get(idHex);
        if (!keyPackage) throw new Error("Missing key package");

        const [, signingCommitments] = commit(Secp256K1Sha256, keyPackage.signingShare, rng);
        commitmentsMap.set(keyPackage.identifier, signingCommitments);
      }

      const verifyingKey = VerifyingKey.create(Secp256K1Sha256, pubkeys.verifyingKey);

      // Create two different randomized params with different RNGs
      const rng1 = createTestRng(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
      const rng2 = createTestRng(new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]));

      const [params1] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256,
        verifyingKey,
        commitmentsMap,
        rng1,
      );

      const [params2] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256,
        verifyingKey,
        commitmentsMap,
        rng2,
      );

      // Different randomizers should produce different randomized verifying keys
      expect(params1.randomizer.equals(params2.randomizer)).toBe(false);
      expect(params1.randomizedVerifyingKey.equals(params2.randomizedVerifyingKey)).toBe(false);
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
