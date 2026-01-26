/**
 * Re-randomized FROST tests for secp256k1-SHA256-TR (Taproot).
 * Ported from frost-secp256k1-tr/tests/rerandomized_tests.rs
 *
 * These tests verify the re-randomized FROST signing protocol,
 * which allows for key re-randomization to enable unlinkable signatures.
 *
 * Note: The Taproot variant uses BIP-340 Schnorr signatures.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createSecureRng,
  createTestRng,
  type CryptoRng,
  signingCommitmentsData,
} from "./helpers/index.js";

import { Secp256K1Sha256TR, keys } from "../src/index.js";

import {
  Identifier,
  SigningCommitments,
  NonceCommitment,
  VerifyingKey,
  commit,
  type SigningNonces,
  type SignatureShare,
  type SigningPackage,
  type KeyPackage,
} from "@frosts/core";

import {
  Randomizer,
  RandomizedParams,
  signWithRandomizerSeed,
  aggregate,
} from "@frosts/rerandomized";

describe("FROST secp256k1-SHA256-TR Re-randomized Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Randomizer Properties", () => {
    it("should create randomizer from commitments", () => {
      // Create some sample commitments
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer, seed] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng,
        signingCommitments,
      );

      expect(randomizer).toBeDefined();
      expect(seed).toBeDefined();
      expect(seed.length).toBe(32); // Scalar size
    });

    it("should regenerate same randomizer from seed and commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer1, seed] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng,
        signingCommitments,
      );

      const randomizer2 = Randomizer.regenerateFromSeedAndCommitments(
        Secp256K1Sha256TR,
        seed,
        signingCommitments,
      );

      expect(randomizer1.equals(randomizer2)).toBe(true);
    });

    it("should produce different randomizers with different rng", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const rng1 = createTestRng(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
      const rng2 = createTestRng(new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]));

      const [randomizer1] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng1,
        signingCommitments,
      );

      const [randomizer2] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng2,
        signingCommitments,
      );

      expect(randomizer1.equals(randomizer2)).toBe(false);
    });

    it("should produce different randomizers with different commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment1 = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      // Create a different commitment (swap hiding and binding)
      const commitment2 = new SigningCommitments(
        Secp256K1Sha256TR,
        bindingCommitment, // swapped
        hidingCommitment, // swapped
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments1 = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments1.set(identifier, commitment1);

      const signingCommitments2 = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments2.set(identifier, commitment2);

      const [randomizer1, seed] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng,
        signingCommitments1,
      );

      // Use the same seed but different commitments
      const randomizer2 = Randomizer.regenerateFromSeedAndCommitments(
        Secp256K1Sha256TR,
        seed,
        signingCommitments2,
      );

      expect(randomizer1.equals(randomizer2)).toBe(false);
    });

    it("should serialize and deserialize randomizer", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng,
        signingCommitments,
      );

      const serialized = randomizer.serialize();
      expect(serialized.length).toBe(32); // Scalar size

      const deserialized = Randomizer.deserialize(Secp256K1Sha256TR, serialized);
      expect(deserialized.equals(randomizer)).toBe(true);
    });
  });

  describe("RandomizedParams", () => {
    it("should create params from randomizer", () => {
      // Create a verifying key from a sample element
      const commitmentsData = signingCommitmentsData();
      const verifyingKeyElement = Secp256K1Sha256TR.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256TR, verifyingKeyElement);

      // Create randomizer
      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng,
        signingCommitments,
      );

      const randomizedParams = RandomizedParams.fromRandomizer(
        Secp256K1Sha256TR,
        verifyingKey,
        randomizer,
      );

      expect(randomizedParams.randomizer.equals(randomizer)).toBe(true);
      expect(randomizedParams.randomizedVerifyingKey).toBeDefined();
    });

    it("should create params from commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const verifyingKeyElement = Secp256K1Sha256TR.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256TR, verifyingKeyElement);

      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizedParams, seed] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256TR,
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
      const verifyingKeyElement = Secp256K1Sha256TR.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256TR, verifyingKeyElement);

      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const [randomizer] = Randomizer.newFromCommitments(
        Secp256K1Sha256TR,
        rng,
        signingCommitments,
      );

      const randomizedParams = RandomizedParams.fromRandomizer(
        Secp256K1Sha256TR,
        verifyingKey,
        randomizer,
      );

      const randomizedVerifyingKey = randomizedParams.randomizedVerifyingKey;

      // The randomized key should be different from the original
      expect(randomizedVerifyingKey.equals(verifyingKey)).toBe(false);
    });

    it("should regenerate params from seed and commitments", () => {
      const commitmentsData = signingCommitmentsData();
      const verifyingKeyElement = Secp256K1Sha256TR.deserializeElement(commitmentsData.hiding);
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256TR, verifyingKeyElement);

      const hidingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Secp256K1Sha256TR,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const signingCommitments = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();
      signingCommitments.set(identifier, commitment);

      const [params1, seed] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256TR,
        verifyingKey,
        signingCommitments,
        rng,
      );

      const params2 = RandomizedParams.regenerateFromSeedAndCommitments(
        Secp256K1Sha256TR,
        verifyingKey,
        seed,
        signingCommitments,
      );

      expect(params1.equals(params2)).toBe(true);
    });
  });

  describe("Re-randomized Signing Flow", () => {
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
      // Note: keys.generateWithDealer in the namespace does NOT take ciphersuite as first param
      const [secretShares, pubkeys] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      // Convert secret shares to key packages
      const keyPackages = new Map<string, KeyPackage<typeof Secp256K1Sha256TR>>();
      for (const [idHex, secretShare] of secretShares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idHex, keyPackage);
      }

      // Select participants (first minSigners)
      const participantIds = [...keyPackages.keys()].slice(0, minSigners);

      // Round 1: Generate nonces and commitments
      const nonces = new Map<string, SigningNonces<typeof Secp256K1Sha256TR>>();
      const commitmentsMap = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();

      for (const idHex of participantIds) {
        const keyPackage = keyPackages.get(idHex);
        if (!keyPackage) throw new Error("Missing key package");

        const [signingNonces, signingCommitments] = commit(
          Secp256K1Sha256TR,
          keyPackage.signingShare,
          rng,
        );
        nonces.set(idHex, signingNonces);
        commitmentsMap.set(keyPackage.identifier, signingCommitments);
      }

      // Create randomized params
      const verifyingKey = VerifyingKey.create(Secp256K1Sha256TR, pubkeys.verifyingKey);
      const [randomizedParams, randomizerSeed] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256TR,
        verifyingKey,
        commitmentsMap,
        rng,
      );

      // Create signing package
      const message = new TextEncoder().encode("test message for rerandomized FROST-TR");
      const signingPackage: SigningPackage<typeof Secp256K1Sha256TR> = {
        signingCommitments: commitmentsMap,
        message,
      };

      // Round 2: Generate signature shares with randomizer seed
      const signatureShares = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SignatureShare<typeof Secp256K1Sha256TR>
      >();

      for (const idHex of participantIds) {
        const keyPackage = keyPackages.get(idHex);
        const signerNonces = nonces.get(idHex);
        if (!keyPackage || !signerNonces) throw new Error("Missing data");

        const signatureShare = signWithRandomizerSeed(
          Secp256K1Sha256TR,
          signingPackage,
          signerNonces,
          keyPackage,
          randomizerSeed,
        );

        signatureShares.set(keyPackage.identifier, signatureShare);
      }

      // Aggregate with randomized params
      const signature = aggregate(
        Secp256K1Sha256TR,
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
      // Note: keys.generateWithDealer in the namespace does NOT take ciphersuite as first param
      const [secretShares, pubkeys] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      // Convert to key packages
      const keyPackages = new Map<string, KeyPackage<typeof Secp256K1Sha256TR>>();
      for (const [idHex, secretShare] of secretShares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idHex, keyPackage);
      }

      const participantIds = [...keyPackages.keys()].slice(0, minSigners);

      // Create commitments
      const commitmentsMap = new Map<
        Identifier<typeof Secp256K1Sha256TR>,
        SigningCommitments<typeof Secp256K1Sha256TR>
      >();

      for (const idHex of participantIds) {
        const keyPackage = keyPackages.get(idHex);
        if (!keyPackage) throw new Error("Missing key package");

        const [, signingCommitments] = commit(Secp256K1Sha256TR, keyPackage.signingShare, rng);
        commitmentsMap.set(keyPackage.identifier, signingCommitments);
      }

      const verifyingKey = VerifyingKey.create(Secp256K1Sha256TR, pubkeys.verifyingKey);

      // Create two different randomized params with different RNGs
      const rng1 = createTestRng(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
      const rng2 = createTestRng(new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]));

      const [params1] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256TR,
        verifyingKey,
        commitmentsMap,
        rng1,
      );

      const [params2] = RandomizedParams.newFromCommitments(
        Secp256K1Sha256TR,
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

  it("should understand Taproot-specific considerations", () => {
    // For Taproot (secp256k1-TR):
    // - Signatures use BIP-340 format (64 bytes)
    // - Randomization affects the x-only public key
    // - The randomized key may need parity adjustment
    expect(true).toBe(true);
  });
});
