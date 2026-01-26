/**
 * Integration tests for FROST Ed25519-SHA512.
 * Ported from frost-ed25519/tests/integration_tests.rs
 *
 * These tests verify the complete FROST protocol flow including
 * key generation, signing, and verification for the Ed25519-SHA512 ciphersuite.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { tests, Identifier } from "@frosts/core";
import { Ed25519Sha512 } from "../src/index.js";
import {
  createSecureRng,
  hexToBytes,
  bytesToHex,
  VECTORS,
  type CryptoRng,
} from "./helpers/index.js";

describe("FROST Ed25519-SHA512 Integration Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Zero Key Validation", () => {
    it("should fail when creating a zero SigningKey", () => {
      tests.checkZeroKeyFails(Ed25519Sha512);
    });
  });

  describe("DKG (Distributed Key Generation)", () => {
    it("should complete full signing flow with DKG", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDkg(Ed25519Sha512, rng);
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    }, 30_000);

    it("should fail DKG part1 with invalid min_signers (min_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ed25519Sha512,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with min_signers greater than max_signers", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ed25519Sha512,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with invalid max_signers (max_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ed25519Sha512,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Repairable Threshold Scheme", () => {
    it("should recover a lost share using RTS", async () => {
      await tests.checkRts(Ed25519Sha512, rng);
    });

    it("should verify repair_share_step_1 math", async () => {
      await tests.checkRepairShareStep1(Ed25519Sha512, rng);
    });

    it("should fail repair share step 1 with invalid min_signers", async () => {
      await tests.checkRepairShareStep1FailsWithInvalidMinSigners(Ed25519Sha512, rng);
    });
  });

  describe("Share Refresh", () => {
    it("should refresh shares with dealer", async () => {
      await tests.checkRefreshSharesWithDealer(Ed25519Sha512, rng);
    });

    it("should serialize and deserialize refresh data correctly", async () => {
      await tests.checkRefreshSharesWithDealerSerialisation(Ed25519Sha512, rng);
    });

    it("should fail refresh with invalid public key package", async () => {
      await tests.checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage(Ed25519Sha512, rng);
    });

    it("should fail refresh with invalid identifier", async () => {
      await tests.checkRefreshSharesWithDealerFailsWithInvalidIdentifier(Ed25519Sha512, rng);
    });

    it("should refresh shares with DKG", async () => {
      await tests.checkRefreshSharesWithDkg(Ed25519Sha512, rng);
    });

    it("should refresh shares with DKG using smaller threshold", async () => {
      await tests.checkRefreshSharesWithDkgSmallerThreshold(Ed25519Sha512, rng);
    });
  });

  describe("Signing with Trusted Dealer", () => {
    it("should complete full signing flow with dealer", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDealer(
        Ed25519Sha512,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail signing with invalid min_signers (min_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(Ed25519Sha512, 1, 3, rng);
    });

    it("should fail signing with min_signers greater than max_signers", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(Ed25519Sha512, 3, 2, rng);
    });

    it("should fail signing with invalid max_signers (max_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(Ed25519Sha512, 3, 1, rng);
    });
  });

  describe("Share Generation", () => {
    it("should generate valid secret shares (Shamir's Secret Sharing)", async () => {
      await tests.checkShareGeneration(Ed25519Sha512, rng);
    });

    it("should fail share generation with min_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(Ed25519Sha512, 0, 3, rng);
    });

    it("should fail share generation with min_signers greater than max_signers", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(Ed25519Sha512, 3, 2, rng);
    });

    it("should fail share generation with max_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(Ed25519Sha512, 3, 0, rng);
    });
  });

  describe("Test Vectors", () => {
    it("should sign with test vectors", async () => {
      // Ported from: check_sign_with_test_vectors
      // Import the JSON test vectors
      const vectorsJson = await import("./vectors/vectors.json");
      await tests.checkSignWithTestVectors(Ed25519Sha512, vectorsJson.default);
    });

    it("should perform DKG keygen with test vectors", async () => {
      // Ported from: check_sign_with_test_vectors_dkg
      const vectorsDkgJson = await import("./vectors/vectors_dkg.json");
      await tests.checkDkgKeygen(Ed25519Sha512, vectorsDkgJson.default);
    });

    it("should sign with test vectors using big identifiers", async () => {
      // Ported from: check_sign_with_test_vectors_with_big_identifiers
      const vectorsBigJson = await import("./vectors/vectors-big-identifier.json");
      await tests.checkSignWithTestVectors(Ed25519Sha512, vectorsBigJson.default);
    });
  });

  describe("Error Handling", () => {
    it("should correctly identify error culprits", () => {
      tests.checkErrorCulprit(Ed25519Sha512);
    });
  });

  describe("Identifier Derivation", () => {
    it("should derive consistent identifiers", () => {
      tests.checkIdentifierDerivation(Ed25519Sha512);
    });

    it("should generate identifiers from numeric and derived values", () => {
      // Ported from: check_identifier_generation (documentation snippet)
      // Test that identifiers can be created both from numbers and derivation

      // Create identifiers from numbers
      const id1 = Identifier.fromU16(Ed25519Sha512, 1);
      const id2 = Identifier.fromU16(Ed25519Sha512, 2);
      const id42 = Identifier.fromU16(Ed25519Sha512, 42);
      const id255 = Identifier.fromU16(Ed25519Sha512, 255);
      const id256 = Identifier.fromU16(Ed25519Sha512, 256);

      // Verify they are different
      expect(id1.equals(id2)).toBe(false);
      expect(id1.equals(id42)).toBe(false);
      expect(id255.equals(id256)).toBe(false);

      // Verify they are consistent (same input = same output)
      const id1Again = Identifier.fromU16(Ed25519Sha512, 1);
      expect(id1.equals(id1Again)).toBe(true);

      // Derive identifiers from arbitrary bytes
      const derived1 = Identifier.derive(Ed25519Sha512, new Uint8Array([1, 2, 3, 4]));
      const derived2 = Identifier.derive(Ed25519Sha512, new Uint8Array([5, 6, 7, 8]));

      // Different input = different output
      expect(derived1.equals(derived2)).toBe(false);

      // Same input = same output
      const derived1Again = Identifier.derive(Ed25519Sha512, new Uint8Array([1, 2, 3, 4]));
      expect(derived1.equals(derived1Again)).toBe(true);
    });
  });

  describe("Signing with Custom Identifiers", () => {
    it("should sign with dealer and custom identifiers", async () => {
      // Ported from: check_sign_with_dealer_and_identifiers
      const [message, signature, verifyingKey] = await tests.checkSignWithDealerAndIdentifiers(
        Ed25519Sha512,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });
  });

  describe("Signing Error Cases", () => {
    it("should fail signing with missing identifier", async () => {
      await tests.checkSignWithMissingIdentifier(Ed25519Sha512, rng);
    });

    it("should fail signing with incorrect commitments", async () => {
      await tests.checkSignWithIncorrectCommitments(Ed25519Sha512, rng);
    });

    it("should fail signing with not enough commitments", async () => {
      await tests.checkSignErrorsWithSetup(Ed25519Sha512, rng);
    });
  });

  describe("Aggregation Error Cases", () => {
    it("should detect corrupted shares and identify culprits", async () => {
      await tests.checkAggregateErrorsWithSetup(Ed25519Sha512, rng);
    });
  });

  describe("Signature Share Verification", () => {
    it("should verify valid signature shares", async () => {
      await tests.checkVerifyingSharesWithSetup(Ed25519Sha512, rng);
    });
  });

  describe("DKG Error Cases", () => {
    it("should fail DKG part2 with corrupted proof of knowledge", async () => {
      await tests.checkDkgPart2ErrorWithSetup(Ed25519Sha512, rng);
    });

    it("should fail DKG part3 with corrupted shares and identify culprits", async () => {
      await tests.checkDkgPart3ErrorsWithSetup(Ed25519Sha512, rng);
    });
  });

  describe("Async Signing", () => {
    it("should complete async signing flow with dealer", async () => {
      // Ported from: check_async_sign_with_dealer / async_check_sign
      // This tests FROST types in async/await context
      await tests.asyncCheckSign(Ed25519Sha512, rng);
    });
  });
});

describe("Test Vector Verification", () => {
  it("should verify test vector signature", () => {
    // Use the generic test vector signature verification from core
    tests.checkTestVectorSignature(Ed25519Sha512, VECTORS);
  });

  it("should verify test vector verifying key derivation", () => {
    // Use the generic test vector verifying key verification from core
    tests.checkTestVectorVerifyingKey(Ed25519Sha512, VECTORS);
  });

  it("should have valid test vector configuration", () => {
    expect(VECTORS.config.name).toBe("FROST(Ed25519, SHA-512)");
    expect(VECTORS.config.group).toBe("ed25519");
    expect(VECTORS.config.hash).toBe("SHA-512");
    expect(parseInt(VECTORS.config.MAX_PARTICIPANTS)).toBe(3);
    expect(parseInt(VECTORS.config.MIN_PARTICIPANTS)).toBe(2);
    expect(parseInt(VECTORS.config.NUM_PARTICIPANTS)).toBe(2);
  });

  it("should have valid participant list", () => {
    expect(VECTORS.inputs.participant_list).toEqual([1, 3]);
    expect(VECTORS.inputs.participant_list.length).toBe(parseInt(VECTORS.config.NUM_PARTICIPANTS));
  });

  it("should have correct message encoding", () => {
    const message = hexToBytes(VECTORS.inputs.message);
    const expectedMessage = new TextEncoder().encode("test");
    expect(bytesToHex(message)).toBe(bytesToHex(expectedMessage));
  });

  it("should have participant shares for all max participants", () => {
    expect(VECTORS.inputs.participant_shares.length).toBe(
      parseInt(VECTORS.config.MAX_PARTICIPANTS),
    );
  });

  it("should have round one outputs for participating identifiers", () => {
    const outputs = VECTORS.round_one_outputs.outputs;
    expect(outputs.length).toBe(parseInt(VECTORS.config.NUM_PARTICIPANTS));
    expect(outputs.map((o) => o.identifier)).toEqual(VECTORS.inputs.participant_list);
  });

  it("should have round two outputs for participating identifiers", () => {
    const outputs = VECTORS.round_two_outputs.outputs;
    expect(outputs.length).toBe(parseInt(VECTORS.config.NUM_PARTICIPANTS));
    expect(outputs.map((o) => o.identifier)).toEqual(VECTORS.inputs.participant_list);
  });

  it("should have final signature output", () => {
    const sig = VECTORS.final_output.sig;
    // Ed25519 signature is 2 * 32 = 64 bytes = 128 hex chars
    expect(sig.length).toBe(128);
  });
});

describe("Batch Verification", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  it("should verify a batch of valid signatures", () => {
    tests.checkBatchVerify(Ed25519Sha512, rng);
  });

  it("should fail batch verification with an invalid signature", () => {
    tests.checkBadBatchVerify(Ed25519Sha512, rng);
  });

  it("should fail verification of an empty batch (NCC audit case)", () => {
    tests.checkEmptyBatchVerify(Ed25519Sha512, rng);
  });
});
