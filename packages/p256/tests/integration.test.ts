/**
 * Integration tests for FROST P-256-SHA256.
 * Ported from frost-p256/tests/integration_tests.rs
 *
 * These tests verify the complete FROST protocol flow including
 * key generation, signing, and verification for the P-256-SHA256 ciphersuite.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { tests, Identifier } from "@frosts/core";
import {
  createSecureRng,
  hexToBytes,
  bytesToHex,
  VECTORS,
  type CryptoRng,
} from "./helpers/index.js";

import { P256Sha256 } from "../src/index.js";

// DKG test vectors
import VECTORS_DKG from "./helpers/vectors_dkg.json";

// Signing test vectors (from Rust)
import VECTORS_SIGNING from "./helpers/vectors.json";
import VECTORS_BIG_IDENTIFIER from "./helpers/vectors-big-identifier.json";

describe("FROST P-256-SHA256 Integration Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Zero Key Validation", () => {
    it("should fail when creating a zero SigningKey", () => {
      tests.checkZeroKeyFails(P256Sha256);
    });
  });

  describe("DKG (Distributed Key Generation)", () => {
    it("should complete full signing flow with DKG", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDkg(P256Sha256, rng);
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail DKG part1 with invalid min_signers (min_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        P256Sha256,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with min_signers greater than max_signers", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        P256Sha256,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with invalid max_signers (max_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        P256Sha256,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Repairable Threshold Scheme", () => {
    it("should recover a lost share using RTS", async () => {
      await tests.checkRts(P256Sha256, rng);
    });

    it("should verify repair_share_step_1 math", async () => {
      await tests.checkRepairShareStep1(P256Sha256, rng);
    });

    it("should fail repair share step 1 with invalid min_signers", async () => {
      await tests.checkRepairShareStep1FailsWithInvalidMinSigners(P256Sha256, rng);
    });
  });

  describe("Share Refresh", () => {
    it("should refresh shares with dealer", async () => {
      await tests.checkRefreshSharesWithDealer(P256Sha256, rng);
    });

    it("should serialize and deserialize refresh data correctly", async () => {
      await tests.checkRefreshSharesWithDealerSerialisation(P256Sha256, rng);
    });

    it("should fail refresh with invalid public key package", async () => {
      await tests.checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage(P256Sha256, rng);
    });

    it("should fail refresh with invalid identifier", async () => {
      await tests.checkRefreshSharesWithDealerFailsWithInvalidIdentifier(P256Sha256, rng);
    });

    it("should refresh shares with DKG", async () => {
      await tests.checkRefreshSharesWithDkg(P256Sha256, rng);
    });

    it("should refresh shares with DKG using smaller threshold", async () => {
      await tests.checkRefreshSharesWithDkgSmallerThreshold(P256Sha256, rng);
    });
  });

  describe("Signing with Trusted Dealer", () => {
    it("should complete full signing flow with dealer", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDealer(P256Sha256, rng);
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail signing with invalid min_signers (min_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        P256Sha256,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail signing with min_signers greater than max_signers", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        P256Sha256,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail signing with invalid max_signers (max_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        P256Sha256,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Share Generation", () => {
    it("should generate valid secret shares (Shamir's Secret Sharing)", async () => {
      await tests.checkShareGeneration(P256Sha256, rng);
    });

    it("should fail share generation with min_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        P256Sha256,
        0, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail share generation with min_signers greater than max_signers", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        P256Sha256,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail share generation with max_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        P256Sha256,
        3, // minSigners
        0, // maxSigners
        rng,
      );
    });
  });

  describe("Test Vectors", () => {
    it("should sign with test vectors", async () => {
      // Ported from: check_sign_with_test_vectors
      await tests.checkSignWithTestVectors(P256Sha256, VECTORS_SIGNING);
    });

    it("should perform DKG keygen with test vectors", async () => {
      // Ported from: check_sign_with_test_vectors_dkg
      await tests.checkDkgKeygen(P256Sha256, VECTORS_DKG, (condition, message) => {
        expect(condition, message).toBe(true);
      });
    });

    it("should sign with test vectors using big identifiers", async () => {
      // Ported from: check_sign_with_test_vectors_with_big_identifiers
      await tests.checkSignWithTestVectors(P256Sha256, VECTORS_BIG_IDENTIFIER);
    });
  });

  describe("Error Handling", () => {
    it("should correctly identify error culprits", () => {
      tests.checkErrorCulprit(P256Sha256);
    });
  });

  describe("Identifier Derivation", () => {
    it("should derive consistent identifiers", () => {
      tests.checkIdentifierDerivation(P256Sha256);
    });

    it("should generate identifiers from numeric and derived values", () => {
      // Ported from: check_identifier_generation (documentation snippet)
      // Test identifier generation from numeric values

      // Test fromU16
      const id1 = Identifier.fromU16(P256Sha256, 1);
      expect(id1).toBeDefined();
      const id2 = Identifier.fromU16(P256Sha256, 2);
      expect(id2).toBeDefined();

      // Identifiers should be distinct
      expect(bytesToHex(id1.serialize())).not.toBe(bytesToHex(id2.serialize()));

      // Test derive from arbitrary data
      const derivedBytes = new Uint8Array([1, 2, 3, 4, 5]);
      const derivedId = Identifier.derive(P256Sha256, derivedBytes);
      expect(derivedId).toBeDefined();
    });
  });

  describe("Signing with Custom Identifiers", () => {
    it("should sign with dealer and custom identifiers", async () => {
      // Ported from: check_sign_with_dealer_and_identifiers
      const [message, signature, verifyingKey] = await tests.checkSignWithDealerAndIdentifiers(
        P256Sha256,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });
  });

  describe("Signing Error Cases", () => {
    it("should fail signing with missing identifier", async () => {
      await tests.checkSignWithMissingIdentifier(P256Sha256, rng);
    });

    it("should fail signing with incorrect commitments", async () => {
      await tests.checkSignWithIncorrectCommitments(P256Sha256, rng);
    });

    it("should fail signing with not enough commitments", async () => {
      await tests.checkSignErrorsWithSetup(P256Sha256, rng);
    });
  });

  describe("Aggregation Error Cases", () => {
    it("should detect corrupted shares and identify culprits", async () => {
      await tests.checkAggregateErrorsWithSetup(P256Sha256, rng);
    });
  });

  describe("Signature Share Verification", () => {
    it("should verify valid signature shares", async () => {
      await tests.checkVerifyingSharesWithSetup(P256Sha256, rng);
    });
  });

  describe("DKG Error Cases", () => {
    it("should fail DKG part2 with corrupted proof of knowledge", async () => {
      await tests.checkDkgPart2ErrorWithSetup(P256Sha256, rng);
    });

    it("should fail DKG part3 with corrupted shares and identify culprits", async () => {
      await tests.checkDkgPart3ErrorsWithSetup(P256Sha256, rng);
    });
  });

  describe("Async Signing", () => {
    it("should complete async signing flow with dealer", async () => {
      // Ported from: check_async_sign_with_dealer / async_check_sign
      // This tests FROST types in async/await context
      await tests.asyncCheckSign(P256Sha256, rng);
    });
  });
});

describe("Test Vector Verification", () => {
  it("should verify test vector signature", () => {
    // Use the generic test vector signature verification from core
    tests.checkTestVectorSignature(P256Sha256, VECTORS);
  });

  it("should verify test vector verifying key derivation", () => {
    // Use the generic test vector verifying key verification from core
    tests.checkTestVectorVerifyingKey(P256Sha256, VECTORS);
  });

  it("should have valid test vector configuration", () => {
    expect(VECTORS.config.name).toBe("FROST(P-256, SHA-256)");
    expect(VECTORS.config.group).toBe("P-256");
    expect(VECTORS.config.hash).toBe("SHA-256");
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
    // P-256 signature is 1 + 32 + 32 = 65 bytes = 130 hex chars (with compression prefix)
    expect(sig.length).toBe(130);
  });
});

describe("Batch Verification", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  it("should verify a batch of valid signatures", () => {
    tests.checkBatchVerify(P256Sha256, rng);
  });

  it("should fail batch verification with an invalid signature", () => {
    tests.checkBadBatchVerify(P256Sha256, rng);
  });

  it("should fail verification of an empty batch (NCC audit case)", () => {
    tests.checkEmptyBatchVerify(P256Sha256, rng);
  });
});
