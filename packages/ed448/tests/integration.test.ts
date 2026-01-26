/**
 * Integration tests for FROST Ed448-SHAKE256.
 * Ported from frost-ed448/tests/integration_tests.rs
 *
 * These tests verify the complete FROST protocol flow including
 * key generation, signing, and verification for the Ed448-SHAKE256 ciphersuite.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { tests } from "@frosts/core";
import {
  createSecureRng,
  hexToBytes,
  bytesToHex,
  VECTORS,
  VECTORS_DKG,
  VECTORS_BIG_IDENTIFIER,
  type CryptoRng,
} from "./helpers/index.js";

import { Ed448Shake256, Identifier } from "../src/index.js";

describe("FROST Ed448-SHAKE256 Integration Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Zero Key Validation", () => {
    it("should fail when creating a zero SigningKey", () => {
      tests.checkZeroKeyFails(Ed448Shake256);
    });
  });

  describe("DKG (Distributed Key Generation)", () => {
    it("should complete full signing flow with DKG", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDkg(Ed448Shake256, rng);
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    }, 30_000);

    it("should fail DKG part1 with invalid min_signers (min_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ed448Shake256,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with min_signers greater than max_signers", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ed448Shake256,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with invalid max_signers (max_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ed448Shake256,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Repairable Threshold Scheme", () => {
    it("should recover a lost share using RTS", async () => {
      await tests.checkRts(Ed448Shake256, rng);
    });

    it("should verify repair_share_step_1 math", async () => {
      await tests.checkRepairShareStep1(Ed448Shake256, rng);
    });

    it("should fail repair share step 1 with invalid min_signers", async () => {
      await tests.checkRepairShareStep1FailsWithInvalidMinSigners(Ed448Shake256, rng);
    });
  });

  describe("Share Refresh", () => {
    it("should refresh shares with dealer", async () => {
      await tests.checkRefreshSharesWithDealer(Ed448Shake256, rng);
    });

    it("should serialize and deserialize refresh data correctly", async () => {
      await tests.checkRefreshSharesWithDealerSerialisation(Ed448Shake256, rng);
    });

    it("should fail refresh with invalid public key package", async () => {
      await tests.checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage(Ed448Shake256, rng);
    });

    it("should fail refresh with invalid identifier", async () => {
      await tests.checkRefreshSharesWithDealerFailsWithInvalidIdentifier(Ed448Shake256, rng);
    });

    it("should refresh shares with DKG", async () => {
      await tests.checkRefreshSharesWithDkg(Ed448Shake256, rng);
    });

    it("should refresh shares with DKG using smaller threshold", async () => {
      await tests.checkRefreshSharesWithDkgSmallerThreshold(Ed448Shake256, rng);
    });
  });

  describe("Signing with Trusted Dealer", () => {
    it("should complete full signing flow with dealer", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDealer(
        Ed448Shake256,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail signing with invalid min_signers (min_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Ed448Shake256,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail signing with min_signers greater than max_signers", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Ed448Shake256,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail signing with invalid max_signers (max_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Ed448Shake256,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Share Generation", () => {
    it("should generate valid secret shares (Shamir's Secret Sharing)", async () => {
      await tests.checkShareGeneration(Ed448Shake256, rng);
    });

    it("should fail share generation with min_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Ed448Shake256,
        0, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail share generation with min_signers greater than max_signers", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Ed448Shake256,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail share generation with max_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Ed448Shake256,
        3, // minSigners
        0, // maxSigners
        rng,
      );
    });
  });

  describe("Test Vectors", () => {
    it("should sign with test vectors", () => {
      // Ported from: check_sign_with_test_vectors
      // Verify the signing flow using the RFC test vectors
      tests.checkSignWithTestVectors(Ed448Shake256, VECTORS as unknown as tests.TestVectorsJson);
    });

    it("should perform DKG keygen with test vectors", async () => {
      // Ported from: check_sign_with_test_vectors_dkg
      // Verify DKG produces correct shares matching test vectors
      await tests.checkDkgKeygen(Ed448Shake256, VECTORS_DKG as unknown as tests.DKGTestVectorsJson);
    });

    it("should sign with test vectors using big identifiers", () => {
      // Ported from: check_sign_with_test_vectors_with_big_identifiers
      // Tests signing with identifiers larger than 16 bits (129, 256, 257)
      tests.checkSignWithTestVectors(
        Ed448Shake256,
        VECTORS_BIG_IDENTIFIER as unknown as tests.TestVectorsJson,
      );
    });
  });

  describe("Error Handling", () => {
    it("should correctly identify error culprits", () => {
      tests.checkErrorCulprit(Ed448Shake256);
    });
  });

  describe("Identifier Derivation", () => {
    it("should derive consistent identifiers", () => {
      tests.checkIdentifierDerivation(Ed448Shake256);
    });

    it("should generate identifiers from numeric and derived values", () => {
      // Ported from: check_identifier_generation (documentation snippet)
      // Test identifier generation from u16 and derived hashing

      // Test creating identifier from u16 - verify via serialization
      const id1 = Identifier.fromU16(Ed448Shake256, 1);
      expect(id1).toBeDefined();
      expect(id1.serialize().length).toBe(57); // Ed448 scalar size
      // First byte should be 0x01 for identifier 1 (little-endian)
      expect(id1.serialize()[0]).toBe(1);

      // Test creating identifier from u16 with larger value
      const id255 = Identifier.fromU16(Ed448Shake256, 255);
      expect(id255).toBeDefined();
      expect(id255.serialize().length).toBe(57);
      // First byte should be 0xff for identifier 255 (little-endian)
      expect(id255.serialize()[0]).toBe(255);

      // Test derived identifier (hashing) - only if HID is implemented
      if (typeof Ed448Shake256.HID === "function") {
        const derivedId = Identifier.derive(Ed448Shake256, new TextEncoder().encode("test"));
        expect(derivedId).toBeDefined();
        expect(derivedId.serialize().length).toBe(57); // Ed448 scalar size
      }
    });
  });

  describe("Signing with Custom Identifiers", () => {
    it("should sign with dealer and custom identifiers", async () => {
      // Ported from: check_sign_with_dealer_and_identifiers
      const [message, signature, verifyingKey] = await tests.checkSignWithDealerAndIdentifiers(
        Ed448Shake256,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });
  });

  describe("Signing Error Cases", () => {
    it("should fail signing with missing identifier", async () => {
      await tests.checkSignWithMissingIdentifier(Ed448Shake256, rng);
    });

    it("should fail signing with incorrect commitments", async () => {
      await tests.checkSignWithIncorrectCommitments(Ed448Shake256, rng);
    });

    it("should fail signing with not enough commitments", async () => {
      await tests.checkSignErrorsWithSetup(Ed448Shake256, rng);
    });
  });

  describe("Aggregation Error Cases", () => {
    it("should detect corrupted shares and identify culprits", async () => {
      await tests.checkAggregateErrorsWithSetup(Ed448Shake256, rng);
    });
  });

  describe("Signature Share Verification", () => {
    it("should verify valid signature shares", async () => {
      await tests.checkVerifyingSharesWithSetup(Ed448Shake256, rng);
    });
  });

  describe("DKG Error Cases", () => {
    it("should fail DKG part2 with corrupted proof of knowledge", async () => {
      await tests.checkDkgPart2ErrorWithSetup(Ed448Shake256, rng);
    });

    it("should fail DKG part3 with corrupted shares and identify culprits", async () => {
      await tests.checkDkgPart3ErrorsWithSetup(Ed448Shake256, rng);
    });
  });

  describe("Async Signing", () => {
    it("should complete async signing flow with dealer", async () => {
      // Ported from: check_async_sign_with_dealer / async_check_sign
      // This tests FROST types in async/await context
      await tests.asyncCheckSign(Ed448Shake256, rng);
    });
  });
});

describe("Test Vector Verification", () => {
  it("should verify test vector signature", () => {
    // Use the generic test vector signature verification from core
    tests.checkTestVectorSignature(Ed448Shake256, VECTORS);
  });

  it("should verify test vector verifying key derivation", () => {
    // Use the generic test vector verifying key verification from core
    tests.checkTestVectorVerifyingKey(Ed448Shake256, VECTORS);
  });

  it("should have valid test vector configuration", () => {
    expect(VECTORS.config.name).toBe("FROST(Ed448, SHAKE256)");
    expect(VECTORS.config.group).toBe("Ed448");
    expect(VECTORS.config.hash).toBe("SHAKE256");
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
    // Ed448 signature is 57 + 57 = 114 bytes = 228 hex chars
    expect(sig.length).toBe(228);
  });
});

describe("Batch Verification", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  it("should verify a batch of valid signatures", () => {
    tests.checkBatchVerify(Ed448Shake256, rng);
  });

  it("should fail batch verification with an invalid signature", () => {
    tests.checkBadBatchVerify(Ed448Shake256, rng);
  }, 30_000);

  it("should fail verification of an empty batch (NCC audit case)", () => {
    tests.checkEmptyBatchVerify(Ed448Shake256, rng);
  });
});
