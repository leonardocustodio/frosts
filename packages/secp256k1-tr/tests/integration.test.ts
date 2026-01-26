/**
 * Integration tests for FROST secp256k1-SHA256-TR (Taproot).
 * Ported from frost-secp256k1-tr/tests/integration_tests.rs
 *
 * These tests verify the complete FROST protocol flow including
 * key generation, signing, and verification for the secp256k1-SHA256-TR
 * (Taproot) ciphersuite.
 *
 * Key differences from non-Taproot secp256k1:
 * - Uses BIP-340 Schnorr signatures (64 bytes)
 * - Supports key tweaking for taproot commitments
 * - Uses x-only public keys for verification
 */

import { describe, it, expect, beforeEach } from "vitest";
import { tests, Identifier } from "@frosts/core";
import {
  createSecureRng,
  hexToBytes,
  bytesToHex,
  VECTORS,
  CIPHERSUITE_NAME,
  SIGNATURE_LENGTH,
  type CryptoRng,
} from "./helpers/index.js";

import { Secp256K1Sha256TR } from "../src/index.js";

describe("FROST secp256k1-SHA256-TR Integration Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Zero Key Validation", () => {
    it("should fail when creating a zero SigningKey", () => {
      tests.checkZeroKeyFails(Secp256K1Sha256TR);
    });
  });

  describe("DKG (Distributed Key Generation)", () => {
    it("should complete full signing flow with DKG", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDkg(
        Secp256K1Sha256TR,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail DKG part1 with invalid min_signers (min_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Secp256K1Sha256TR,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with min_signers greater than max_signers", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Secp256K1Sha256TR,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with invalid max_signers (max_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Secp256K1Sha256TR,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Repairable Threshold Scheme", () => {
    it("should recover a lost share using RTS", async () => {
      // Ported from: check_rts
      await tests.checkRts(Secp256K1Sha256TR, rng);
    });

    it("should verify repair_share_step_1 math", async () => {
      // Ported from: check_repair_share_step_1
      await tests.checkRepairShareStep1(Secp256K1Sha256TR, rng);
    });

    it("should fail repair share step 1 with invalid min_signers", async () => {
      // Ported from: check_repair_share_step_1_fails_with_invalid_min_signers
      await tests.checkRepairShareStep1FailsWithInvalidMinSigners(Secp256K1Sha256TR, rng);
    });
  });

  describe("Share Refresh", () => {
    it("should refresh shares with dealer", async () => {
      // Ported from: check_refresh_shares_with_dealer
      await tests.checkRefreshSharesWithDealer(Secp256K1Sha256TR, rng);
    });

    it("should serialize and deserialize refresh data correctly", async () => {
      // Ported from: check_refresh_shares_with_dealer_serialisation
      await tests.checkRefreshSharesWithDealerSerialisation(Secp256K1Sha256TR, rng);
    });

    it("should fail refresh with invalid public key package", async () => {
      // Ported from: check_refresh_shares_with_dealer_fails_with_invalid_public_key_package
      await tests.checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage(
        Secp256K1Sha256TR,
        rng,
      );
    });

    it("should fail refresh with invalid identifier", async () => {
      // Ported from: check_refresh_shares_with_dealer_fails_with_invalid_identifier
      await tests.checkRefreshSharesWithDealerFailsWithInvalidIdentifier(Secp256K1Sha256TR, rng);
    });

    it("should refresh shares with DKG", async () => {
      // Ported from: check_refresh_shares_with_dkg
      await tests.checkRefreshSharesWithDkg(Secp256K1Sha256TR, rng);
    });

    it("should refresh shares with DKG using smaller threshold", async () => {
      // Ported from: check_refresh_shares_with_dkg_smaller_threshold
      await tests.checkRefreshSharesWithDkgSmallerThreshold(Secp256K1Sha256TR, rng);
    });
  });

  describe("Signing with Trusted Dealer", () => {
    it("should complete full signing flow with dealer", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDealer(
        Secp256K1Sha256TR,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail signing with invalid min_signers (min_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Secp256K1Sha256TR,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail signing with min_signers greater than max_signers", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Secp256K1Sha256TR,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail signing with invalid max_signers (max_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Secp256K1Sha256TR,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Share Generation", () => {
    it("should generate valid secret shares (Shamir's Secret Sharing)", async () => {
      await tests.checkShareGeneration(Secp256K1Sha256TR, rng);
    });

    it("should fail share generation with min_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Secp256K1Sha256TR,
        0, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail share generation with min_signers greater than max_signers", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Secp256K1Sha256TR,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail share generation with max_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Secp256K1Sha256TR,
        3, // minSigners
        0, // maxSigners
        rng,
      );
    });
  });

  describe("Test Vectors", () => {
    it("should sign with test vectors", async () => {
      // Ported from: check_sign_with_test_vectors
      const vectorsJson = await import("./vectors/vectors.json");
      tests.checkSignWithTestVectors(
        Secp256K1Sha256TR,
        vectorsJson.default as unknown as tests.TestVectorsJson,
      );
    });

    it("should perform DKG keygen with test vectors", async () => {
      // Ported from: check_sign_with_test_vectors_dkg
      const vectorsDkgJson = await import("./vectors/vectors_dkg.json");
      await tests.checkDkgKeygen(
        Secp256K1Sha256TR,
        vectorsDkgJson.default as unknown as tests.DKGTestVectorsJson,
      );
    });

    it("should sign with test vectors using big identifiers", async () => {
      // Ported from: check_sign_with_test_vectors_with_big_identifiers
      const vectorsBigJson = await import("./vectors/vectors-big-identifier.json");
      tests.checkSignWithTestVectors(
        Secp256K1Sha256TR,
        vectorsBigJson.default as unknown as tests.TestVectorsJson,
      );
    });
  });

  describe("Error Handling", () => {
    it("should correctly identify error culprits", () => {
      tests.checkErrorCulprit(Secp256K1Sha256TR);
    });
  });

  describe("Identifier Derivation", () => {
    it("should derive consistent identifiers", () => {
      tests.checkIdentifierDerivation(Secp256K1Sha256TR);
    });

    it("should generate identifiers from numeric and derived values", () => {
      // Ported from: check_identifier_generation (documentation snippet)
      // Test that identifiers can be created both from numbers and derivation

      // Create identifiers from numbers
      const id1 = Identifier.fromU16(Secp256K1Sha256TR, 1);
      const id2 = Identifier.fromU16(Secp256K1Sha256TR, 2);
      const id42 = Identifier.fromU16(Secp256K1Sha256TR, 42);
      const id255 = Identifier.fromU16(Secp256K1Sha256TR, 255);
      const id256 = Identifier.fromU16(Secp256K1Sha256TR, 256);

      // Verify they are different
      expect(id1.equals(id2)).toBe(false);
      expect(id1.equals(id42)).toBe(false);
      expect(id255.equals(id256)).toBe(false);

      // Verify they are consistent (same input = same output)
      const id1Again = Identifier.fromU16(Secp256K1Sha256TR, 1);
      expect(id1.equals(id1Again)).toBe(true);

      // Derive identifiers from bytes
      const derivedId1 = Identifier.derive(Secp256K1Sha256TR, new Uint8Array([1, 2, 3, 4]));
      const derivedId2 = Identifier.derive(Secp256K1Sha256TR, new Uint8Array([5, 6, 7, 8]));

      // Verify derived identifiers are different
      expect(derivedId1.equals(derivedId2)).toBe(false);

      // Verify derivation is consistent
      const derivedId1Again = Identifier.derive(Secp256K1Sha256TR, new Uint8Array([1, 2, 3, 4]));
      expect(derivedId1.equals(derivedId1Again)).toBe(true);
    });
  });

  describe("Signing with Custom Identifiers", () => {
    it("should sign with dealer and custom identifiers", async () => {
      // Ported from: check_sign_with_dealer_and_identifiers
      await tests.checkSignWithDealerAndIdentifiers(Secp256K1Sha256TR, rng);
    });
  });

  describe("Signing Error Cases", () => {
    it("should fail signing with missing identifier", async () => {
      // Ported from: check_sign_with_missing_identifier
      await tests.checkSignWithMissingIdentifier(Secp256K1Sha256TR, rng);
    });

    it("should fail signing with incorrect commitments", async () => {
      // Ported from: check_sign_with_incorrect_commitments
      await tests.checkSignWithIncorrectCommitments(Secp256K1Sha256TR, rng);
    });
  });

  describe("Async Signing", () => {
    it("should complete async signing flow with dealer", async () => {
      // Ported from: check_async_sign_with_dealer
      await tests.asyncCheckSign(Secp256K1Sha256TR, rng);
    });
  });
});

describe("Test Vector Verification", () => {
  it("should verify test vector signature", () => {
    // Use the generic test vector signature verification from core
    tests.checkTestVectorSignature(Secp256K1Sha256TR, VECTORS);
  });

  it("should verify test vector verifying key derivation", () => {
    // Use the generic test vector verifying key verification from core
    tests.checkTestVectorVerifyingKey(Secp256K1Sha256TR, VECTORS);
  });

  it("should have valid test vector configuration", () => {
    expect(VECTORS.config.name).toBe("FROST(secp256k1, SHA-256) Taproot");
    expect(VECTORS.config.group).toBe("secp256k1");
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

  it("should use correct Taproot ciphersuite name", () => {
    expect(CIPHERSUITE_NAME).toBe("FROST-secp256k1-SHA256-TR-v1");
    // Note the "-TR" suffix distinguishing from non-Taproot
    expect(CIPHERSUITE_NAME).toContain("-TR-");
  });

  it("should use correct BIP-340 signature length", () => {
    // BIP-340 signatures are 64 bytes (x-only R + s)
    // Non-Taproot secp256k1 signatures are 65 bytes (SEC1 R + s)
    expect(SIGNATURE_LENGTH).toBe(64);
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
    // BIP-340 signature is 64 bytes = 128 hex chars
    expect(sig.length).toBe(128);
  });
});
