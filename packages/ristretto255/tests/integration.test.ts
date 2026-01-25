/**
 * Integration tests for FROST Ristretto255-SHA512.
 * Ported from frost-ristretto255/tests/integration_tests.rs
 *
 * These tests verify the complete FROST protocol flow including
 * key generation, signing, and verification for the Ristretto255-SHA512 ciphersuite.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { tests } from "@frosts/core";
import {
  createSecureRng,
  hexToBytes,
  bytesToHex,
  VECTORS,
  type CryptoRng,
} from "./helpers/index.js";

import { Ristretto255Sha512 } from "../src/index.js";

describe("FROST Ristretto255-SHA512 Integration Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Zero Key Validation", () => {
    it("should fail when creating a zero SigningKey", () => {
      tests.checkZeroKeyFails(Ristretto255Sha512);
    });
  });

  describe("DKG (Distributed Key Generation)", () => {
    it("should complete full signing flow with DKG", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDkg(
        Ristretto255Sha512,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail DKG part1 with invalid min_signers (min_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ristretto255Sha512,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with min_signers greater than max_signers", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ristretto255Sha512,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail DKG part1 with invalid max_signers (max_signers = 1)", () => {
      tests.checkDkgPart1FailsWithInvalidSigners(
        Ristretto255Sha512,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Repairable Threshold Scheme", () => {
    it.skip("should recover a lost share using RTS", () => {
      // Ported from: check_rts
      // TODO: Implement RTS functions in core
      expect(true).toBe(true);
    });
  });

  describe("Share Refresh", () => {
    it.skip("should refresh shares with dealer", () => {
      // Ported from: check_refresh_shares_with_dealer
      // TODO: Implement refresh functions in core
      expect(true).toBe(true);
    });

    it.skip("should serialize and deserialize refresh data correctly", () => {
      // Ported from: check_refresh_shares_with_dealer_serialisation
      // TODO: Implement refresh functions in core
      expect(true).toBe(true);
    });

    it.skip("should fail refresh with invalid public key package", () => {
      // Ported from: check_refresh_shares_with_dealer_fails_with_invalid_public_key_package
      // TODO: Implement refresh functions in core
      expect(true).toBe(true);
    });

    it.skip("should fail refresh with invalid identifier", () => {
      // Ported from: check_refresh_shares_with_dealer_fails_with_invalid_identifier
      // TODO: Implement refresh functions in core
      expect(true).toBe(true);
    });

    it.skip("should refresh shares with DKG", () => {
      // Ported from: check_refresh_shares_with_dkg
      // TODO: Implement refresh functions in core
      expect(true).toBe(true);
    });

    it.skip("should refresh shares with DKG using smaller threshold", () => {
      // Ported from: check_refresh_shares_with_dkg_smaller_threshold
      // TODO: Implement refresh functions in core
      expect(true).toBe(true);
    });
  });

  describe("Signing with Trusted Dealer", () => {
    it("should complete full signing flow with dealer", async () => {
      const [message, signature, verifyingKey] = await tests.checkSignWithDealer(
        Ristretto255Sha512,
        rng,
      );
      expect(message).toBeDefined();
      expect(signature).toBeDefined();
      expect(verifyingKey).toBeDefined();
    });

    it("should fail signing with invalid min_signers (min_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Ristretto255Sha512,
        1, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail signing with min_signers greater than max_signers", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Ristretto255Sha512,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail signing with invalid max_signers (max_signers = 1)", async () => {
      await tests.checkSignWithDealerFailsWithInvalidSigners(
        Ristretto255Sha512,
        3, // minSigners
        1, // maxSigners
        rng,
      );
    });
  });

  describe("Share Generation", () => {
    it("should generate valid secret shares (Shamir's Secret Sharing)", async () => {
      await tests.checkShareGeneration(Ristretto255Sha512, rng);
    });

    it("should fail share generation with min_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Ristretto255Sha512,
        0, // minSigners
        3, // maxSigners
        rng,
      );
    });

    it("should fail share generation with min_signers greater than max_signers", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Ristretto255Sha512,
        3, // minSigners
        2, // maxSigners
        rng,
      );
    });

    it("should fail share generation with max_signers = 0", async () => {
      await tests.checkShareGenerationFailsWithInvalidSigners(
        Ristretto255Sha512,
        3, // minSigners
        0, // maxSigners
        rng,
      );
    });
  });

  describe("Test Vectors", () => {
    it.skip("should sign with test vectors", () => {
      // Ported from: check_sign_with_test_vectors
      // TODO: Implement test vector verification in core
      expect(true).toBe(true);
    });

    it.skip("should perform DKG keygen with test vectors", () => {
      // Ported from: check_sign_with_test_vectors_dkg
      // TODO: Implement DKG test vector verification in core
      expect(true).toBe(true);
    });

    it.skip("should sign with test vectors using big identifiers", () => {
      // Ported from: check_sign_with_test_vectors_with_big_identifiers
      // TODO: Implement test vector verification in core
      expect(true).toBe(true);
    });
  });

  describe("Error Handling", () => {
    it("should correctly identify error culprits", () => {
      tests.checkErrorCulprit(Ristretto255Sha512);
    });
  });

  describe("Identifier Derivation", () => {
    it("should derive consistent identifiers", () => {
      tests.checkIdentifierDerivation(Ristretto255Sha512);
    });

    it.skip("should generate identifiers from numeric and derived values", () => {
      // Ported from: check_identifier_generation (documentation snippet)
      // TODO: Test identifier generation separately
      expect(true).toBe(true);
    });
  });

  describe("Signing with Custom Identifiers", () => {
    it.skip("should sign with dealer and custom identifiers", () => {
      // Ported from: check_sign_with_dealer_and_identifiers
      // TODO: Implement custom identifier support in core
      expect(true).toBe(true);
    });
  });

  describe("Signing Error Cases", () => {
    it.skip("should fail signing with missing identifier", () => {
      // Ported from: check_sign_with_missing_identifier
      // TODO: Implement error case tests in core
      expect(true).toBe(true);
    });

    it.skip("should fail signing with incorrect commitments", () => {
      // Ported from: check_sign_with_incorrect_commitments
      // TODO: Implement error case tests in core
      expect(true).toBe(true);
    });
  });

  describe("Async Signing", () => {
    it.skip("should complete async signing flow with dealer", async () => {
      // Ported from: check_async_sign_with_dealer
      // TODO: Test async signing separately
      expect(true).toBe(true);
    });
  });
});

describe("Test Vector Verification", () => {
  it("should have valid test vector configuration", () => {
    expect(VECTORS.config.name).toBe("FROST(ristretto255, SHA-512)");
    expect(VECTORS.config.group).toBe("ristretto255");
    expect(VECTORS.config.hash).toBe("SHA-512");
    expect(parseInt(VECTORS.config.MAX_PARTICIPANTS)).toBe(3);
    expect(parseInt(VECTORS.config.MIN_PARTICIPANTS)).toBe(2);
    expect(parseInt(VECTORS.config.NUM_PARTICIPANTS)).toBe(2);
  });

  it("should have valid participant list", () => {
    expect(VECTORS.inputs.participant_list).toEqual([1, 3]);
    expect(VECTORS.inputs.participant_list.length).toBe(
      parseInt(VECTORS.config.NUM_PARTICIPANTS),
    );
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
    // Ristretto255 signature is 2 * 32 = 64 bytes = 128 hex chars
    expect(sig.length).toBe(128);
  });
});
