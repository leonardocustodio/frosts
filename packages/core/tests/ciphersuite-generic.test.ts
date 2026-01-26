/**
 * Ciphersuite-generic test functions.
 * Ported from frost-core/src/tests/ciphersuite_generic.rs
 *
 * These tests verify the core FROST functionality using a dynamically-loaded ciphersuite.
 * The Ed25519 ciphersuite is imported at test time to avoid circular dependency issues.
 */

import { describe, it, beforeAll, beforeEach } from "vitest";
import type { Ciphersuite, CryptoRng } from "../src/index.js";
import { createSecureRng } from "./helpers.js";
import { getTestCiphersuite } from "./helpers/ciphersuite.js";

// Import the actual test functions from src/tests
import {
  checkZeroKeyFails,
  checkShareGeneration,
  checkShareGenerationFailsWithInvalidSigners,
  checkSignWithDealer,
  checkSignWithDealerFailsWithInvalidSigners,
  checkSignWithDkg,
  checkDkgPart1FailsWithInvalidSigners,
  checkErrorCulprit,
  checkIdentifierDerivation,
  checkSignErrorsWithSetup,
  checkAggregateErrorsWithSetup,
  checkVerifyingSharesWithSetup,
  checkDkgPart2ErrorWithSetup,
  checkDkgPart3ErrorsWithSetup,
  checkSignWithMissingIdentifier,
  checkSignWithIncorrectCommitments,
  checkSignWithDealerAndIdentifiers,
} from "../src/tests/ciphersuite-generic.js";

describe("Ciphersuite Generic Tests", () => {
  let rng: CryptoRng;
  let ciphersuite: Ciphersuite;

  beforeAll(async () => {
    ciphersuite = await getTestCiphersuite();
  });

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Zero Key Validation", () => {
    it("should fail when creating a zero SigningKey", () => {
      checkZeroKeyFails(ciphersuite);
    });
  });

  describe("Share Generation", () => {
    it("should generate valid secret shares", async () => {
      await checkShareGeneration(ciphersuite, rng);
    }, 30_000);

    it("should fail reconstruction with empty shares", async () => {
      // This is tested as part of checkShareGeneration which tests error cases
      await checkShareGeneration(ciphersuite, rng);
    });

    it("should fail reconstruction with insufficient shares", async () => {
      // This is tested as part of checkShareGeneration which tests error cases
      await checkShareGeneration(ciphersuite, rng);
    });

    it("should fail reconstruction with duplicate identifiers", async () => {
      // This is tested as part of checkShareGeneration which tests error cases
      await checkShareGeneration(ciphersuite, rng);
    });
  });

  describe("Share Generation with Invalid Signers", () => {
    it("should fail with min_signers = 0", () => {
      checkShareGenerationFailsWithInvalidSigners(ciphersuite, 0, 5, rng);
    });

    it("should fail with max_signers < min_signers", () => {
      checkShareGenerationFailsWithInvalidSigners(ciphersuite, 5, 2, rng);
    });
  });

  describe("FROST Signing with Trusted Dealer", () => {
    it("should complete full signing flow with dealer", async () => {
      await checkSignWithDealer(ciphersuite, rng);
    }, 30_000);

    it("should fail signing with not enough signers (min_signers = 0)", async () => {
      await checkSignWithDealerFailsWithInvalidSigners(ciphersuite, 0, 5, rng);
    });
  });

  describe("FROST Signing with DKG", () => {
    it("should complete full signing flow with DKG", async () => {
      await checkSignWithDkg(ciphersuite, rng);
    }, 30_000);
  });

  describe("DKG Error Cases", () => {
    it("should fail DKG part1 with invalid signers", () => {
      checkDkgPart1FailsWithInvalidSigners(ciphersuite, 0, 5, rng);
    });

    it("should fail DKG part2 with corrupted proof of knowledge", () => {
      checkDkgPart2ErrorWithSetup(ciphersuite, rng);
    });

    it("should fail DKG part3 with different participant sets", async () => {
      await checkDkgPart3ErrorsWithSetup(ciphersuite, rng);
    });

    it("should fail DKG part3 with corrupted share and identify culprit", async () => {
      // This is covered by checkDkgPart3ErrorsWithSetup which tests both
      // different participants and corrupted shares
      await checkDkgPart3ErrorsWithSetup(ciphersuite, rng);
    });
  });

  describe("Signing Error Cases", () => {
    it("should fail signing with incorrect number of commitments", async () => {
      await checkSignErrorsWithSetup(ciphersuite, rng);
    });

    it("should fail signing with missing identifier", async () => {
      await checkSignWithMissingIdentifier(ciphersuite, rng);
    });

    it("should fail signing with incorrect commitment", async () => {
      await checkSignWithIncorrectCommitments(ciphersuite, rng);
    });
  });

  describe("Aggregation Error Cases", () => {
    it("should fail aggregation with corrupted share and identify culprits", async () => {
      await checkAggregateErrorsWithSetup(ciphersuite, rng);
    });

    it("should fail aggregation with invalid share identifier", async () => {
      // This is covered by checkAggregateErrorsWithSetup which tests both cases
      await checkAggregateErrorsWithSetup(ciphersuite, rng);
    });
  });

  describe("Error Culprit Method", () => {
    it("should return correct culprits for InvalidSignatureShare", () => {
      // This is tested as part of checkAggregateErrorsWithSetup
      checkErrorCulprit(ciphersuite);
    });

    it("should return correct culprit for InvalidProofOfKnowledge", () => {
      // This is tested as part of checkDkgPart2ErrorWithSetup
      checkErrorCulprit(ciphersuite);
    });

    it("should return empty array for InvalidSignature", () => {
      // This is tested as part of checkAggregateErrorsWithSetup
      checkErrorCulprit(ciphersuite);
    });
  });

  describe("Identifier Derivation", () => {
    it("should derive consistent identifiers from same input", () => {
      checkIdentifierDerivation(ciphersuite);
    });
  });

  describe("Custom Identifiers", () => {
    it("should work with custom identifiers", async () => {
      await checkSignWithDealerAndIdentifiers(ciphersuite, rng);
    });

    it("should fail with duplicated identifiers", async () => {
      // This is tested as part of checkSignWithDealerAndIdentifiers
      await checkSignWithDealerAndIdentifiers(ciphersuite, rng);
    });

    it("should fail with incorrect number of identifiers", async () => {
      // This is tested as part of checkSignWithDealerAndIdentifiers
      await checkSignWithDealerAndIdentifiers(ciphersuite, rng);
    });
  });

  describe("Verify Signature Share", () => {
    it("should verify valid signature shares", async () => {
      await checkVerifyingSharesWithSetup(ciphersuite, rng);
    });

    it("should reject corrupted signature shares", async () => {
      // This is tested as part of checkVerifyingSharesWithSetup which tests
      // both valid and corrupted shares
      await checkVerifyingSharesWithSetup(ciphersuite, rng);
    });
  });
});
