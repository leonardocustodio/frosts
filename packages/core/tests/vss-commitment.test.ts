/**
 * VerifiableSecretSharingCommitment functions tests.
 * Ported from frost-core/src/tests/vss_commitment.rs
 *
 * These tests verify VSS commitment functionality using a dynamically-loaded ciphersuite.
 */

import { describe, it, beforeAll, beforeEach } from "vitest";
import type { Ciphersuite, CryptoRng } from "../src/index.js";
import { createSecureRng } from "./helpers.js";
import { getTestCiphersuite } from "./helpers/ciphersuite.js";
import elementsJson from "./helpers/elements.json";

// Import the actual test functions from src/tests
import {
  checkSerializeVssCommitment,
  checkSerializeWholeVssCommitment,
  checkDeserializeVssCommitment,
  checkDeserializeWholeVssCommitment,
  checkDeserializeVssCommitmentError,
  checkDeserializeWholeVssCommitmentError,
  checkDeserializeWholeVssCommitmentInvalidLength,
  checkComputePublicKeyPackage,
} from "../src/tests/vss-commitment.js";

describe("VerifiableSecretSharingCommitment (Generic)", () => {
  let rng: CryptoRng;
  let ciphersuite: Ciphersuite;

  beforeAll(async () => {
    ciphersuite = await getTestCiphersuite();
  });

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize VSS commitment correctly", () => {
      checkSerializeVssCommitment(ciphersuite, rng);
    });

    it("should serialize whole VSS commitment correctly", () => {
      checkSerializeWholeVssCommitment(ciphersuite, rng);
    });
  });

  describe("Deserialization", () => {
    it("should deserialize VSS commitment correctly", () => {
      checkDeserializeVssCommitment(ciphersuite, rng);
    });

    it("should deserialize whole VSS commitment correctly", () => {
      checkDeserializeWholeVssCommitment(ciphersuite, rng);
    });
  });

  describe("Deserialization Errors", () => {
    it("should fail to deserialize with invalid element", () => {
      checkDeserializeVssCommitmentError(ciphersuite, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid element", () => {
      checkDeserializeWholeVssCommitmentError(ciphersuite, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid length", () => {
      checkDeserializeWholeVssCommitmentInvalidLength(ciphersuite, rng);
    });
  });

  describe("Public Key Package Computation", () => {
    it("should compute public key package from list of commitments", async () => {
      await checkComputePublicKeyPackage(ciphersuite, rng);
    });
  });
});
