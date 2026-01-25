/**
 * VerifiableSecretSharingCommitment tests for FROST P-256-SHA256.
 * Uses generic test functions from @frosts/core with the P256Sha256 ciphersuite.
 *
 * This pattern matches the Rust implementation where:
 * - frost-core provides generic test functions
 * - Ciphersuite packages call them with their specific type
 */

import { describe, it, beforeEach } from "vitest";
import { tests } from "@frosts/core";
import { P256Sha256 } from "../src/index.js";
import { createSecureRng, type CryptoRng } from "./helpers/index.js";
import elementsJson from "./helpers/elements.json";

describe("VerifiableSecretSharingCommitment (P256)", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize VSS commitment correctly", () => {
      tests.checkSerializeVssCommitment(P256Sha256, rng);
    });

    it("should serialize whole VSS commitment correctly", () => {
      tests.checkSerializeWholeVssCommitment(P256Sha256, rng);
    });
  });

  describe("Deserialization", () => {
    it("should deserialize VSS commitment correctly", () => {
      tests.checkDeserializeVssCommitment(P256Sha256, rng);
    });

    it("should deserialize whole VSS commitment correctly", () => {
      tests.checkDeserializeWholeVssCommitment(P256Sha256, rng);
    });
  });

  describe("Deserialization Errors", () => {
    it("should fail to deserialize with invalid element", () => {
      tests.checkDeserializeVssCommitmentError(P256Sha256, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid element", () => {
      tests.checkDeserializeWholeVssCommitmentError(P256Sha256, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid length", () => {
      tests.checkDeserializeWholeVssCommitmentInvalidLength(P256Sha256, rng);
    });
  });

  describe("Public Key Package Computation", () => {
    it("should compute public key package from list of commitments", async () => {
      await tests.checkComputePublicKeyPackage(P256Sha256, rng);
    });
  });
});
