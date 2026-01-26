/**
 * VerifiableSecretSharingCommitment tests for FROST Ed448-SHAKE256.
 * Uses generic test functions from @frosts/core with the Ed448Shake256 ciphersuite.
 *
 * This pattern matches the Rust implementation where:
 * - frost-core provides generic test functions
 * - Ciphersuite packages call them with their specific type
 */

import { describe, it, beforeEach } from "vitest";
import { tests } from "@frosts/core";
import { Ed448Shake256 } from "../src/index.js";
import { createSecureRng, type CryptoRng } from "./helpers/index.js";
import elementsJson from "./helpers/elements.json";

describe("VerifiableSecretSharingCommitment (Ed448)", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize VSS commitment correctly", () => {
      tests.checkSerializeVssCommitment(Ed448Shake256, rng);
    });

    it("should serialize whole VSS commitment correctly", () => {
      tests.checkSerializeWholeVssCommitment(Ed448Shake256, rng);
    });
  });

  describe("Deserialization", () => {
    it("should deserialize VSS commitment correctly", () => {
      tests.checkDeserializeVssCommitment(Ed448Shake256, rng);
    });

    it("should deserialize whole VSS commitment correctly", () => {
      tests.checkDeserializeWholeVssCommitment(Ed448Shake256, rng);
    });
  });

  describe("Deserialization Errors", () => {
    it("should fail to deserialize with invalid element", () => {
      tests.checkDeserializeVssCommitmentError(Ed448Shake256, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid element", () => {
      tests.checkDeserializeWholeVssCommitmentError(Ed448Shake256, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid length", () => {
      tests.checkDeserializeWholeVssCommitmentInvalidLength(Ed448Shake256, rng);
    });
  });

  describe("Public Key Package Computation", () => {
    it("should compute public key package from list of commitments", async () => {
      await tests.checkComputePublicKeyPackage(Ed448Shake256, rng);
    });
  });
});
