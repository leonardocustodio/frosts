/**
 * VerifiableSecretSharingCommitment tests for FROST Ristretto255-SHA512.
 * Uses generic test functions from @frosts/core with the Ristretto255Sha512 ciphersuite.
 *
 * This pattern matches the Rust implementation where:
 * - frost-core provides generic test functions
 * - Ciphersuite packages call them with their specific type
 */

import { describe, it, beforeEach } from "vitest";
import * as tests from "@frosts/core/tests";
import { Ristretto255Sha512 } from "../src/index.js";
import { createSecureRng, type CryptoRng } from "./helpers/index.js";
import elementsJson from "./helpers/elements.json";

describe("VerifiableSecretSharingCommitment (Ristretto255)", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize VSS commitment correctly", () => {
      tests.checkSerializeVssCommitment(Ristretto255Sha512, rng);
    });

    it("should serialize whole VSS commitment correctly", () => {
      tests.checkSerializeWholeVssCommitment(Ristretto255Sha512, rng);
    });
  });

  describe("Deserialization", () => {
    it("should deserialize VSS commitment correctly", () => {
      tests.checkDeserializeVssCommitment(Ristretto255Sha512, rng);
    });

    it("should deserialize whole VSS commitment correctly", () => {
      tests.checkDeserializeWholeVssCommitment(Ristretto255Sha512, rng);
    });
  });

  describe("Deserialization Errors", () => {
    it("should fail to deserialize with invalid element", () => {
      tests.checkDeserializeVssCommitmentError(Ristretto255Sha512, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid element", () => {
      tests.checkDeserializeWholeVssCommitmentError(Ristretto255Sha512, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid length", () => {
      tests.checkDeserializeWholeVssCommitmentInvalidLength(Ristretto255Sha512, rng);
    });
  });

  describe("Public Key Package Computation", () => {
    it("should compute public key package from list of commitments", async () => {
      await tests.checkComputePublicKeyPackage(Ristretto255Sha512, rng);
    });
  });
});
