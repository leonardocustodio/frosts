/**
 * VerifiableSecretSharingCommitment tests for FROST secp256k1-SHA256-TR (Taproot).
 * Uses generic test functions from @frosts/core with the Secp256K1Sha256TR ciphersuite.
 *
 * This pattern matches the Rust implementation where:
 * - frost-core provides generic test functions
 * - Ciphersuite packages call them with their specific type
 */

import { describe, it, beforeEach } from "vitest";
import * as tests from "@frosts/core/tests";
import { Secp256K1Sha256TR } from "../src/index.js";
import { createSecureRng, type CryptoRng } from "./helpers/index.js";
import elementsJson from "./helpers/elements.json";

describe("VerifiableSecretSharingCommitment (Secp256K1-TR)", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize VSS commitment correctly", () => {
      tests.checkSerializeVssCommitment(Secp256K1Sha256TR, rng);
    });

    it("should serialize whole VSS commitment correctly", () => {
      tests.checkSerializeWholeVssCommitment(Secp256K1Sha256TR, rng);
    });
  });

  describe("Deserialization", () => {
    it("should deserialize VSS commitment correctly", () => {
      tests.checkDeserializeVssCommitment(Secp256K1Sha256TR, rng);
    });

    it("should deserialize whole VSS commitment correctly", () => {
      tests.checkDeserializeWholeVssCommitment(Secp256K1Sha256TR, rng);
    });
  });

  describe("Deserialization Errors", () => {
    it("should fail to deserialize with invalid element", () => {
      tests.checkDeserializeVssCommitmentError(Secp256K1Sha256TR, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid element", () => {
      tests.checkDeserializeWholeVssCommitmentError(Secp256K1Sha256TR, rng, elementsJson);
    });

    it("should fail to deserialize whole with invalid length", () => {
      tests.checkDeserializeWholeVssCommitmentInvalidLength(Secp256K1Sha256TR, rng);
    });
  });

  describe("Public Key Package Computation", () => {
    it("should compute public key package from list of commitments", async () => {
      await tests.checkComputePublicKeyPackage(Secp256K1Sha256TR, rng);
    });
  });
});
