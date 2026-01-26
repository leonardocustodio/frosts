/**
 * CoefficientCommitment tests for FROST secp256k1-SHA256-TR (Taproot).
 * Uses generic test functions from @frosts/core with the Secp256K1Sha256TR ciphersuite.
 *
 * This pattern matches the Rust implementation where:
 * - frost-core provides generic test functions
 * - Ciphersuite packages call them with their specific type
 */

import { describe, it, beforeEach } from "vitest";
import { tests } from "@frosts/core";
import { Secp256K1Sha256TR } from "../src/index.js";
import { createSecureRng, type CryptoRng } from "./helpers/index.js";
import elementsJson from "./helpers/elements.json";

describe("CoefficientCommitment (Secp256K1-TR)", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize a CoefficientCommitment correctly", () => {
      tests.checkSerializationOfCoefficientCommitment(Secp256K1Sha256TR, rng);
    });
  });

  describe("Creation", () => {
    it("should create a CoefficientCommitment from serialized element", () => {
      tests.checkCreateCoefficientCommitment(Secp256K1Sha256TR, rng);
    });
  });

  describe("Error Handling", () => {
    it("should fail to deserialize an invalid element", () => {
      tests.checkCreateCoefficientCommitmentError(Secp256K1Sha256TR, elementsJson);
    });
  });

  describe("Value Retrieval", () => {
    it("should retrieve the element value from CoefficientCommitment", () => {
      tests.checkGetValueOfCoefficientCommitment(Secp256K1Sha256TR, rng);
    });
  });
});
