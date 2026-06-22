/**
 * CoefficientCommitment tests for FROST Ristretto255-SHA512.
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

describe("CoefficientCommitment (Ristretto255)", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize a CoefficientCommitment correctly", () => {
      tests.checkSerializationOfCoefficientCommitment(Ristretto255Sha512, rng);
    });
  });

  describe("Creation", () => {
    it("should create a CoefficientCommitment from serialized element", () => {
      tests.checkCreateCoefficientCommitment(Ristretto255Sha512, rng);
    });
  });

  describe("Error Handling", () => {
    it("should fail to deserialize an invalid element", () => {
      tests.checkCreateCoefficientCommitmentError(Ristretto255Sha512, elementsJson);
    });
  });

  describe("Value Retrieval", () => {
    it("should retrieve the element value from CoefficientCommitment", () => {
      tests.checkGetValueOfCoefficientCommitment(Ristretto255Sha512, rng);
    });
  });
});
