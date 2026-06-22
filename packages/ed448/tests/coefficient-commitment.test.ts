/**
 * CoefficientCommitment tests for FROST Ed448-SHAKE256.
 * Uses generic test functions from @frosts/core with the Ed448Shake256 ciphersuite.
 *
 * This pattern matches the Rust implementation where:
 * - frost-core provides generic test functions
 * - Ciphersuite packages call them with their specific type
 */

import { describe, it, beforeEach } from "vitest";
import * as tests from "@frosts/core/tests";
import { Ed448Shake256 } from "../src/index.js";
import { createSecureRng, type CryptoRng } from "./helpers/index.js";
import elementsJson from "./helpers/elements.json";

describe("CoefficientCommitment (Ed448)", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize a CoefficientCommitment correctly", () => {
      tests.checkSerializationOfCoefficientCommitment(Ed448Shake256, rng);
    });
  });

  describe("Creation", () => {
    it("should create a CoefficientCommitment from serialized element", () => {
      tests.checkCreateCoefficientCommitment(Ed448Shake256, rng);
    });
  });

  describe("Error Handling", () => {
    it("should fail to deserialize an invalid element", () => {
      tests.checkCreateCoefficientCommitmentError(Ed448Shake256, elementsJson);
    });
  });

  describe("Value Retrieval", () => {
    it("should retrieve the element value from CoefficientCommitment", () => {
      tests.checkGetValueOfCoefficientCommitment(Ed448Shake256, rng);
    });
  });
});
