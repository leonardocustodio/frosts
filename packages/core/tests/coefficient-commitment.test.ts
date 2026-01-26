/**
 * CoefficientCommitment functions tests.
 * Ported from frost-core/src/tests/coefficient_commitment.rs
 *
 * These tests verify CoefficientCommitment functionality using a dynamically-loaded ciphersuite.
 */

import { describe, it, beforeAll, beforeEach } from "vitest";
import type { Ciphersuite, CryptoRng } from "../src/index.js";
import { createSecureRng } from "./helpers.js";
import { getTestCiphersuite } from "./helpers/ciphersuite.js";
import elementsJson from "./helpers/elements.json";

// Import the actual test functions from src/tests
import {
  checkSerializationOfCoefficientCommitment,
  checkCreateCoefficientCommitment,
  checkCreateCoefficientCommitmentError,
  checkGetValueOfCoefficientCommitment,
} from "../src/tests/coefficient-commitment.js";

describe("CoefficientCommitment (Generic)", () => {
  let rng: CryptoRng;
  let ciphersuite: Ciphersuite;

  beforeAll(async () => {
    ciphersuite = await getTestCiphersuite();
  });

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Serialization", () => {
    it("should serialize a CoefficientCommitment correctly", () => {
      checkSerializationOfCoefficientCommitment(ciphersuite, rng);
    });
  });

  describe("Creation", () => {
    it("should create a CoefficientCommitment from serialized element", () => {
      checkCreateCoefficientCommitment(ciphersuite, rng);
    });
  });

  describe("Error Handling", () => {
    it("should fail to deserialize an invalid element", () => {
      checkCreateCoefficientCommitmentError(ciphersuite, elementsJson);
    });
  });

  describe("Value Retrieval", () => {
    it("should retrieve the element value from CoefficientCommitment", () => {
      checkGetValueOfCoefficientCommitment(ciphersuite, rng);
    });
  });
});
