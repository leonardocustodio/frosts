/**
 * CoefficientCommitment functions tests.
 * Ported from frost-core/src/tests/coefficient_commitment.rs
 *
 * NOTE: These tests require a concrete ciphersuite implementation.
 * The actual tests are run in ciphersuite packages (e.g., @frosts/ristretto255)
 * using the generic test functions exported from @frosts/core.
 *
 * To run these tests with a specific ciphersuite, see:
 * - packages/ristretto255/tests/coefficient-commitment.test.ts
 * - packages/ed25519/tests/coefficient-commitment.test.ts
 * - etc.
 */

import { describe, it } from "vitest";

describe("CoefficientCommitment (Generic)", () => {
  describe("Serialization", () => {
    it.skip("should serialize a CoefficientCommitment correctly - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkSerializationOfCoefficientCommitment() with a ciphersuite
    });
  });

  describe("Creation", () => {
    it.skip("should create a CoefficientCommitment from serialized element - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkCreateCoefficientCommitment() with a ciphersuite
    });
  });

  describe("Error Handling", () => {
    it.skip("should fail to deserialize an invalid element - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkCreateCoefficientCommitmentError() with a ciphersuite
    });
  });

  describe("Value Retrieval", () => {
    it.skip("should retrieve the element value from CoefficientCommitment - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkGetValueOfCoefficientCommitment() with a ciphersuite
    });
  });
});
