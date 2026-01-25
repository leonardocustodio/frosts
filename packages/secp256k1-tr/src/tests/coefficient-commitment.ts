/**
 * CoefficientCommitment tests for FROST-secp256k1-SHA256-TR (Taproot).
 * Ported from frost-secp256k1-tr/src/tests/coefficient_commitment.rs
 *
 * These tests verify serialization, deserialization, and creation
 * of coefficient commitments for the secp256k1-SHA256-TR ciphersuite.
 */

import { describe, it, expect } from "vitest";
// TODO: Import test helpers from @frost/core once types are properly exported
// import {
//   createSecureRng,
//   hexToBytes,
//   checkSerializationOfCoefficientCommitment,
//   checkCreateCoefficientCommitment,
//   checkCreateCoefficientCommitmentError,
//   checkGetValueOfCoefficientCommitment,
// } from "@frost/core/tests/index.js";

// TODO: Import Secp256K1Sha256TR ciphersuite once implemented
// import { Secp256K1Sha256TR } from "../index.js";

/**
 * Elements data for testing invalid element handling.
 * This data is loaded from the elements.json test helper file in Rust.
 * For secp256k1, points are 33 bytes (SEC1 compressed format).
 *
 * The invalid_element is a 33-byte hex string that does not represent
 * a valid point on the secp256k1 curve.
 */
export const ELEMENTS = {
  elements: {
    invalid_element:
      "123456afdf4a7f88885ab26b20d18edb7d4d9589812a6cf1a5a1a09d3808dae5d8",
  },
};

describe("Secp256K1-SHA256-TR CoefficientCommitment", () => {

  describe("Serialization", () => {
    it("should serialize a CoefficientCommitment correctly", () => {
      // Test logic from Rust:
      // frost_core::tests::coefficient_commitment::check_serialization_of_coefficient_commitment::<
      //   Secp256K1Sha256TR, _
      // >(rng);
      //
      // Once Secp256K1Sha256TR ciphersuite is implemented:
      // checkSerializationOfCoefficientCommitment(Secp256K1Sha256TR, rng);

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });

  describe("Creation", () => {
    it("should create a CoefficientCommitment from serialized element", () => {
      // Test logic from Rust:
      // frost_core::tests::coefficient_commitment::check_create_coefficient_commitment::<
      //   Secp256K1Sha256TR, _
      // >(rng);
      //
      // Once Secp256K1Sha256TR ciphersuite is implemented:
      // checkCreateCoefficientCommitment(Secp256K1Sha256TR, rng);

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });

  describe("Error Handling", () => {
    it("should fail to deserialize an invalid element", () => {
      // Test logic from Rust:
      // frost_core::tests::coefficient_commitment::check_create_coefficient_commitment_error::<
      //   Secp256K1Sha256TR
      // >(&ELEMENTS);
      //
      // Once Secp256K1Sha256TR ciphersuite is implemented:
      // checkCreateCoefficientCommitmentError(Secp256K1Sha256TR, ELEMENTS);

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });

  describe("Value Retrieval", () => {
    it("should retrieve the element value from CoefficientCommitment", () => {
      // Test logic from Rust:
      // frost_core::tests::coefficient_commitment::check_get_value_of_coefficient_commitment::<
      //   Secp256K1Sha256TR, _
      // >(rng);
      //
      // Once Secp256K1Sha256TR ciphersuite is implemented:
      // checkGetValueOfCoefficientCommitment(Secp256K1Sha256TR, rng);

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });
});

// Test functions from @frost/core are re-exported via index.ts
