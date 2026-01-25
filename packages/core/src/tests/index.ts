/**
 * Generic FROST test functions.
 *
 * This module exports generic test functions that can be used by ciphersuite-specific
 * packages to test their implementations. The pattern follows Rust's frost-core
 * `test-impl` feature, where core provides parameterized test functions and
 * ciphersuites call them with their specific type.
 *
 * Usage in a ciphersuite package:
 * ```typescript
 * import { tests } from "@frosts/core";
 * import { Ristretto255Sha512 } from "../src/index.js";
 *
 * describe("CoefficientCommitment", () => {
 *   it("should serialize correctly", () => {
 *     const rng = tests.createSecureRng();
 *     tests.checkSerializationOfCoefficientCommitment(Ristretto255Sha512, rng);
 *   });
 * });
 * ```
 *
 * @module @frosts/core/tests
 */

// Re-export helper functions
export {
  generateElement,
  createTestRng,
  createSecureRng,
  hexToBytes,
  bytesToHex,
  type CryptoRng,
} from "./helpers.js";

// Re-export CoefficientCommitment test functions
export {
  checkSerializationOfCoefficientCommitment,
  checkCreateCoefficientCommitment,
  checkCreateCoefficientCommitmentError,
  checkGetValueOfCoefficientCommitment,
} from "./coefficient-commitment.js";

// Re-export VerifiableSecretSharingCommitment test functions
export {
  checkSerializeVssCommitment,
  checkSerializeWholeVssCommitment,
  checkDeserializeVssCommitment,
  checkDeserializeWholeVssCommitment,
  checkDeserializeVssCommitmentError,
  checkDeserializeWholeVssCommitmentError,
  checkDeserializeWholeVssCommitmentInvalidLength,
  checkComputePublicKeyPackage,
} from "./vss-commitment.js";
