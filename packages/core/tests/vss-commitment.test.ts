/**
 * VerifiableSecretSharingCommitment functions tests.
 * Ported from frost-core/src/tests/vss_commitment.rs
 *
 * NOTE: These tests require a concrete ciphersuite implementation.
 * The actual tests are run in ciphersuite packages (e.g., @frosts/ristretto255)
 * using the generic test functions exported from @frosts/core.
 *
 * To run these tests with a specific ciphersuite, see:
 * - packages/ristretto255/tests/vss-commitment.test.ts
 * - packages/ed25519/tests/vss-commitment.test.ts
 * - etc.
 */

import { describe, it } from "vitest";

describe("VerifiableSecretSharingCommitment (Generic)", () => {
  describe("Serialization", () => {
    it.skip("should serialize VSS commitment correctly - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkSerializeVssCommitment() with a ciphersuite
    });

    it.skip("should serialize whole VSS commitment correctly - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkSerializeWholeVssCommitment() with a ciphersuite
    });
  });

  describe("Deserialization", () => {
    it.skip("should deserialize VSS commitment correctly - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkDeserializeVssCommitment() with a ciphersuite
    });

    it.skip("should deserialize whole VSS commitment correctly - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkDeserializeWholeVssCommitment() with a ciphersuite
    });
  });

  describe("Deserialization Errors", () => {
    it.skip("should fail to deserialize with invalid element - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkDeserializeVssCommitmentError() with a ciphersuite
    });

    it.skip("should fail to deserialize whole with invalid element - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkDeserializeWholeVssCommitmentError() with a ciphersuite
    });

    it.skip("should fail to deserialize whole with invalid length - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkDeserializeWholeVssCommitmentInvalidLength() with a ciphersuite
    });
  });

  describe("Public Key Package Computation", () => {
    it.skip("should compute public key package from list of commitments - requires concrete ciphersuite", () => {
      // Use @frosts/core tests.checkComputePublicKeyPackage() with a ciphersuite
    });
  });
});
