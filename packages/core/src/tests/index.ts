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
 * import * as tests from "@frosts/core/tests";
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

// Re-export batch verification test functions
export { checkBatchVerify, checkBadBatchVerify, checkEmptyBatchVerify } from "./batch.js";

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

// Re-export ciphersuite-generic test functions
export {
  checkZeroKeyFails,
  checkShareGeneration,
  checkShareGenerationFailsWithInvalidSigners,
  checkSignWithDealer,
  checkSign,
  checkSignWithDealerFailsWithInvalidSigners,
  checkErrorCulprit,
  checkIdentifierDerivation,
  checkSignWithDkg,
  checkDkgPart1FailsWithInvalidSigners,
  checkInteroperabilityInDealer,
  checkInteroperabilityInDkg,
  type InteroperabilityVerifier,
  // Test vector verification functions
  checkTestVectorSignature,
  checkTestVectorVerifyingKey,
  type TestVectorData,
  // Error handling test functions
  checkSignErrors,
  checkAggregateErrors,
  checkAggregateCorruptedShare,
  checkAggregateInvalidShareIdentifierForVerifyingShares,
  checkVerifyingShares,
  checkVerifySignatureShare,
  checkPart2Error,
  checkPart3CorruptedShare,
  checkPart3Errors,
  checkPart3DifferentParticipants,
  // Signing error case test functions
  checkSignWithMissingIdentifier,
  checkSignWithIncorrectCommitments,
  // Self-contained wrapper test functions
  checkSignErrorsWithSetup,
  checkAggregateErrorsWithSetup,
  checkVerifyingSharesWithSetup,
  checkDkgPart2ErrorWithSetup,
  checkDkgPart3ErrorsWithSetup,
  // Additional signing tests
  checkSignWithDealerAndIdentifiers,
  asyncCheckSign,
} from "./ciphersuite-generic.js";

// Re-export share refresh test functions
export {
  checkRefreshSharesWithDealer,
  checkRefreshSharesWithDealerFailsWithInvalidSigners,
  checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage,
  checkRefreshSharesWithDealerFailsWithInvalidIdentifier,
  checkRefreshSharesWithDealerSerialisation,
  checkRefreshSharesWithDkg,
  checkRefreshSharesWithDkgSmallerThreshold,
} from "./refresh.js";

// Re-export repairable threshold scheme test functions
export {
  checkRts,
  checkRepairShareStep1,
  checkRepairShareStep2,
  checkRepairShareStep3,
  checkRepairShareStep1FailsWithInvalidMinSigners,
  type RepairShareStep2TestData,
  type RepairShareStep3TestData,
} from "./repairable.js";

// Re-export DKG test vector functions
export {
  checkDkgKeygen,
  parseTestVectorsDkg,
  buildRound1Package,
  buildRound2Package,
  buildPublicKeyPackage,
  type DKGTestVectors,
  type DKGTestVectorsJson,
} from "./vectors-dkg.js";

// Re-export property-based test functions
export { SignatureCase, Tweak, checkSignatureWithTweak } from "./proptests.js";

// Re-export test vector functions for signing
export {
  parseTestVectors,
  checkSignWithTestVectors,
  type TestVectors,
  type TestVectorsJson,
} from "./vectors.js";
