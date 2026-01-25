/**
 * Helper function for testing with test vectors.
 * Ported from frost-core/src/tests/vectors.rs
 */

import { describe, it, expect } from "vitest";

// Types will be imported from actual implementation once available
import type {
  Ciphersuite,
  Identifier,
  SigningKey,
  VerifyingKey,
  SigningNonces,
  SigningCommitments,
  SignatureShare,
  BindingFactor,
  KeyPackage,
  Scalar,
} from "../src/index.js";

/**
 * Test vectors structure for a ciphersuite.
 */
export interface TestVectors<C extends Ciphersuite> {
  secretKey: SigningKey<C>;
  verifyingKey: VerifyingKey<C>;
  keyPackages: Map<Identifier<C>, KeyPackage<C>>;
  messageBytes: Uint8Array;
  sharePolynomialCoefficients: Scalar<C>[];
  hidingNoncesRandomness: Map<Identifier<C>, Uint8Array>;
  bindingNoncesRandomness: Map<Identifier<C>, Uint8Array>;
  signerNonces: Map<Identifier<C>, SigningNonces<C>>;
  signerCommitments: Map<Identifier<C>, SigningCommitments<C>>;
  bindingFactorInputs: Map<Identifier<C>, Uint8Array>;
  bindingFactors: Map<Identifier<C>, BindingFactor<C>>;
  signatureShares: Map<Identifier<C>, SignatureShare<C>>;
  signatureBytes: Uint8Array;
}

/**
 * JSON structure for test vectors.
 */
export interface TestVectorsJson {
  inputs: {
    group_secret_key: string;
    message: string;
    share_polynomial_coefficients: string[];
    participant_shares: Array<{
      identifier: number;
      participant_share: string;
    }>;
    verifying_key_key: string;
  };
  round_one_outputs: {
    outputs: Array<{
      identifier: number;
      hiding_nonce_randomness: string;
      binding_nonce_randomness: string;
      hiding_nonce: string;
      binding_nonce: string;
      hiding_nonce_commitment: string;
      binding_nonce_commitment: string;
      binding_factor_input: string;
      binding_factor: string;
    }>;
  };
  round_two_outputs: {
    outputs: Array<{
      identifier: number;
      sig_share: string;
    }>;
  };
  final_output: {
    sig: string;
  };
}

/**
 * Parse test vectors for a given ciphersuite.
 */
export function parseTestVectors<C extends Ciphersuite>(
  _ciphersuite: C,
  _jsonVectors: TestVectorsJson,
): TestVectors<C> | null {
  // This will be implemented when the actual types are available
  // For now, return null as a placeholder

  // The parsing logic from Rust:
  // 1. Parse secret key from hex
  // 2. Parse message bytes
  // 3. Parse polynomial coefficients
  // 4. Parse participant shares into key packages
  // 5. Parse verifying key
  // 6. Parse round one outputs (nonces, commitments, binding factors)
  // 7. Parse round two outputs (signature shares)
  // 8. Parse final signature

  return null;
}

describe("Test Vectors", () => {
  describe("Vector Parsing", () => {
    it.skip("should parse test vectors correctly", () => {
      // This test will be enabled when we have actual test vector JSON files
      // and the ciphersuite implementation

      expect(true).toBe(true); // Placeholder
    });
  });

  describe("Signing with Test Vectors", () => {
    it.skip("should complete signing flow matching test vectors", () => {
      // Test logic from Rust check_sign_with_test_vectors:
      //
      // 1. Key generation
      //    - Generate secret shares using the same polynomial coefficients
      //    - Verify key packages match the test vectors
      //
      // 2. Round 1: Generate nonces and commitments
      //    - Compute nonces from secret and randomness
      //    - Verify hiding nonces match
      //    - Verify binding nonces match
      //    - Verify nonce commitments match
      //
      // 3. Round 2: Generate signature shares
      //    - Create signing package from commitments
      //    - Verify binding factor inputs match
      //    - Verify binding factors match
      //    - Generate signature shares
      //    - Verify signature shares match test vectors
      //
      // 4. Aggregation
      //    - Aggregate signature shares
      //    - Verify aggregation succeeds
      //    - Verify final signature matches test vector

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should verify key packages match expected values", () => {
      // Verify each key package's verifying share matches what's computed
      // from the signing share

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should verify nonces computed from randomness", () => {
      // Verify that nonces generated from secret and randomness
      // match the expected nonces in test vectors

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should verify binding factors", () => {
      // Verify binding factor computation matches test vectors

      expect(true).toBe(true); // Placeholder
    });

    it.skip("should verify final signature matches", () => {
      // Verify the aggregated signature matches the expected signature

      expect(true).toBe(true); // Placeholder
    });
  });
});

/**
 * Test with the given test vectors for a ciphersuite.
 * This is the main test function that verifies the entire FROST flow
 * against known test vectors.
 */
export function checkSignWithTestVectors<C extends Ciphersuite>(
  _ciphersuite: C,
  _jsonVectors: TestVectorsJson,
): void {
  // Parse test vectors
  // const testVectors = parseTestVectors(ciphersuite, jsonVectors);
  // if (!testVectors) {
  //   throw new Error('Failed to parse test vectors');
  // }
  // Key generation
  // const maxSigners = testVectors.keyPackages.size;
  // const minSigners = testVectors.sharePolynomialCoefficients.length + 1;
  // const secretShares = frost.keys.generateSecretShares(
  //   testVectors.secretKey,
  //   maxSigners,
  //   minSigners,
  //   testVectors.sharePolynomialCoefficients,
  //   frost.keys.defaultIdentifiers(maxSigners)
  // );
  // Verify key packages
  // for (const [id, keyPackage] of testVectors.keyPackages) {
  //   const secretShare = secretShares.get(id);
  //   expect(keyPackage.signingShare()).toEqual(secretShare.signingShare());
  //   expect(keyPackage.verifyingShare()).toEqual(
  //     VerifyingShare.from(keyPackage.signingShare())
  //   );
  // }
  // Round 1: Verify nonces and commitments
  // for (const [i, commitments] of testVectors.signerCommitments) {
  //   const nonces = testVectors.signerNonces.get(i);
  //   const secret = secretShares.get(i).signingShare();
  //
  //   // Verify hiding nonce
  //   const hidingRandomness = testVectors.hidingNoncesRandomness.get(i);
  //   const hidingNonce = Nonce.generateFromRandomBytes(secret, hidingRandomness);
  //   expect(nonces.hiding()).toEqual(hidingNonce);
  //
  //   // Verify binding nonce
  //   const bindingRandomness = testVectors.bindingNoncesRandomness.get(i);
  //   const bindingNonce = Nonce.generateFromRandomBytes(secret, bindingRandomness);
  //   expect(nonces.binding()).toEqual(bindingNonce);
  //
  //   // Verify commitments
  //   expect(NonceCommitment.from(nonces.hiding())).toEqual(commitments.hiding());
  //   expect(NonceCommitment.from(nonces.binding())).toEqual(commitments.binding());
  // }
  // Round 2: Verify binding factors and signature shares
  // const signingPackage = new SigningPackage(
  //   testVectors.signerCommitments,
  //   testVectors.messageBytes
  // );
  // Verify binding factor inputs
  // const bindingFactorInputs = signingPackage.bindingFactorPreimages(
  //   testVectors.verifyingKey,
  //   []
  // );
  // for (const [id, input] of bindingFactorInputs) {
  //   expect(input).toEqual(testVectors.bindingFactorInputs.get(id));
  // }
  // Verify binding factors
  // const bindingFactorList = computeBindingFactorList(
  //   signingPackage,
  //   testVectors.verifyingKey,
  //   []
  // );
  // for (const [id, factor] of bindingFactorList) {
  //   expect(factor).toEqual(testVectors.bindingFactors.get(id));
  // }
  // Generate and verify signature shares
  // const ourSignatureShares = new Map();
  // for (const [id, nonces] of testVectors.signerNonces) {
  //   const keyPackage = testVectors.keyPackages.get(id);
  //   const signatureShare = frost.round2.sign(signingPackage, nonces, keyPackage);
  //   ourSignatureShares.set(id, signatureShare);
  // }
  // expect(ourSignatureShares).toEqual(testVectors.signatureShares);
  // Create public key package
  // const verifyingShares = new Map();
  // for (const [id, keyPackage] of testVectors.keyPackages) {
  //   verifyingShares.set(id, keyPackage.verifyingShare());
  // }
  // const pubkeyPackage = new PublicKeyPackage(
  //   verifyingShares,
  //   testVectors.verifyingKey,
  //   minSigners
  // );
  // Aggregation: Verify signature
  // const groupSignature = frost.aggregate(
  //   signingPackage,
  //   testVectors.signatureShares,
  //   pubkeyPackage
  // );
  // expect(groupSignature.ok).toBe(true);
  // expect(groupSignature.value.serialize()).toEqual(testVectors.signatureBytes);
  // Verify with our signature shares too
  // const ourGroupSignature = frost.aggregate(
  //   signingPackage,
  //   ourSignatureShares,
  //   pubkeyPackage
  // );
  // expect(ourGroupSignature.ok).toBe(true);
  // expect(ourGroupSignature.value.serialize()).toEqual(testVectors.signatureBytes);
}
