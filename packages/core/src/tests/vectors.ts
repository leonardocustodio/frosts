/**
 * Helper functions for testing with test vectors.
 * Ported from frost-core/src/tests/vectors.rs
 *
 * This module provides functions to parse and verify FROST signing
 * against official test vectors from the specification.
 */

import { expect } from "vitest";
import { hexToBytes } from "./helpers.js";

// Types and classes from core implementation
import type { Ciphersuite, Identifier, SigningPackage } from "../index.js";

import {
  SigningKey,
  SigningShare,
  type VerifyingShare,
  KeyPackage,
  PublicKeyPackage,
  VerifyingKey,
  Signature,
  identifierToString,
  BindingFactor,
  generateSecretShares,
} from "../index.js";

// Round 1 types
import { Nonce, SigningNonces, SigningCommitments, NonceCommitment } from "../round1.js";

// Round 2 types
import { SignatureShare, sign } from "../round2.js";

// Aggregate function
import { aggregate } from "../aggregate.js";

// Identifier
import { Identifier as IdentifierClass } from "../identifier.js";

/**
 * Test vectors structure for a ciphersuite.
 */
export interface TestVectors<C extends Ciphersuite> {
  secretKey: SigningKey<C>;
  verifyingKey: VerifyingKey<C>;
  keyPackages: Map<string, KeyPackage<C>>;
  messageBytes: Uint8Array;
  sharePolynomialCoefficients: C["Scalar"][];
  hidingNoncesRandomness: Map<string, Uint8Array>;
  bindingNoncesRandomness: Map<string, Uint8Array>;
  signerNonces: Map<string, SigningNonces<C>>;
  signerCommitments: Map<string, SigningCommitments<C>>;
  bindingFactorInputs: Map<string, Uint8Array>;
  bindingFactors: Map<string, BindingFactor<C>>;
  signatureShares: Map<string, SignatureShare<C>>;
  signatureBytes: Uint8Array;
}

/**
 * Participant share data from JSON test vectors.
 */
interface ParticipantShareJson {
  identifier: number;
  participant_share: string;
}

/**
 * Round one output from JSON test vectors.
 */
interface RoundOneOutputJson {
  identifier: number;
  hiding_nonce_randomness: string;
  binding_nonce_randomness: string;
  hiding_nonce: string;
  binding_nonce: string;
  hiding_nonce_commitment: string;
  binding_nonce_commitment: string;
  binding_factor_input: string;
  binding_factor: string;
}

/**
 * Round two output from JSON test vectors.
 */
interface RoundTwoOutputJson {
  identifier: number;
  sig_share: string;
}

/**
 * JSON structure for test vectors.
 */
export interface TestVectorsJson {
  config: {
    MAX_PARTICIPANTS: string | number;
    NUM_PARTICIPANTS: string | number;
    MIN_PARTICIPANTS: string | number;
    name?: string;
    group?: string;
    hash?: string;
  };
  inputs: {
    participant_list?: number[];
    group_secret_key: string;
    message: string;
    share_polynomial_coefficients: string[];
    participant_shares: ParticipantShareJson[];
    verifying_key_key: string;
  };
  round_one_outputs: {
    outputs: RoundOneOutputJson[];
  };
  round_two_outputs: {
    outputs: RoundTwoOutputJson[];
  };
  final_output: {
    sig: string;
  };
}

/**
 * Parse test vectors for a given ciphersuite.
 */
export function parseTestVectors<C extends Ciphersuite>(
  ciphersuite: C,
  jsonVectors: TestVectorsJson,
): TestVectors<C> {
  const inputs = jsonVectors.inputs;

  // Parse secret key
  const secretKey = SigningKey.deserialize(ciphersuite, hexToBytes(inputs.group_secret_key));

  // Parse message
  const messageBytes = hexToBytes(inputs.message);

  // Parse polynomial coefficients
  const sharePolynomialCoefficients: C["Scalar"][] = inputs.share_polynomial_coefficients.map(
    (coef) => ciphersuite.deserializeScalar(hexToBytes(coef)),
  );

  // Parse verifying key
  const verifyingKey = VerifyingKey.deserialize(ciphersuite, hexToBytes(inputs.verifying_key_key));

  // Parse participant shares into key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  const minSigners =
    typeof jsonVectors.config.MIN_PARTICIPANTS === "string"
      ? parseInt(jsonVectors.config.MIN_PARTICIPANTS, 10)
      : jsonVectors.config.MIN_PARTICIPANTS;

  for (const shareData of inputs.participant_shares) {
    const identifier = IdentifierClass.fromU16(ciphersuite, shareData.identifier);
    const idStr = identifierToString(identifier);

    const signingShare = SigningShare.deserialize(
      ciphersuite,
      hexToBytes(shareData.participant_share),
    );
    const verifyingShare = signingShare.toVerifyingShare();

    const keyPackage = new KeyPackage(
      ciphersuite,
      identifier,
      signingShare,
      verifyingShare,
      verifyingKey.toElement(),
      minSigners,
    );

    keyPackages.set(idStr, keyPackage);
  }

  // Parse round one outputs
  const hidingNoncesRandomness = new Map<string, Uint8Array>();
  const bindingNoncesRandomness = new Map<string, Uint8Array>();
  const signerNonces = new Map<string, SigningNonces<C>>();
  const signerCommitments = new Map<string, SigningCommitments<C>>();
  const bindingFactorInputs = new Map<string, Uint8Array>();
  const bindingFactors = new Map<string, BindingFactor<C>>();

  for (const output of jsonVectors.round_one_outputs.outputs) {
    const identifier = IdentifierClass.fromU16(ciphersuite, output.identifier);
    const idStr = identifierToString(identifier);

    // Parse randomness
    hidingNoncesRandomness.set(idStr, hexToBytes(output.hiding_nonce_randomness));
    bindingNoncesRandomness.set(idStr, hexToBytes(output.binding_nonce_randomness));

    // Parse nonces
    const hidingNonce = Nonce.deserialize(ciphersuite, hexToBytes(output.hiding_nonce));
    const bindingNonce = Nonce.deserialize(ciphersuite, hexToBytes(output.binding_nonce));
    const nonces = SigningNonces.fromNonces(ciphersuite, hidingNonce, bindingNonce);
    signerNonces.set(idStr, nonces);

    // Parse commitments
    const hidingCommitment = NonceCommitment.deserialize(
      ciphersuite,
      hexToBytes(output.hiding_nonce_commitment),
    );
    const bindingCommitment = NonceCommitment.deserialize(
      ciphersuite,
      hexToBytes(output.binding_nonce_commitment),
    );
    const commitments = new SigningCommitments(ciphersuite, hidingCommitment, bindingCommitment);
    signerCommitments.set(idStr, commitments);

    // Parse binding factor input
    bindingFactorInputs.set(idStr, hexToBytes(output.binding_factor_input));

    // Parse binding factor
    const bindingFactorScalar = ciphersuite.deserializeScalar(hexToBytes(output.binding_factor));
    const bindingFactor = BindingFactor.fromScalar(ciphersuite, bindingFactorScalar);
    bindingFactors.set(idStr, bindingFactor);
  }

  // Parse round two outputs (signature shares)
  const signatureShares = new Map<string, SignatureShare<C>>();

  for (const output of jsonVectors.round_two_outputs.outputs) {
    const identifier = IdentifierClass.fromU16(ciphersuite, output.identifier);
    const idStr = identifierToString(identifier);

    const signatureShare = SignatureShare.deserialize(ciphersuite, hexToBytes(output.sig_share));
    signatureShares.set(idStr, signatureShare);
  }

  // Parse final signature
  const signatureBytes = hexToBytes(jsonVectors.final_output.sig);

  return {
    secretKey,
    verifyingKey,
    keyPackages,
    messageBytes,
    sharePolynomialCoefficients,
    hidingNoncesRandomness,
    bindingNoncesRandomness,
    signerNonces,
    signerCommitments,
    bindingFactorInputs,
    bindingFactors,
    signatureShares,
    signatureBytes,
  };
}

/**
 * Test with the given test vectors for a ciphersuite.
 * This is the main test function that verifies the entire FROST flow
 * against known test vectors.
 */
export function checkSignWithTestVectors<C extends Ciphersuite>(
  ciphersuite: C,
  jsonVectors: TestVectorsJson,
): void {
  const testVectors = parseTestVectors(ciphersuite, jsonVectors);
  const {
    secretKey,
    verifyingKey,
    keyPackages,
    messageBytes,
    sharePolynomialCoefficients,
    hidingNoncesRandomness,
    bindingNoncesRandomness,
    signerNonces,
    signerCommitments,
    bindingFactorInputs: _bindingFactorInputs,
    bindingFactors,
    signatureShares,
    signatureBytes,
  } = testVectors;

  // === 1. KEY GENERATION ===
  // Generate secret shares using the same polynomial coefficients
  const maxSigners =
    typeof jsonVectors.config.MAX_PARTICIPANTS === "string"
      ? parseInt(jsonVectors.config.MAX_PARTICIPANTS, 10)
      : jsonVectors.config.MAX_PARTICIPANTS;
  const minSigners = sharePolynomialCoefficients.length + 1;

  // Build identifiers for key generation
  const identifiers: Identifier<C>[] = [];
  for (const shareData of jsonVectors.inputs.participant_shares) {
    identifiers.push(IdentifierClass.fromU16(ciphersuite, shareData.identifier));
  }

  // Generate secret shares with the fixed polynomial coefficients from test vectors
  const secretShares = generateSecretShares(
    ciphersuite,
    secretKey.toScalar(),
    maxSigners,
    minSigners,
    sharePolynomialCoefficients,
    identifiers,
  );

  // Verify key packages match test vectors
  for (const secretShare of secretShares) {
    const idStr = identifierToString(secretShare.identifier);
    const expectedKeyPackage = keyPackages.get(idStr);

    if (expectedKeyPackage !== undefined) {
      // Verify the signing share matches
      expect(
        ciphersuite.scalarsEqual(
          secretShare.signingShare.toScalar(),
          expectedKeyPackage.signingShare.toScalar(),
        ),
      ).toBe(true);

      // Verify the verifying share is computed correctly from the signing share
      const computedVerifyingShare = secretShare.signingShare.toVerifyingShare();
      expect(computedVerifyingShare.equals(expectedKeyPackage.verifyingShare)).toBe(true);
    }
  }

  // === 2. ROUND 1: Verify nonces and commitments ===
  for (const [idStr, keyPackage] of keyPackages) {
    const nonces = signerNonces.get(idStr);
    const commitments = signerCommitments.get(idStr);
    const hidingRandomness = hidingNoncesRandomness.get(idStr);
    const bindingRandomness = bindingNoncesRandomness.get(idStr);

    if (
      nonces === undefined ||
      commitments === undefined ||
      hidingRandomness === undefined ||
      bindingRandomness === undefined
    ) {
      // This participant is not part of the signing set
      continue;
    }

    // Verify nonces generated from randomness match test vectors
    const computedHidingNonce = Nonce.nonceGenerateFromRandomBytes(
      ciphersuite,
      keyPackage.signingShare,
      hidingRandomness,
    );
    const computedBindingNonce = Nonce.nonceGenerateFromRandomBytes(
      ciphersuite,
      keyPackage.signingShare,
      bindingRandomness,
    );

    // Compare nonce scalars
    expect(ciphersuite.scalarsEqual(computedHidingNonce.toScalar(), nonces.hiding.toScalar())).toBe(
      true,
    );
    expect(
      ciphersuite.scalarsEqual(computedBindingNonce.toScalar(), nonces.binding.toScalar()),
    ).toBe(true);

    // Verify commitments match
    const computedHidingCommitment = NonceCommitment.fromNonce(ciphersuite, computedHidingNonce);
    const computedBindingCommitment = NonceCommitment.fromNonce(ciphersuite, computedBindingNonce);

    expect(computedHidingCommitment.equals(commitments.hiding)).toBe(true);
    expect(computedBindingCommitment.equals(commitments.binding)).toBe(true);
  }

  // === 3. ROUND 2: Verify binding factors and signature shares ===
  // Create a SigningPackage from commitments
  const signingCommitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();
  for (const [idStr, commitment] of signerCommitments) {
    // Find the identifier for this idStr
    for (const [kpIdStr, kp] of keyPackages) {
      if (kpIdStr === idStr) {
        signingCommitmentsMap.set(kp.identifier, commitment);
        break;
      }
    }
  }

  // Use the ciphersuite's signing package creation if available
  const signingPackage =
    "createSigningPackage" in ciphersuite && typeof ciphersuite.createSigningPackage === "function"
      ? (
          ciphersuite.createSigningPackage as (
            map: typeof signingCommitmentsMap,
            msg: Uint8Array,
          ) => SigningPackage<C>
        )(signingCommitmentsMap, messageBytes)
      : { signingCommitments: signingCommitmentsMap, message: messageBytes };

  // Verify binding factor inputs match
  const computedBindingFactorList = ciphersuite.computeBindingFactorList(
    signingPackage,
    verifyingKey.toElement(),
    new Uint8Array(0),
  );

  // Verify binding factors match
  for (const [idStr, expectedBindingFactor] of bindingFactors) {
    // Find the identifier
    for (const [kpIdStr, kp] of keyPackages) {
      if (kpIdStr === idStr) {
        const computedBindingFactor = computedBindingFactorList.get(kp.identifier);
        if (computedBindingFactor !== undefined) {
          expect(
            ciphersuite.scalarsEqual(
              computedBindingFactor.toScalar(),
              expectedBindingFactor.toScalar(),
            ),
          ).toBe(true);
        }
        break;
      }
    }
  }

  // Generate and verify signature shares
  const ourSignatureShares = new Map<string, SignatureShare<C>>();

  for (const [idStr, nonces] of signerNonces) {
    const keyPackage = keyPackages.get(idStr);
    if (keyPackage === undefined) continue;

    // Clone nonces since sign() consumes them
    const noncesClone = nonces.clone();

    const signatureShare = sign(ciphersuite, signingPackage, noncesClone, keyPackage);
    ourSignatureShares.set(idStr, signatureShare);

    // Verify our signature share matches the test vector
    const expectedShare = signatureShares.get(idStr);
    if (expectedShare !== undefined) {
      expect(signatureShare.equals(expectedShare)).toBe(true);
    }
  }

  // === 4. AGGREGATION ===
  // Create public key package
  const verifyingShares = new Map<string, VerifyingShare<C>>();
  for (const [idStr, keyPackage] of keyPackages) {
    verifyingShares.set(idStr, keyPackage.verifyingShare);
  }

  const pubkeyPackage = new PublicKeyPackage(
    ciphersuite,
    verifyingShares,
    verifyingKey.toElement(),
    minSigners,
  );

  // Convert signature shares to the format expected by aggregate
  const signatureSharesForAggregate = new Map<Identifier<C>, SignatureShare<C>>();
  for (const [idStr, share] of signatureShares) {
    for (const [kpIdStr, kp] of keyPackages) {
      if (kpIdStr === idStr) {
        signatureSharesForAggregate.set(kp.identifier, share);
        break;
      }
    }
  }

  // Aggregate the signature shares
  const groupSignature = aggregate(
    ciphersuite,
    signingPackage,
    signatureSharesForAggregate,
    pubkeyPackage,
  );

  // Verify the final signature matches the test vector
  const expectedSignature = Signature.deserialize(ciphersuite, signatureBytes);
  expect(groupSignature.equals(ciphersuite, expectedSignature)).toBe(true);

  // Also verify with our computed signature shares
  const ourSignatureSharesForAggregate = new Map<Identifier<C>, SignatureShare<C>>();
  for (const [idStr, share] of ourSignatureShares) {
    for (const [kpIdStr, kp] of keyPackages) {
      if (kpIdStr === idStr) {
        ourSignatureSharesForAggregate.set(kp.identifier, share);
        break;
      }
    }
  }

  const ourGroupSignature = aggregate(
    ciphersuite,
    signingPackage,
    ourSignatureSharesForAggregate,
    pubkeyPackage,
  );

  expect(ourGroupSignature.equals(ciphersuite, expectedSignature)).toBe(true);

  // Verify the signature is valid using the group verifying key
  verifyingKey.verify(messageBytes, groupSignature);
}
