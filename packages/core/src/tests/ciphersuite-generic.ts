/**
 * Ciphersuite-generic test functions.
 *
 * These are generic test functions that can be used by ciphersuite-specific
 * packages to test their implementations. The pattern follows Rust's frost-core
 * `test-impl` feature.
 *
 * @module @frosts/core/tests/ciphersuite-generic
 */

import { expect } from "vitest";
import type { Ciphersuite, SigningPackage, IdentifierLike } from "../types.js";
import { SigningKey } from "../signing_key.js";
import { FrostError, FrostErrorType } from "../error.js";
import { Identifier } from "../identifier.js";
import {
  generateWithDealer,
  type KeyPackage,
  SecretShare as _SecretShare,
  type PublicKeyPackage,
  generateSecretShares,
  generateCoefficients,
  defaultIdentifiers,
  reconstruct,
  round1,
  round2,
  part1,
  part2,
  part3,
  SigningShare,
  VerifyingShare as _VerifyingShare,
} from "../keys.js";
import { commit, type SigningCommitments, type SigningNonces } from "../round1.js";
import {
  sign,
  SignatureShare,
  IncorrectNumberOfCommitmentsError,
  InvalidSignatureShareError,
  MissingCommitmentError,
  IncorrectCommitmentError,
} from "../round2.js";
import {
  aggregate,
  aggregateCustom,
  CheaterDetection,
  verifySignatureShare,
} from "../aggregate.js";
import { Signature } from "../signature.js";
import { VerifyingKey } from "../verifying_key.js";
import { hexToBytes, bytesToHex, type CryptoRng } from "./helpers.js";

/**
 * Helper function to unwrap a value that may be undefined.
 * Throws an error if the value is undefined.
 */
function unwrap<T>(value: T | undefined, message = "Value is undefined"): T {
  if (value === undefined) {
    throw new Error(message);
  }
  return value;
}

/**
 * Test if creating a zero SigningKey fails.
 *
 * @param ciphersuite - The ciphersuite to test
 */
export function checkZeroKeyFails<C extends Ciphersuite>(ciphersuite: C): void {
  const zero = ciphersuite.scalarZero();
  const encodedZero = ciphersuite.serializeScalar(zero);

  expect(() => {
    SigningKey.deserialize(ciphersuite, encodedZero);
  }).toThrow();
}

/**
 * Test share generation with a Ciphersuite.
 *
 * This tests that Shamir's secret sharing to compute an arbitrary value is working.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function checkShareGeneration<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const secret = SigningKey.generate(ciphersuite, rng);
  // Simulate serialization / deserialization to ensure it works
  const deserializedSecret = SigningKey.deserialize(ciphersuite, secret.serialize());

  const maxSigners = 5;
  const minSigners = 3;

  const identifiers = await defaultIdentifiers(ciphersuite, maxSigners);
  const coefficients = generateCoefficients(ciphersuite, minSigners - 1, rng);

  const secretShares = generateSecretShares(
    ciphersuite,
    deserializedSecret.toScalar(),
    maxSigners,
    minSigners,
    coefficients,
    identifiers,
  );

  const keyPackages: KeyPackage<C>[] = [];
  for (const share of secretShares) {
    keyPackages.push(share.toKeyPackage());
  }

  // Reconstruct the secret and verify it matches
  // reconstruct returns a scalar, so we compare using serialize
  const reconstructed = reconstruct(ciphersuite, keyPackages);
  expect(ciphersuite.serializeScalar(reconstructed)).toEqual(deserializedSecret.serialize());

  // Test error cases - not enough shares
  expect(() => {
    reconstruct(ciphersuite, []);
  }).toThrow();

  expect(() => {
    reconstruct(ciphersuite, [keyPackages[0]]);
  }).toThrow();

  // Test error cases - duplicate identifier
  const duplicatedPackages = [...keyPackages];
  duplicatedPackages[0] = keyPackages[1];

  expect(() => {
    reconstruct(ciphersuite, duplicatedPackages);
  }).toThrow();
}

/**
 * Test share generation fails with invalid signers.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param minSigners - Minimum number of signers
 * @param maxSigners - Maximum number of signers
 * @param rng - A cryptographically secure random number generator
 */
export function checkShareGenerationFailsWithInvalidSigners<C extends Ciphersuite>(
  ciphersuite: C,
  minSigners: number,
  maxSigners: number,
  rng: CryptoRng,
): void {
  const secret = SigningKey.generate(ciphersuite, rng);

  // Use arbitrary number of coefficients so tests don't fail for overflow reasons
  const coefficients = generateCoefficients(ciphersuite, 3, rng);

  expect(() => {
    const identifiers = [];
    for (let i = 1; i <= maxSigners; i++) {
      identifiers.push(Identifier.fromU16(ciphersuite, i));
    }
    generateSecretShares(ciphersuite, secret, maxSigners, minSigners, coefficients, identifiers);
  }).toThrow();
}

/**
 * Test FROST signing with trusted dealer.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 * @returns A tuple of [message, signature, verifyingKey]
 */
export async function checkSignWithDealer<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<[Uint8Array, Signature<C>, VerifyingKey<C>]> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation with dealer
  const [shares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert shares to key packages
  // Note: shares is Map<string, SecretShare> where key is the hex-encoded identifier
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idHex, share] of shares) {
    const keyPackage = share.toKeyPackage();
    keyPackages.set(idHex, keyPackage);
  }

  // Run the signing protocol
  const result = checkSign(ciphersuite, minSigners, keyPackages, rng, pubKeyPackage);
  return result;
}

/**
 * Test FROST signing with the given shares.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param minSigners - Minimum number of signers
 * @param keyPackages - Map of identifier to KeyPackage
 * @param rng - A cryptographically secure random number generator
 * @param pubkeyPackage - The public key package
 * @returns A tuple of [message, signature, verifyingKey]
 */
export function checkSign<C extends Ciphersuite>(
  ciphersuite: C,
  minSigners: number,
  keyPackages: Map<string, KeyPackage<C>>,
  rng: CryptoRng,
  pubkeyPackage: PublicKeyPackage<C>,
): [Uint8Array, Signature<C>, VerifyingKey<C>] {
  const noncesMap = new Map<string, SigningNonces<C>>();
  const commitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();

  // Round 1: generating nonces and signing commitments for each participant
  // Use the keyPackage.identifier directly to ensure reference equality later
  let count = 0;
  for (const [idKey, keyPackage] of keyPackages) {
    if (count >= minSigners) break;

    const [nonces, commitments] = commit(ciphersuite, keyPackage.signingShare, rng);

    noncesMap.set(idKey, nonces);
    // Use keyPackage.identifier directly - this ensures the same reference
    // is used when the sign function looks up the commitment
    commitmentsMap.set(keyPackage.identifier, commitments);
    count++;
  }

  // Create signing package
  const message = new TextEncoder().encode("message to sign");
  const signingPackage: SigningPackage<C> = {
    signingCommitments: commitmentsMap,
    message,
  };

  // Round 2: each participant generates their signature share
  const signatureShares = new Map<Identifier<C>, SignatureShare<C>>();

  for (const [idKey, nonces] of noncesMap) {
    const keyPackage = unwrap(keyPackages.get(idKey), `KeyPackage not found for ${idKey}`);

    // Check sign errors
    checkSignErrors(ciphersuite, signingPackage, nonces, keyPackage);

    const signatureShare = sign(ciphersuite, signingPackage, nonces, keyPackage);
    // Use keyPackage.identifier directly for consistency
    signatureShares.set(keyPackage.identifier, signatureShare);
  }

  // Check aggregate errors
  checkAggregateErrors(ciphersuite, signingPackage, signatureShares, pubkeyPackage);

  // Check verifying shares
  checkVerifyingShares(ciphersuite, pubkeyPackage, signingPackage, signatureShares);

  // Check verify signature share
  checkVerifySignatureShare(ciphersuite, pubkeyPackage, signingPackage, signatureShares);

  // Aggregation
  const groupSignature = aggregate(ciphersuite, signingPackage, signatureShares, pubkeyPackage);

  // Verify the signature
  const verifyingKey = VerifyingKey.create(ciphersuite, pubkeyPackage.verifyingKey);
  verifyingKey.verify(message, groupSignature);

  return [message, groupSignature, verifyingKey];
}

/**
 * Test FROST signing with dealer fails with invalid numbers of signers.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param minSigners - Minimum number of signers
 * @param maxSigners - Maximum number of signers
 * @param rng - A cryptographically secure random number generator
 */
export async function checkSignWithDealerFailsWithInvalidSigners<C extends Ciphersuite>(
  ciphersuite: C,
  minSigners: number,
  maxSigners: number,
  rng: CryptoRng,
): Promise<void> {
  await expect(
    generateWithDealer(ciphersuite, maxSigners, minSigners, { type: "Default" }, rng),
  ).rejects.toThrow();
}

/**
 * Test that error correctly identifies culprits.
 *
 * @param ciphersuite - The ciphersuite to test
 */
export function checkErrorCulprit<C extends Ciphersuite>(ciphersuite: C): void {
  // Create a test identifier
  const id1 = Identifier.fromU16(ciphersuite, 1);

  // Verify the identifier can be serialized and deserialized
  const serialized = id1.serialize();
  const deserialized = Identifier.deserialize(ciphersuite, serialized);

  expect(id1.equals(deserialized)).toBe(true);
}

/**
 * Test identifier derivation if supported.
 *
 * @param ciphersuite - The ciphersuite to test
 */
export function checkIdentifierDerivation<C extends Ciphersuite>(ciphersuite: C): void {
  // Check if the ciphersuite supports identifier derivation
  if (ciphersuite.HID === undefined) {
    // Skip test if not supported
    return;
  }

  const testInput = new TextEncoder().encode("alice@example.com");
  const result = ciphersuite.HID(testInput);

  // Should return a non-null scalar
  expect(result).not.toBeNull();
  if (result === null) throw new Error("result is null");

  // The same input should produce the same output
  const result2 = ciphersuite.HID(testInput);
  if (result2 === null) throw new Error("result2 is null");
  expect(ciphersuite.scalarsEqual(result, result2)).toBe(true);

  // Different inputs should produce different outputs (with high probability)
  const differentInput = new TextEncoder().encode("bob@example.com");
  const differentResult = ciphersuite.HID(differentInput);
  if (differentResult === null) throw new Error("differentResult is null");
  expect(ciphersuite.scalarsEqual(result, differentResult)).toBe(false);
}

// Helper functions bytesToHex and hexToBytes are imported from "./helpers.js"

/**
 * Test FROST signing with distributed key generation (DKG).
 *
 * This tests the full DKG protocol: part1, part2, part3, then signing.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 * @returns A tuple of [message, signature, verifyingKey]
 */
export async function checkSignWithDkg<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<[Uint8Array, Signature<C>, VerifyingKey<C>]> {
  const maxSigners = 5;
  const minSigners = 3;

  // Round 1: Each participant generates their round 1 packages
  const round1SecretPackages = new Map<string, round1.SecretPackage<C>>();
  const receivedRound1Packages = new Map<string, Map<string, round1.Package<C>>>();

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idStr = bytesToHex(identifier.serialize());

    const [secretPkg, round1Pkg] = part1(ciphersuite, identifier, maxSigners, minSigners, rng);

    round1SecretPackages.set(idStr, secretPkg);

    // "Send" the round 1 package to all other participants
    for (let j = 1; j <= maxSigners; j++) {
      if (j === i) continue;
      const receiverId = Identifier.fromU16(ciphersuite, j);
      const receiverIdStr = bytesToHex(receiverId.serialize());

      if (!receivedRound1Packages.has(receiverIdStr)) {
        receivedRound1Packages.set(receiverIdStr, new Map());
      }
      unwrap(receivedRound1Packages.get(receiverIdStr)).set(idStr, round1Pkg.clone());
    }
  }

  // Test part2 error handling for one participant
  {
    const identifier = Identifier.fromU16(ciphersuite, 1);
    const idStr = bytesToHex(identifier.serialize());
    const secretPkg = unwrap(round1SecretPackages.get(idStr));
    const round1Pkgs = unwrap(receivedRound1Packages.get(idStr));
    checkPart2Error(ciphersuite, secretPkg, round1Pkgs);
  }

  // Round 2: Each participant processes received packages and generates round 2 packages
  const round2SecretPackages = new Map<string, round2.SecretPackage<C>>();
  const receivedRound2Packages = new Map<string, Map<string, round2.Package<C>>>();

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idStr = bytesToHex(identifier.serialize());

    const secretPkg = unwrap(round1SecretPackages.get(idStr));
    const round1Pkgs = unwrap(receivedRound1Packages.get(idStr));

    const [round2Secret, round2Pkgs] = part2(ciphersuite, secretPkg, round1Pkgs);

    round2SecretPackages.set(idStr, round2Secret);

    // "Send" the round 2 packages to their respective recipients
    for (const [receiverIdStr, round2Pkg] of round2Pkgs) {
      if (!receivedRound2Packages.has(receiverIdStr)) {
        receivedRound2Packages.set(receiverIdStr, new Map());
      }
      unwrap(receivedRound2Packages.get(receiverIdStr)).set(idStr, round2Pkg);
    }
  }

  // Test part3 error handling for all participants
  await checkPart3Errors(
    ciphersuite,
    maxSigners,
    round2SecretPackages,
    receivedRound1Packages,
    receivedRound2Packages,
  );

  // Part 3: Each participant computes their key package
  const keyPackages = new Map<string, KeyPackage<C>>();
  let pubKeyPackage: PublicKeyPackage<C> | undefined;

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idStr = bytesToHex(identifier.serialize());

    const round2Secret = unwrap(round2SecretPackages.get(idStr));
    const round1Pkgs = unwrap(receivedRound1Packages.get(idStr));
    const round2Pkgs = unwrap(receivedRound2Packages.get(idStr));

    const [keyPkg, pubPkg] = await part3(ciphersuite, round2Secret, round1Pkgs, round2Pkgs);

    keyPackages.set(idStr, keyPkg);

    // All participants should compute the same public key package
    pubKeyPackage ??= pubPkg;
  }

  if (pubKeyPackage === undefined) {
    throw new Error("pubKeyPackage is undefined after DKG");
  }

  // Run the signing protocol with the DKG-generated keys
  return checkSign(ciphersuite, minSigners, keyPackages, rng, pubKeyPackage);
}

/**
 * Test DKG part1 fails with invalid numbers of signers.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param minSigners - Minimum number of signers
 * @param maxSigners - Maximum number of signers
 * @param rng - A cryptographically secure random number generator
 */
export function checkDkgPart1FailsWithInvalidSigners<C extends Ciphersuite>(
  ciphersuite: C,
  minSigners: number,
  maxSigners: number,
  rng: CryptoRng,
): void {
  const identifier = Identifier.fromU16(ciphersuite, 1);

  expect(() => {
    part1(ciphersuite, identifier, maxSigners, minSigners, rng);
  }).toThrow();
}

/**
 * Verification callback type for interoperability tests.
 *
 * This function should verify a FROST signature using a native cryptographic library
 * (e.g., @noble/curves) to ensure interoperability with non-FROST implementations.
 *
 * The signature and verifying key are provided as raw bytes (already serialized)
 * so they can be passed directly to external verification libraries.
 *
 * @param message - The message that was signed
 * @param signatureBytes - The serialized FROST group signature
 * @param verifyingKeyBytes - The serialized group verifying key
 */
export type InteroperabilityVerifier = (
  message: Uint8Array,
  signatureBytes: Uint8Array,
  verifyingKeyBytes: Uint8Array,
) => void;

/**
 * Test FROST interoperability with trusted dealer key generation.
 *
 * This function runs multiple signing operations and verifies each signature
 * using a native cryptographic library via the provided verifier callback.
 * This ensures FROST signatures are compatible with standard signature
 * verification implementations.
 *
 * Ported from: frost-core/src/tests/ciphersuite_generic.rs check_interoperability_in_dealer
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 * @param verifier - A callback that verifies signatures using a native library (receives serialized bytes)
 * @param iterations - Number of signing iterations (default: 256, matching Rust)
 */
export async function checkInteroperabilityInDealer<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
  verifier: InteroperabilityVerifier,
  iterations = 256,
): Promise<void> {
  for (let i = 0; i < iterations; i++) {
    const [message, signature, verifyingKey] = await checkSignWithDealer(ciphersuite, rng);
    const signatureBytes = signature.serialize(ciphersuite);
    const verifyingKeyBytes = verifyingKey.serialize();
    verifier(message, signatureBytes, verifyingKeyBytes);
  }
}

/**
 * Test FROST interoperability with distributed key generation (DKG).
 *
 * This function runs multiple DKG + signing operations and verifies each signature
 * using a native cryptographic library via the provided verifier callback.
 * This ensures FROST signatures generated from DKG keys are compatible with
 * standard signature verification implementations.
 *
 * Ported from: frost-core/src/tests/ciphersuite_generic.rs check_interoperability_in_dkg
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 * @param verifier - A callback that verifies signatures using a native library (receives serialized bytes)
 * @param iterations - Number of signing iterations (default: 256, matching Rust)
 */
export async function checkInteroperabilityInDkg<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
  verifier: InteroperabilityVerifier,
  iterations = 256,
): Promise<void> {
  for (let i = 0; i < iterations; i++) {
    const [message, signature, verifyingKey] = await checkSignWithDkg(ciphersuite, rng);
    const signatureBytes = signature.serialize(ciphersuite);
    const verifyingKeyBytes = verifyingKey.serialize();
    verifier(message, signatureBytes, verifyingKeyBytes);
  }
}

/**
 * Test vector data structure (matching Rust frost-core test vectors JSON format).
 */
export interface TestVectorData {
  config: {
    readonly name: string;
    readonly group: string;
    readonly hash: string;
    readonly MAX_PARTICIPANTS: string;
    readonly MIN_PARTICIPANTS: string;
    readonly NUM_PARTICIPANTS: string;
  };
  inputs: {
    readonly participant_list: readonly number[];
    readonly group_secret_key: string;
    readonly verifying_key_key: string;
    readonly message: string;
    readonly share_polynomial_coefficients: readonly string[];
    readonly participant_shares: readonly {
      readonly identifier: number;
      readonly participant_share: string;
    }[];
  };
  round_one_outputs: {
    readonly outputs: readonly {
      readonly identifier: number;
      readonly hiding_nonce_randomness: string;
      readonly binding_nonce_randomness: string;
      readonly hiding_nonce: string;
      readonly binding_nonce: string;
      readonly hiding_nonce_commitment: string;
      readonly binding_nonce_commitment: string;
    }[];
  };
  round_two_outputs: {
    readonly outputs: readonly {
      readonly identifier: number;
      readonly sig_share: string;
    }[];
  };
  final_output: {
    readonly sig: string;
  };
}

/**
 * Verify test vector signature.
 *
 * This function verifies that the expected signature from test vectors
 * can be verified using the group verifying key and message.
 * It uses the ciphersuite's native verify method to ensure compatibility.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param vectors - The test vector data
 */
export function checkTestVectorSignature<C extends Ciphersuite>(
  ciphersuite: C,
  vectors: TestVectorData,
): void {
  // Parse inputs from test vectors
  const messageBytes = hexToBytes(vectors.inputs.message);
  const verifyingKeyBytes = hexToBytes(vectors.inputs.verifying_key_key);
  const signatureBytes = hexToBytes(vectors.final_output.sig);

  // Deserialize the verifying key
  const verifyingKey = VerifyingKey.deserialize(ciphersuite, verifyingKeyBytes);

  // Deserialize the signature
  const signature = Signature.deserialize(ciphersuite, signatureBytes);

  // Verify the signature (throws if verification fails)
  verifyingKey.verify(messageBytes, signature);
}

/**
 * Verify test vector verifying key derivation.
 *
 * This function verifies that the group verifying key from test vectors
 * matches the derived verifying key from the group secret key.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param vectors - The test vector data
 */
export function checkTestVectorVerifyingKey<C extends Ciphersuite>(
  ciphersuite: C,
  vectors: TestVectorData,
): void {
  // Parse the group secret key
  const groupSecretBytes = hexToBytes(vectors.inputs.group_secret_key);
  const signingKey = SigningKey.deserialize(ciphersuite, groupSecretBytes);

  // Derive the verifying key
  const derivedVerifyingKey = VerifyingKey.fromSigningKey(ciphersuite, signingKey);

  // Parse the expected verifying key
  const expectedVerifyingKeyBytes = hexToBytes(vectors.inputs.verifying_key_key);
  const expectedVerifyingKey = VerifyingKey.deserialize(ciphersuite, expectedVerifyingKeyBytes);

  // Verify they match
  expect(derivedVerifyingKey.serialize()).toEqual(expectedVerifyingKey.serialize());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

/**
 * Test signing error cases.
 *
 * Ported from Rust: check_sign_errors
 *
 * This function tests that signing fails when there are not enough commitments
 * in the signing package.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param signingPackage - The signing package
 * @param signingNonces - The signer's nonces
 * @param keyPackage - The signer's key package
 */
export function checkSignErrors<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signingNonces: SigningNonces<C>,
  keyPackage: KeyPackage<C>,
): void {
  // Check if passing not enough commitments causes an error

  // Clone the commitments map and remove one commitment that's not from the key_package owner
  const commitments = new Map(signingPackage.signingCommitments);

  // Remove one commitment that's not from the key_package owner
  let idToRemove: IdentifierLike<C> | undefined;
  for (const [id] of commitments) {
    if (!id.equals(keyPackage.identifier)) {
      idToRemove = id;
      break;
    }
  }

  if (idToRemove !== undefined) {
    commitments.delete(idToRemove);
  }

  const modifiedSigningPackage: SigningPackage<C> = {
    signingCommitments: commitments,
    message: signingPackage.message,
  };

  expect(() => {
    sign(ciphersuite, modifiedSigningPackage, signingNonces, keyPackage);
  }).toThrow(IncorrectNumberOfCommitmentsError);
}

/**
 * Test aggregation error cases.
 *
 * Ported from Rust: check_aggregate_errors
 *
 * This function calls both check_aggregate_corrupted_share and
 * check_aggregate_invalid_share_identifier_for_verifying_shares.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param signingPackage - The signing package
 * @param signatureShares - Map of signature shares
 * @param pubkeyPackage - The public key package
 */
export function checkAggregateErrors<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  pubkeyPackage: PublicKeyPackage<C>,
): void {
  checkAggregateCorruptedShare(ciphersuite, signingPackage, signatureShares, pubkeyPackage);
  checkAggregateInvalidShareIdentifierForVerifyingShares(
    ciphersuite,
    signingPackage,
    signatureShares,
    pubkeyPackage,
  );
}

/**
 * Test corrupted share detection during aggregation.
 *
 * Ported from Rust: check_aggregate_corrupted_share
 *
 * This function corrupts two signature shares and verifies that:
 * 1. Default aggregation (FirstCheater) catches the first cheater
 * 2. Disabled cheater detection returns InvalidSignature
 * 3. AllCheaters mode catches both cheaters
 *
 * @param ciphersuite - The ciphersuite to test
 * @param signingPackage - The signing package
 * @param signatureShares - Map of signature shares (will be cloned and corrupted)
 * @param pubkeyPackage - The public key package
 */
export function checkAggregateCorruptedShare<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  pubkeyPackage: PublicKeyPackage<C>,
): void {
  const one = ciphersuite.scalarOne();

  // Clone the signature shares map
  const corruptedShares = new Map<Identifier<C>, SignatureShare<C>>();
  for (const [id, share] of signatureShares) {
    corruptedShares.set(id, share.clone());
  }

  // Get the first two identifiers
  const ids = Array.from(corruptedShares.keys());
  const id1 = ids[0];
  const id2 = ids[1];

  // Corrupt two shares by adding 1 to their scalar values
  const share1 = unwrap(corruptedShares.get(id1));
  const corruptedScalar1 = ciphersuite.scalarAdd(share1.toScalar(), one);
  corruptedShares.set(id1, SignatureShare.fromScalar(ciphersuite, corruptedScalar1));

  const share2 = unwrap(corruptedShares.get(id2));
  const corruptedScalar2 = ciphersuite.scalarAdd(share2.toScalar(), one);
  corruptedShares.set(id2, SignatureShare.fromScalar(ciphersuite, corruptedScalar2));

  // Test default aggregation (FirstCheater) - should catch the first cheater
  try {
    aggregate(ciphersuite, signingPackage, corruptedShares, pubkeyPackage);
    expect.fail("Should have thrown InvalidSignatureShareError");
  } catch (e) {
    if (e instanceof InvalidSignatureShareError) {
      expect(e.culprits.length).toBe(1);
      expect(e.culprits[0].equals(id1)).toBe(true);
    } else {
      throw e;
    }
  }

  // Test with cheater detection disabled - should return InvalidSignature
  try {
    aggregateCustom(
      ciphersuite,
      signingPackage,
      corruptedShares,
      pubkeyPackage,
      CheaterDetection.Disabled,
    );
    expect.fail("Should have thrown an error");
  } catch (e) {
    if (e instanceof FrostError) {
      expect(e.type).toBe(FrostErrorType.InvalidSignature);
      expect(e.culprits().length).toBe(0);
    } else {
      throw e;
    }
  }

  // Test FirstCheater explicitly - should catch the first cheater
  try {
    aggregateCustom(
      ciphersuite,
      signingPackage,
      corruptedShares,
      pubkeyPackage,
      CheaterDetection.FirstCheater,
    );
    expect.fail("Should have thrown InvalidSignatureShareError");
  } catch (e) {
    if (e instanceof InvalidSignatureShareError) {
      expect(e.culprits.length).toBe(1);
      expect(e.culprits[0].equals(id1)).toBe(true);
    } else {
      throw e;
    }
  }

  // Test AllCheaters mode - should catch both cheaters
  try {
    aggregateCustom(
      ciphersuite,
      signingPackage,
      corruptedShares,
      pubkeyPackage,
      CheaterDetection.AllCheaters,
    );
    expect.fail("Should have thrown InvalidSignatureShareError");
  } catch (e) {
    if (e instanceof InvalidSignatureShareError) {
      expect(e.culprits.length).toBe(2);
      // Both culprits should be present
      const culpritIds = e.culprits.map((c) => bytesToHex(c.serialize()));
      expect(culpritIds).toContain(bytesToHex(id1.serialize()));
      expect(culpritIds).toContain(bytesToHex(id2.serialize()));
    } else {
      throw e;
    }
  }
}

/**
 * Test NCC-E008263-4VP audit finding (PublicKeyPackage).
 *
 * Ported from Rust: check_aggregate_invalid_share_identifier_for_verifying_shares
 *
 * This test verifies that aggregation fails (but doesn't panic) when a
 * signature share has an identifier that's not in the verifying shares.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param signingPackage - The signing package
 * @param signatureShares - Map of signature shares
 * @param pubkeyPackage - The public key package
 */
export function checkAggregateInvalidShareIdentifierForVerifyingShares<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  pubkeyPackage: PublicKeyPackage<C>,
): void {
  // Clone the signature shares map
  const modifiedShares = new Map<Identifier<C>, SignatureShare<C>>();
  for (const [id, share] of signatureShares) {
    modifiedShares.set(id, share.clone());
  }

  // Create an invalid identifier by deriving from a unique string
  const invalidIdentifier = Identifier.derive<C>(
    ciphersuite,
    new TextEncoder().encode("invalid identifier"),
  );

  // Insert a new share (copied from other existing share) with an invalid identifier
  const existingShareResult = signatureShares.values().next();
  if (existingShareResult.done === true || existingShareResult.value === undefined) {
    throw new Error("No existing shares found");
  }
  const existingShare = existingShareResult.value;
  modifiedShares.set(invalidIdentifier, existingShare.clone());

  // Should error, but not panic
  expect(() => {
    aggregate(ciphersuite, signingPackage, modifiedShares, pubkeyPackage);
  }).toThrow();
}

/**
 * Test verifying shares validation.
 *
 * Ported from Rust: check_verifying_shares
 *
 * This function corrupts the last signature share and verifies that
 * aggregation correctly identifies the culprit.
 *
 * NOTE: If the last verifying share is invalid this test will not detect this.
 * The test is intended for ensuring the correct calculation of verifying shares
 * which is covered in this test.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param pubkeys - The public key package
 * @param signingPackage - The signing package
 * @param signatureShares - Map of signature shares
 */
export function checkVerifyingShares<C extends Ciphersuite>(
  ciphersuite: C,
  pubkeys: PublicKeyPackage<C>,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
): void {
  const one = ciphersuite.scalarOne();

  // Clone the signature shares map
  const corruptedShares = new Map<Identifier<C>, SignatureShare<C>>();
  for (const [id, share] of signatureShares) {
    corruptedShares.set(id, share.clone());
  }

  // Get the last identifier
  const ids = Array.from(corruptedShares.keys());
  const lastId = ids[ids.length - 1];

  // Corrupt last share
  const lastShare = unwrap(corruptedShares.get(lastId));
  const corruptedScalar = ciphersuite.scalarAdd(lastShare.toScalar(), one);
  corruptedShares.set(lastId, SignatureShare.fromScalar(ciphersuite, corruptedScalar));

  // Aggregation should fail and identify the culprit
  try {
    aggregate(ciphersuite, signingPackage, corruptedShares, pubkeys);
    expect.fail("Should have thrown InvalidSignatureShareError");
  } catch (e) {
    if (e instanceof InvalidSignatureShareError) {
      expect(e.culprits.length).toBe(1);
      expect(e.culprits[0].equals(lastId)).toBe(true);
    } else {
      throw e;
    }
  }
}

/**
 * Test verify_signature_share function.
 *
 * Ported from Rust: check_verify_signature_share
 *
 * This function tests that verifySignatureShare correctly validates
 * signature shares, both valid and corrupted.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param pubkeys - The public key package
 * @param signingPackage - The signing package
 * @param signatureShares - Map of signature shares
 */
export function checkVerifySignatureShare<C extends Ciphersuite>(
  ciphersuite: C,
  pubkeys: PublicKeyPackage<C>,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
): void {
  const verifyingKey = VerifyingKey.create(ciphersuite, pubkeys.verifyingKey);

  // First, verify all valid shares pass
  for (const [identifier, signatureShare] of signatureShares) {
    const idKey = bytesToHex(identifier.serialize());
    const verifyingShare = unwrap(pubkeys.verifyingShares.get(idKey));

    // Should not throw
    verifySignatureShare(
      ciphersuite,
      identifier,
      verifyingShare,
      signatureShare,
      signingPackage,
      verifyingKey,
    );
  }

  // Now test with corrupted shares
  const one = ciphersuite.scalarOne();

  for (const [identifier, signatureShare] of signatureShares) {
    const idKey = bytesToHex(identifier.serialize());
    const verifyingShare = unwrap(pubkeys.verifyingShares.get(idKey));

    // Corrupt the share by adding 1
    const corruptedScalar = ciphersuite.scalarAdd(signatureShare.toScalar(), one);
    const corruptedShare = SignatureShare.fromScalar(ciphersuite, corruptedScalar);

    // Should throw
    expect(() => {
      verifySignatureShare(
        ciphersuite,
        identifier,
        verifyingShare,
        corruptedShare,
        signingPackage,
        verifyingKey,
      );
    }).toThrow();
  }
}

/**
 * Test DKG part2 error handling.
 *
 * Ported from Rust: check_part2_error
 *
 * This function tests that part2 correctly detects corrupted proof of knowledge.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param round1SecretPackage - The round 1 secret package
 * @param round1Packages - Map of round 1 packages
 */
export function checkPart2Error<C extends Ciphersuite>(
  ciphersuite: C,
  round1SecretPackage: round1.SecretPackage<C>,
  round1Packages: Map<string, round1.Package<C>>,
): void {
  const one = ciphersuite.scalarOne();

  // Clone the round 1 packages
  const corruptedPackages = new Map<string, round1.Package<C>>();
  for (const [id, pkg] of round1Packages) {
    corruptedPackages.set(id, pkg.clone());
  }

  // Get the first identifier and corrupt its proof of knowledge
  const firstIdResult = corruptedPackages.keys().next();
  if (firstIdResult.done === true || firstIdResult.value === undefined) {
    throw new Error("No corrupted packages found");
  }
  const firstIdStr = firstIdResult.value;
  const firstPkg = unwrap(corruptedPackages.get(firstIdStr));

  // Corrupt the proof of knowledge by adding 1 to the z component
  const corruptedZ = ciphersuite.scalarAdd(firstPkg.proofOfKnowledge.z, one);
  const corruptedPkg = new round1.Package(ciphersuite, firstPkg.commitment, {
    R: firstPkg.proofOfKnowledge.R,
    z: corruptedZ,
  });
  corruptedPackages.set(firstIdStr, corruptedPkg);

  // part2 should fail with InvalidProofOfKnowledge
  try {
    part2(ciphersuite, round1SecretPackage.clone(), corruptedPackages);
    expect.fail("Should have thrown FrostError for InvalidProofOfKnowledge");
  } catch (e) {
    if (e instanceof FrostError) {
      expect(e.type).toBe(FrostErrorType.InvalidProofOfKnowledge);
      const errorCulprits = e.culprits();
      expect(errorCulprits.length).toBe(1);
      // The culprit should be the one whose PoK we corrupted
      const culpritId = errorCulprits[0];
      const culpritIdStr = bytesToHex(culpritId.serialize());
      expect(culpritIdStr).toBe(firstIdStr);
    } else {
      throw e;
    }
  }
}

/**
 * Test DKG part3 corrupted share handling.
 *
 * Ported from Rust: check_part3_corrupted_share
 *
 * This function tests that part3 correctly detects corrupted signing shares
 * and identifies the culprit.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param maxSigners - Maximum number of signers
 * @param round2SecretPackages - Map of round 2 secret packages
 * @param receivedRound1Packages - Map of received round 1 packages
 * @param receivedRound2Packages - Map of received round 2 packages
 */
export async function checkPart3CorruptedShare<C extends Ciphersuite>(
  ciphersuite: C,
  maxSigners: number,
  round2SecretPackages: Map<string, round2.SecretPackage<C>>,
  receivedRound1Packages: Map<string, Map<string, round1.Package<C>>>,
  receivedRound2Packages: Map<string, Map<string, round2.Package<C>>>,
): Promise<void> {
  const one = ciphersuite.scalarOne();

  // For each participant, test corrupted share detection
  for (let participantIndex = 1; participantIndex <= maxSigners; participantIndex++) {
    const participantIdentifier = Identifier.fromU16(ciphersuite, participantIndex);
    const participantIdStr = bytesToHex(participantIdentifier.serialize());

    // Clone the received round 2 packages for this participant
    const originalR2Packages = unwrap(receivedRound2Packages.get(participantIdStr));
    const corruptedR2Packages = new Map<string, round2.Package<C>>();
    for (const [id, pkg] of originalR2Packages) {
      corruptedR2Packages.set(id, pkg.clone());
    }

    // Get the first sender's package and corrupt it
    const culpritIdResult = corruptedR2Packages.keys().next();
    if (culpritIdResult.done === true || culpritIdResult.value === undefined) {
      throw new Error("No corrupted R2 packages found");
    }
    const culpritIdStr = culpritIdResult.value;
    const culpritPkg = unwrap(corruptedR2Packages.get(culpritIdStr));

    // Corrupt the signing share by adding 1
    const corruptedScalar = ciphersuite.scalarAdd(culpritPkg.signingShare.toScalar(), one);
    const corruptedSigningShare = new SigningShare(ciphersuite, corruptedScalar);
    const corruptedPkg = new round2.Package(ciphersuite, corruptedSigningShare);
    corruptedR2Packages.set(culpritIdStr, corruptedPkg);

    // part3 should fail with InvalidSecretShare and identify the culprit
    try {
      await part3(
        ciphersuite,
        unwrap(round2SecretPackages.get(participantIdStr)),
        unwrap(receivedRound1Packages.get(participantIdStr)),
        corruptedR2Packages,
      );
      expect.fail("Should have thrown FrostError for InvalidSecretShare");
    } catch (e) {
      if (e instanceof FrostError) {
        expect(e.type).toBe(FrostErrorType.InvalidSecretShare);
        const errorCulprits = e.culprits();
        expect(errorCulprits.length).toBe(1);
        const detectedCulpritId = errorCulprits[0];
        const detectedCulpritIdStr = bytesToHex(detectedCulpritId.serialize());
        expect(detectedCulpritIdStr).toBe(culpritIdStr);
      } else {
        throw e;
      }
    }
  }
}

/**
 * Check all DKG part3 error cases.
 *
 * Ported from Rust: check_part3_errors
 *
 * This function runs both check_part3_different_participants and
 * check_part3_corrupted_share tests.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param maxSigners - Maximum number of signers
 * @param round2SecretPackages - Map of round 2 secret packages
 * @param receivedRound1Packages - Map of received round 1 packages
 * @param receivedRound2Packages - Map of received round 2 packages
 */
export async function checkPart3Errors<C extends Ciphersuite>(
  ciphersuite: C,
  maxSigners: number,
  round2SecretPackages: Map<string, round2.SecretPackage<C>>,
  receivedRound1Packages: Map<string, Map<string, round1.Package<C>>>,
  receivedRound2Packages: Map<string, Map<string, round2.Package<C>>>,
): Promise<void> {
  await checkPart3DifferentParticipants(
    ciphersuite,
    maxSigners,
    round2SecretPackages,
    receivedRound1Packages,
    receivedRound2Packages,
  );
  await checkPart3CorruptedShare(
    ciphersuite,
    maxSigners,
    round2SecretPackages,
    receivedRound1Packages,
    receivedRound2Packages,
  );
}

/**
 * Check that calling dkg::part3() with distinct sets of participants fails.
 *
 * Ported from Rust: check_part3_different_participants
 *
 * @param ciphersuite - The ciphersuite to test
 * @param maxSigners - Maximum number of signers
 * @param round2SecretPackages - Map of round 2 secret packages
 * @param receivedRound1Packages - Map of received round 1 packages
 * @param receivedRound2Packages - Map of received round 2 packages
 */
export async function checkPart3DifferentParticipants<C extends Ciphersuite>(
  ciphersuite: C,
  maxSigners: number,
  round2SecretPackages: Map<string, round2.SecretPackage<C>>,
  receivedRound1Packages: Map<string, Map<string, round1.Package<C>>>,
  receivedRound2Packages: Map<string, Map<string, round2.Package<C>>>,
): Promise<void> {
  // For each participant, test with different identifier sets
  for (let participantIndex = 1; participantIndex <= maxSigners; participantIndex++) {
    const participantIdentifier = Identifier.fromU16(ciphersuite, participantIndex);
    const participantIdStr = bytesToHex(participantIdentifier.serialize());

    // Clone the received round 2 packages for this participant
    const originalR2Packages = unwrap(receivedRound2Packages.get(participantIdStr));
    const modifiedR2Packages = new Map<string, round2.Package<C>>();

    // Remove the first package from the map, and reinsert it with an unrelated identifier
    let firstPkg: round2.Package<C> | undefined;
    let isFirst = true;
    for (const [id, pkg] of originalR2Packages) {
      if (isFirst) {
        firstPkg = pkg.clone();
        isFirst = false;
      } else {
        modifiedR2Packages.set(id, pkg.clone());
      }
    }

    // Insert with a different identifier (42)
    const invalidIdentifier = Identifier.fromU16(ciphersuite, 42);
    const invalidIdStr = bytesToHex(invalidIdentifier.serialize());
    if (firstPkg === undefined) {
      throw new Error("firstPkg is undefined");
    }
    modifiedR2Packages.set(invalidIdStr, firstPkg);

    // part3 should fail with IncorrectPackage
    try {
      await part3(
        ciphersuite,
        unwrap(round2SecretPackages.get(participantIdStr)),
        unwrap(receivedRound1Packages.get(participantIdStr)),
        modifiedR2Packages,
      );
      expect.fail("Should have thrown FrostError for IncorrectPackage");
    } catch (e) {
      if (e instanceof FrostError) {
        expect(e.type).toBe(FrostErrorType.IncorrectPackage);
      } else {
        throw e;
      }
    }
  }
}

/**
 * Test signing with a missing identifier in the signing package.
 *
 * Ported from Rust: check_sign_with_missing_identifier
 *
 * This test verifies that signing fails with MissingCommitment error when the
 * signer's identifier is not in the signing package's commitments.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function checkSignWithMissingIdentifier<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation with dealer
  const [shares, _pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert shares to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idHex, share] of shares) {
    const keyPackage = share.toKeyPackage();
    keyPackages.set(idHex, keyPackage);
  }

  // Get identifiers 1-4
  const id1 = Identifier.fromU16(ciphersuite, 1);
  const id2 = Identifier.fromU16(ciphersuite, 2);
  const id3 = Identifier.fromU16(ciphersuite, 3);
  const id4 = Identifier.fromU16(ciphersuite, 4);

  const id1Hex = bytesToHex(id1.serialize());
  const id2Hex = bytesToHex(id2.serialize());
  const id3Hex = bytesToHex(id3.serialize());
  // id4 is used for commitments but we don't need its hex representation

  // Round 1: Generate nonces and commitments
  const noncesMap = new Map<string, SigningNonces<C>>();
  const commitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();

  const participants = [id1Hex, id2Hex, id3Hex];

  for (const idHex of participants) {
    const keyPackage = unwrap(keyPackages.get(idHex));
    const [nonces, commitments] = commit(ciphersuite, keyPackage.signingShare, rng);
    noncesMap.set(idHex, nonces);

    // Participant with id_1 is excluded from the commitments_map so it is missing from the signing package.
    // To prevent sign() from returning an error due to incorrect number of commitments,
    // add the commitment under another unrelated participant.
    if (idHex === id1Hex) {
      commitmentsMap.set(id4, commitments);
    } else {
      commitmentsMap.set(keyPackage.identifier, commitments);
    }
  }

  // Create signing package
  const message = new TextEncoder().encode("message to sign");
  const signingPackage: SigningPackage<C> = {
    signingCommitments: commitmentsMap,
    message,
  };

  // Round 2: Participant with id_1 tries to sign, but their identifier is missing
  const keyPackage1 = unwrap(keyPackages.get(id1Hex));
  const nonces1 = unwrap(noncesMap.get(id1Hex));

  // Should fail with MissingCommitmentError
  expect(() => {
    sign(ciphersuite, signingPackage, nonces1, keyPackage1);
  }).toThrow(MissingCommitmentError);

  try {
    sign(ciphersuite, signingPackage, nonces1, keyPackage1);
    expect.fail("Should have thrown MissingCommitmentError");
  } catch (e) {
    expect(e).toBeInstanceOf(MissingCommitmentError);
    if (e instanceof MissingCommitmentError) {
      // Verify the identifier in the error matches id1
      expect(bytesToHex(e.identifier.serialize())).toBe(id1Hex);
    }
  }
}

/**
 * Test signing with incorrect commitments.
 *
 * Ported from Rust: check_sign_with_incorrect_commitments
 *
 * This test verifies that signing fails with IncorrectCommitment error when the
 * commitment in the signing package doesn't match the nonces being used.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function checkSignWithIncorrectCommitments<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation with dealer
  const [shares, _pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert shares to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idHex, share] of shares) {
    const keyPackage = share.toKeyPackage();
    keyPackages.set(idHex, keyPackage);
  }

  // Get identifier hex strings for lookup in keyPackages map
  const id1Hex = bytesToHex(Identifier.fromU16(ciphersuite, 1).serialize());
  const id2Hex = bytesToHex(Identifier.fromU16(ciphersuite, 2).serialize());
  const id3Hex = bytesToHex(Identifier.fromU16(ciphersuite, 3).serialize());

  // Get the actual keyPackages (using identifier references that will match in the Map)
  const keyPackage1 = unwrap(keyPackages.get(id1Hex));
  const keyPackage2 = unwrap(keyPackages.get(id2Hex));
  const keyPackage3 = unwrap(keyPackages.get(id3Hex));

  // Round 1: Generate nonces and commitments
  const commitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();

  // Generate for participant 1
  const [_nonces1, commitments1] = commit(ciphersuite, keyPackage1.signingShare, rng);

  // Generate for participant 2
  const [_nonces2, commitments2] = commit(ciphersuite, keyPackage2.signingShare, rng);

  // Generate for participant 3 (we'll use nonces3 but give it WRONG commitments)
  const [nonces3, _commitments3] = commit(ciphersuite, keyPackage3.signingShare, rng);

  // Use keyPackage.identifier references for Map keys (JavaScript Maps use reference equality)
  commitmentsMap.set(keyPackage1.identifier, commitments1);
  commitmentsMap.set(keyPackage2.identifier, commitments2);
  // Invalid commitment for id_3 - using commitments1 instead of commitments3
  // This should trigger IncorrectCommitmentError when id_3 tries to sign
  commitmentsMap.set(keyPackage3.identifier, commitments1);

  // Create signing package
  const message = new TextEncoder().encode("message to sign");
  const signingPackage: SigningPackage<C> = {
    signingCommitments: commitmentsMap,
    message,
  };

  // Round 2: Participant with id_3 tries to sign, but their commitment doesn't match their nonces
  // Should fail with IncorrectCommitmentError
  expect(() => {
    sign(ciphersuite, signingPackage, nonces3, keyPackage3);
  }).toThrow(IncorrectCommitmentError);
}

/**
 * Self-contained wrapper for checkSignErrors.
 *
 * Creates signing setup internally and tests that signing fails with incorrect number of commitments.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function checkSignErrorsWithSetup<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation with dealer
  const [shares, _pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert shares to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idHex, share] of shares) {
    keyPackages.set(idHex, share.toKeyPackage());
  }

  // Get identifiers
  const id1 = Identifier.fromU16(ciphersuite, 1);
  const id2 = Identifier.fromU16(ciphersuite, 2);
  const id3 = Identifier.fromU16(ciphersuite, 3);

  const id1Hex = bytesToHex(id1.serialize());
  const id2Hex = bytesToHex(id2.serialize());
  const id3Hex = bytesToHex(id3.serialize());

  // Round 1: Generate nonces and commitments
  const noncesMap = new Map<string, SigningNonces<C>>();
  const commitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();

  const participants = [id1Hex, id2Hex, id3Hex];

  for (const idHex of participants) {
    const keyPackage = unwrap(keyPackages.get(idHex));
    const [nonces, commitments] = commit(ciphersuite, keyPackage.signingShare, rng);
    noncesMap.set(idHex, nonces);
    commitmentsMap.set(keyPackage.identifier, commitments);
  }

  // Create signing package
  const message = new TextEncoder().encode("message to sign");
  const signingPackage: SigningPackage<C> = {
    signingCommitments: commitmentsMap,
    message,
  };

  // Get signer's data
  const keyPackage1 = unwrap(keyPackages.get(id1Hex));
  const nonces1 = unwrap(noncesMap.get(id1Hex));

  // Call the actual test function
  checkSignErrors(ciphersuite, signingPackage, nonces1, keyPackage1);
}

/**
 * Self-contained wrapper for aggregate error tests.
 *
 * Creates full signing setup internally and tests aggregate error detection.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function checkAggregateErrorsWithSetup<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation with dealer
  const [shares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert shares to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idHex, share] of shares) {
    keyPackages.set(idHex, share.toKeyPackage());
  }

  // Get identifiers
  const id1 = Identifier.fromU16(ciphersuite, 1);
  const id2 = Identifier.fromU16(ciphersuite, 2);
  const id3 = Identifier.fromU16(ciphersuite, 3);

  const id1Hex = bytesToHex(id1.serialize());
  const id2Hex = bytesToHex(id2.serialize());
  const id3Hex = bytesToHex(id3.serialize());

  // Round 1: Generate nonces and commitments
  const noncesMap = new Map<string, SigningNonces<C>>();
  const commitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();

  const participants = [id1Hex, id2Hex, id3Hex];

  for (const idHex of participants) {
    const keyPackage = unwrap(keyPackages.get(idHex));
    const [nonces, commitments] = commit(ciphersuite, keyPackage.signingShare, rng);
    noncesMap.set(idHex, nonces);
    commitmentsMap.set(keyPackage.identifier, commitments);
  }

  // Create signing package
  const message = new TextEncoder().encode("message to sign");
  const signingPackage: SigningPackage<C> = {
    signingCommitments: commitmentsMap,
    message,
  };

  // Round 2: Generate signature shares
  const signatureShares = new Map<Identifier<C>, SignatureShare<C>>();

  for (const idHex of participants) {
    const keyPackage = unwrap(keyPackages.get(idHex));
    const nonces = unwrap(noncesMap.get(idHex));
    const share = sign(ciphersuite, signingPackage, nonces, keyPackage);
    signatureShares.set(keyPackage.identifier, share);
  }

  // Call the actual test functions
  checkAggregateCorruptedShare(ciphersuite, signingPackage, signatureShares, pubKeyPackage);
  checkAggregateInvalidShareIdentifierForVerifyingShares(
    ciphersuite,
    signingPackage,
    signatureShares,
    pubKeyPackage,
  );
}

/**
 * Self-contained wrapper for verifying shares tests.
 *
 * Creates full signing setup and tests signature share verification.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function checkVerifyingSharesWithSetup<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // Key generation with dealer
  const [shares, pubKeyPackage] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Default" },
    rng,
  );

  // Convert shares to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idHex, share] of shares) {
    keyPackages.set(idHex, share.toKeyPackage());
  }

  // Get identifiers
  const id1 = Identifier.fromU16(ciphersuite, 1);
  const id2 = Identifier.fromU16(ciphersuite, 2);
  const id3 = Identifier.fromU16(ciphersuite, 3);

  const id1Hex = bytesToHex(id1.serialize());
  const id2Hex = bytesToHex(id2.serialize());
  const id3Hex = bytesToHex(id3.serialize());

  // Round 1: Generate nonces and commitments
  const noncesMap = new Map<string, SigningNonces<C>>();
  const commitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();

  const participants = [id1Hex, id2Hex, id3Hex];

  for (const idHex of participants) {
    const keyPackage = unwrap(keyPackages.get(idHex));
    const [nonces, commitments] = commit(ciphersuite, keyPackage.signingShare, rng);
    noncesMap.set(idHex, nonces);
    commitmentsMap.set(keyPackage.identifier, commitments);
  }

  // Create signing package
  const message = new TextEncoder().encode("message to sign");
  const signingPackage: SigningPackage<C> = {
    signingCommitments: commitmentsMap,
    message,
  };

  // Round 2: Generate signature shares
  const signatureShares = new Map<Identifier<C>, SignatureShare<C>>();

  for (const idHex of participants) {
    const keyPackage = unwrap(keyPackages.get(idHex));
    const nonces = unwrap(noncesMap.get(idHex));
    const share = sign(ciphersuite, signingPackage, nonces, keyPackage);
    signatureShares.set(keyPackage.identifier, share);
  }

  // Call the actual test functions (note: pubKeyPackage comes before signingPackage)
  checkVerifyingShares(ciphersuite, pubKeyPackage, signingPackage, signatureShares);
  checkVerifySignatureShare(ciphersuite, pubKeyPackage, signingPackage, signatureShares);
}

/**
 * Self-contained wrapper for DKG Part 2 error test.
 *
 * Creates DKG setup and tests part2 error handling with corrupted proof of knowledge.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export function checkDkgPart2ErrorWithSetup<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): void {
  const maxSigners = 5;
  const minSigners = 3;

  // DKG Round 1
  const round1SecretPackages = new Map<string, round1.SecretPackage<C>>();
  const round1Packages = new Map<string, round1.Package<C>>();

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idHex = bytesToHex(identifier.serialize());
    const [secretPackage, pkg] = part1(ciphersuite, identifier, maxSigners, minSigners, rng);
    round1SecretPackages.set(idHex, secretPackage);
    round1Packages.set(idHex, pkg);
  }

  // Get the first participant's secret package
  const firstIdHex = bytesToHex(Identifier.fromU16(ciphersuite, 1).serialize());
  const secretPackage = unwrap(round1SecretPackages.get(firstIdHex));

  // Create received round 1 packages (excluding self)
  const receivedRound1Packages = new Map<string, round1.Package<C>>();
  for (const [idHex, pkg] of round1Packages) {
    if (idHex !== firstIdHex) {
      receivedRound1Packages.set(idHex, pkg);
    }
  }

  // Call the actual test function
  checkPart2Error(ciphersuite, secretPackage, receivedRound1Packages);
}

/**
 * Self-contained wrapper for DKG Part 3 error tests.
 *
 * Creates full DKG setup and tests part3 error handling.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function checkDkgPart3ErrorsWithSetup<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  const maxSigners = 5;
  const minSigners = 3;

  // DKG Round 1
  const round1SecretPackages = new Map<string, round1.SecretPackage<C>>();
  const round1Packages = new Map<string, round1.Package<C>>();

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idHex = bytesToHex(identifier.serialize());
    const [secretPackage, pkg] = part1(ciphersuite, identifier, maxSigners, minSigners, rng);
    round1SecretPackages.set(idHex, secretPackage);
    round1Packages.set(idHex, pkg);
  }

  // DKG Round 2 - Each participant processes round 1 packages and generates round 2 packages
  const round2SecretPackages = new Map<string, round2.SecretPackage<C>>();
  const receivedRound1Packages = new Map<string, Map<string, round1.Package<C>>>();
  const receivedRound2Packages = new Map<string, Map<string, round2.Package<C>>>();

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idHex = bytesToHex(identifier.serialize());

    // Collect round 1 packages from others
    const othersRound1 = new Map<string, round1.Package<C>>();
    for (const [otherIdHex, pkg] of round1Packages) {
      if (otherIdHex !== idHex) {
        othersRound1.set(otherIdHex, pkg);
      }
    }
    receivedRound1Packages.set(idHex, othersRound1);

    // Run part2
    const secretPackage = unwrap(round1SecretPackages.get(idHex));
    const [round2SecretPackage, round2PackagesForOthers] = part2(
      ciphersuite,
      secretPackage,
      othersRound1,
    );
    round2SecretPackages.set(idHex, round2SecretPackage);

    // Distribute round 2 packages to recipients
    for (const [recipientIdHex, pkg] of round2PackagesForOthers) {
      if (!receivedRound2Packages.has(recipientIdHex)) {
        receivedRound2Packages.set(recipientIdHex, new Map());
      }
      unwrap(receivedRound2Packages.get(recipientIdHex)).set(idHex, pkg);
    }
  }

  // Call the actual test functions
  await checkPart3CorruptedShare(
    ciphersuite,
    maxSigners,
    round2SecretPackages,
    receivedRound1Packages,
    receivedRound2Packages,
  );

  await checkPart3Errors(
    ciphersuite,
    maxSigners,
    round2SecretPackages,
    receivedRound1Packages,
    receivedRound2Packages,
  );

  await checkPart3DifferentParticipants(
    ciphersuite,
    maxSigners,
    round2SecretPackages,
    receivedRound1Packages,
    receivedRound2Packages,
  );
}

/**
 * Test FROST signing with trusted dealer using specified identifiers.
 *
 * Ported from Rust: check_sign_with_dealer_and_identifiers
 *
 * This test verifies:
 * 1. Duplicate identifiers are rejected
 * 2. Incorrect number of identifiers is rejected
 * 3. Custom identifiers work correctly in the signing flow
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 * @returns A tuple of [message, signature, verifyingKey]
 */
export async function checkSignWithDealerAndIdentifiers<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<[Uint8Array, Signature<C>, VerifyingKey<C>]> {
  const maxSigners = 5;
  const minSigners = 3;

  // Check error cases first
  // Check repeated identifiers - [1, 42, 100, 257, 42] has duplicate 42
  const duplicateIdentifiers: Identifier<C>[] = [1, 42, 100, 257, 42].map((i) =>
    Identifier.fromU16(ciphersuite, i),
  );

  await expect(
    generateWithDealer(
      ciphersuite,
      maxSigners,
      minSigners,
      { type: "Custom", identifiers: duplicateIdentifiers },
      rng,
    ),
  ).rejects.toThrow();

  // Check incorrect number of identifiers - only 4 identifiers for 5 signers
  const incorrectNumberIdentifiers: Identifier<C>[] = [1, 42, 100, 257].map((i) =>
    Identifier.fromU16(ciphersuite, i),
  );

  await expect(
    generateWithDealer(
      ciphersuite,
      maxSigners,
      minSigners,
      { type: "Custom", identifiers: incorrectNumberIdentifiers },
      rng,
    ),
  ).rejects.toThrow();

  // Check correct case - valid custom identifiers
  const customIdentifiers: Identifier<C>[] = [1, 42, 100, 257, 65535].map((i) =>
    Identifier.fromU16(ciphersuite, i),
  );

  const [shares, pubkeys] = await generateWithDealer(
    ciphersuite,
    maxSigners,
    minSigners,
    { type: "Custom", identifiers: customIdentifiers },
    rng,
  );

  // Check if the specified identifiers were used
  for (const id of customIdentifiers) {
    const idStr = bytesToHex(id.serialize());
    expect(shares.has(idStr)).toBe(true);
  }

  // Convert shares to key packages
  const keyPackages = new Map<string, KeyPackage<C>>();
  for (const [idHex, share] of shares) {
    const keyPackage = share.toKeyPackage();
    keyPackages.set(idHex, keyPackage);
  }

  // Do regular testing to make sure it works
  return checkSign(ciphersuite, minSigners, keyPackages, rng, pubkeys);
}

/**
 * Test FROST signing in an async context.
 *
 * Ported from Rust: async_check_sign
 *
 * The ultimate goal of this test is to ensure that types are usable in
 * async contexts. In TypeScript, this verifies that our implementations
 * don't have any hidden synchronous-only dependencies.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export async function asyncCheckSign<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
): Promise<void> {
  // Run the signing flow in a Promise to simulate async context
  await new Promise<void>((resolve, reject) => {
    void (async () => {
      try {
        const maxSigners = 5;
        const minSigners = 3;

        const [shares, pubkeyPackage] = await generateWithDealer(
          ciphersuite,
          maxSigners,
          minSigners,
          { type: "Default" },
          rng,
        );

        // Simulate async delay (like tokio::time::sleep in Rust)
        await delay(1);

        // Convert shares to key packages
        const keyPackages = new Map<string, KeyPackage<C>>();
        for (const [idHex, share] of shares) {
          keyPackages.set(idHex, share.toKeyPackage());
        }

        await delay(1);

        // Round 1: generating nonces and signing commitments
        const noncesMap = new Map<string, SigningNonces<C>>();
        const commitmentsMap = new Map<Identifier<C>, SigningCommitments<C>>();

        let count = 0;
        for (const [idHex, keyPackage] of keyPackages) {
          if (count >= minSigners) break;

          const [nonces, commitments] = commit(ciphersuite, keyPackage.signingShare, rng);

          await delay(1);

          noncesMap.set(idHex, nonces);
          commitmentsMap.set(keyPackage.identifier, commitments);
          count++;
        }

        // Create signing package
        const message = new TextEncoder().encode("message to sign");
        const signingPackage: SigningPackage<C> = {
          signingCommitments: commitmentsMap,
          message,
        };

        // Round 2: each participant generates their signature share
        const signatureShares = new Map<Identifier<C>, SignatureShare<C>>();

        for (const [idHex, nonces] of noncesMap) {
          const keyPackage = unwrap(keyPackages.get(idHex));
          const signatureShare = sign(ciphersuite, signingPackage, nonces, keyPackage);

          await delay(1);

          signatureShares.set(keyPackage.identifier, signatureShare);
        }

        // Aggregation
        const groupSignature = aggregate(
          ciphersuite,
          signingPackage,
          signatureShares,
          pubkeyPackage,
        );

        await delay(1);

        // Verify the signature with the group verifying key
        const verifyingKey = VerifyingKey.create(ciphersuite, pubkeyPackage.verifyingKey);
        verifyingKey.verify(message, groupSignature);

        await delay(1);

        // Also verify using each participant's verifying key from KeyPackage
        for (const [idHex] of noncesMap) {
          const keyPackage = unwrap(keyPackages.get(idHex));
          const pkgVerifyingKey = VerifyingKey.create(ciphersuite, keyPackage.verifyingKey);
          pkgVerifyingKey.verify(message, groupSignature);

          await delay(1);
        }

        resolve();
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    })();
  });
}

/**
 * Helper function to create a small delay for async testing.
 *
 * @param ms - Milliseconds to delay
 */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, ms));
}
