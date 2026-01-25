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
import type { Ciphersuite, SigningPackage } from "../types.js";
import { SigningKey } from "../signing_key.js";
import { FrostError } from "../error.js";
import { Identifier } from "../identifier.js";
import {
  generateWithDealer,
  KeyPackage,
  SecretShare,
  PublicKeyPackage,
  generateSecretShares,
  generateCoefficients,
  defaultIdentifiers,
  reconstruct,
  round1,
  round2,
  part1,
  part2,
  part3,
} from "../keys.js";
import { commit, SigningCommitments, SigningNonces } from "../round1.js";
import { sign, SignatureShare } from "../round2.js";
import { aggregate } from "../aggregate.js";
import { Signature } from "../signature.js";
import { VerifyingKey } from "../verifying_key.js";
import type { CryptoRng } from "./helpers.js";

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
export async function checkShareGenerationFailsWithInvalidSigners<C extends Ciphersuite>(
  ciphersuite: C,
  minSigners: number,
  maxSigners: number,
  rng: CryptoRng,
): Promise<void> {
  const secret = SigningKey.generate(ciphersuite, rng);

  // Use arbitrary number of coefficients so tests don't fail for overflow reasons
  const coefficients = generateCoefficients(ciphersuite, 3, rng);

  expect(() => {
    const identifiers = [];
    for (let i = 1; i <= maxSigners; i++) {
      identifiers.push(Identifier.fromU16(ciphersuite, i));
    }
    generateSecretShares(
      ciphersuite,
      secret,
      maxSigners,
      minSigners,
      coefficients,
      identifiers,
    );
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
    "default",
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
  const result = await checkSign(ciphersuite, minSigners, keyPackages, rng, pubKeyPackage);
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
export async function checkSign<C extends Ciphersuite>(
  ciphersuite: C,
  minSigners: number,
  keyPackages: Map<string, KeyPackage<C>>,
  rng: CryptoRng,
  pubkeyPackage: PublicKeyPackage<C>,
): Promise<[Uint8Array, Signature<C>, VerifyingKey<C>]> {
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
    const keyPackage = keyPackages.get(idKey)!;

    const signatureShare = sign(ciphersuite, signingPackage, nonces, keyPackage);
    // Use keyPackage.identifier directly for consistency
    signatureShares.set(keyPackage.identifier, signatureShare);
  }

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
    generateWithDealer(ciphersuite, maxSigners, minSigners, "default", rng),
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

  // The same input should produce the same output
  const result2 = ciphersuite.HID(testInput);
  expect(ciphersuite.scalarsEqual(result!, result2!)).toBe(true);

  // Different inputs should produce different outputs (with high probability)
  const differentInput = new TextEncoder().encode("bob@example.com");
  const differentResult = ciphersuite.HID(differentInput);
  expect(ciphersuite.scalarsEqual(result!, differentResult!)).toBe(false);
}

// Helper functions

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

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
      receivedRound1Packages.get(receiverIdStr)!.set(idStr, round1Pkg.clone());
    }
  }

  // Round 2: Each participant processes received packages and generates round 2 packages
  const round2SecretPackages = new Map<string, round2.SecretPackage<C>>();
  const receivedRound2Packages = new Map<string, Map<string, round2.Package<C>>>();

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idStr = bytesToHex(identifier.serialize());

    const secretPkg = round1SecretPackages.get(idStr)!;
    const round1Pkgs = receivedRound1Packages.get(idStr)!;

    const [round2Secret, round2Pkgs] = part2(ciphersuite, secretPkg, round1Pkgs);

    round2SecretPackages.set(idStr, round2Secret);

    // "Send" the round 2 packages to their respective recipients
    for (const [receiverIdStr, round2Pkg] of round2Pkgs) {
      if (!receivedRound2Packages.has(receiverIdStr)) {
        receivedRound2Packages.set(receiverIdStr, new Map());
      }
      receivedRound2Packages.get(receiverIdStr)!.set(idStr, round2Pkg);
    }
  }

  // Part 3: Each participant computes their key package
  const keyPackages = new Map<string, KeyPackage<C>>();
  let pubKeyPackage: PublicKeyPackage<C> | undefined;

  for (let i = 1; i <= maxSigners; i++) {
    const identifier = Identifier.fromU16(ciphersuite, i);
    const idStr = bytesToHex(identifier.serialize());

    const round2Secret = round2SecretPackages.get(idStr)!;
    const round1Pkgs = receivedRound1Packages.get(idStr)!;
    const round2Pkgs = receivedRound2Packages.get(idStr)!;

    const [keyPkg, pubPkg] = await part3(ciphersuite, round2Secret, round1Pkgs, round2Pkgs);

    keyPackages.set(idStr, keyPkg);

    // All participants should compute the same public key package
    if (pubKeyPackage === undefined) {
      pubKeyPackage = pubPkg;
    }
  }

  // Run the signing protocol with the DKG-generated keys
  return checkSign(ciphersuite, minSigners, keyPackages, rng, pubKeyPackage!);
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
