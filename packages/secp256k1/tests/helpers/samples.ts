/**
 * Generate sample, fixed instances of structs for testing.
 * Ported from frost-secp256k1/tests/helpers/samples.rs
 *
 * These samples provide deterministic test data for serialization
 * and recreation tests.
 *
 * Key differences from Ristretto255:
 * - SCALAR_LENGTH = 32 bytes (same)
 * - ELEMENT_LENGTH = 33 bytes (SEC1 compressed format)
 * - Signature serialization is 65 bytes (33 + 32)
 */

// Test vector data for secp256k1
// element1 = generator point G (SEC1 compressed)
// element2 = 2G (SEC1 compressed)
// scalar1 = inverse of 3 (mod order)
const SAMPLES = {
  // Identifier 42 as a scalar
  identifier: "000000000000000000000000000000000000000000000000000000000000002a",
  // Generator point G (SEC1 compressed, 02 prefix for even y)
  element1: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  // 2G (SEC1 compressed)
  element2: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  // Inverse of 3 mod secp256k1 order
  // order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  // scalar1 = inverse(3) = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9d1c9e899ca306ad27fe1945de0242b81
  scalar1: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9d1c9e899ca306ad27fe1945de0242b81",
  // Proof of knowledge: element1 (33 bytes) + scalar1 (32 bytes) = 65 bytes
  proofOfKnowledge:
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9d1c9e899ca306ad27fe1945de0242b81",
} as const;

/**
 * Convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Get the sample identifier (42 as a scalar).
 */
export function sampleIdentifier(): Uint8Array {
  return hexToBytes(SAMPLES.identifier);
}

/**
 * Get the sample identifier value (42).
 */
export function sampleIdentifierValue(): number {
  return 42;
}

/**
 * Get the first sample element (generator point G, SEC1 compressed).
 */
export function element1(): Uint8Array {
  return hexToBytes(SAMPLES.element1);
}

/**
 * Get the second sample element (2G, SEC1 compressed).
 */
export function element2(): Uint8Array {
  return hexToBytes(SAMPLES.element2);
}

/**
 * Get the sample scalar (inverse of 3).
 */
export function scalar1(): Uint8Array {
  return hexToBytes(SAMPLES.scalar1);
}

/**
 * Get the sample proof of knowledge (signature: element + scalar).
 */
export function proofOfKnowledge(): Uint8Array {
  return hexToBytes(SAMPLES.proofOfKnowledge);
}

/**
 * Sample data interface for creating test objects.
 */
export interface SampleData {
  identifier: Uint8Array;
  identifierValue: number;
  element1: Uint8Array;
  element2: Uint8Array;
  scalar1: Uint8Array;
  proofOfKnowledge: Uint8Array;
}

/**
 * Get all sample data.
 */
export function getSampleData(): SampleData {
  return {
    identifier: sampleIdentifier(),
    identifierValue: sampleIdentifierValue(),
    element1: element1(),
    element2: element2(),
    scalar1: scalar1(),
    proofOfKnowledge: proofOfKnowledge(),
  };
}

/**
 * Sample SigningCommitments data.
 * Uses element1 as hiding commitment and element2 as binding commitment.
 */
export interface SigningCommitmentsData {
  hiding: Uint8Array;
  binding: Uint8Array;
}

export function signingCommitmentsData(): SigningCommitmentsData {
  return {
    hiding: element1(),
    binding: element2(),
  };
}

/**
 * Sample SigningNonces data.
 * Uses scalar1 for both hiding and binding nonces.
 */
export interface SigningNoncesData {
  hiding: Uint8Array;
  binding: Uint8Array;
}

export function signingNoncesData(): SigningNoncesData {
  return {
    hiding: scalar1(),
    binding: scalar1(),
  };
}

/**
 * Sample SigningPackage data.
 */
export interface SigningPackageData {
  identifier: number;
  commitments: SigningCommitmentsData;
  message: Uint8Array;
}

export function signingPackageData(): SigningPackageData {
  return {
    identifier: 42,
    commitments: signingCommitmentsData(),
    message: new TextEncoder().encode("hello world"),
  };
}

/**
 * Sample SignatureShare data.
 */
export interface SignatureShareData {
  share: Uint8Array;
}

export function signatureShareData(): SignatureShareData {
  return {
    share: scalar1(),
  };
}

/**
 * Sample SecretShare data.
 */
export interface SecretShareData {
  identifier: number;
  signingShare: Uint8Array;
  commitment: Uint8Array[];
}

export function secretShareData(): SecretShareData {
  return {
    identifier: 42,
    signingShare: scalar1(),
    commitment: [element1()],
  };
}

/**
 * Sample KeyPackage data.
 */
export interface KeyPackageData {
  identifier: number;
  signingShare: Uint8Array;
  verifyingShare: Uint8Array;
  verifyingKey: Uint8Array;
  minSigners: number;
}

export function keyPackageData(): KeyPackageData {
  return {
    identifier: 42,
    signingShare: scalar1(),
    verifyingShare: element1(),
    verifyingKey: element1(),
    minSigners: 2,
  };
}

/**
 * Sample PublicKeyPackage data (legacy without minSigners).
 */
export interface PublicKeyPackageData {
  verifyingShares: Map<number, Uint8Array>;
  verifyingKey: Uint8Array;
  minSigners?: number;
}

export function publicKeyPackageData(): PublicKeyPackageData {
  const verifyingShares = new Map<number, Uint8Array>();
  verifyingShares.set(42, element1());
  return {
    verifyingShares,
    verifyingKey: element1(),
  };
}

/**
 * Sample PublicKeyPackage data with minSigners.
 */
export function publicKeyPackageNewData(): PublicKeyPackageData {
  const verifyingShares = new Map<number, Uint8Array>();
  verifyingShares.set(42, element1());
  return {
    verifyingShares,
    verifyingKey: element1(),
    minSigners: 2,
  };
}

/**
 * Sample Round1 SecretPackage data.
 */
export interface Round1SecretPackageData {
  identifier: number;
  coefficients: Uint8Array[];
  commitment: Uint8Array[];
  minSigners: number;
  maxSigners: number;
}

export function round1SecretPackageData(): Round1SecretPackageData {
  return {
    identifier: 42,
    coefficients: [scalar1(), scalar1()],
    commitment: [element1()],
    minSigners: 2,
    maxSigners: 3,
  };
}

/**
 * Sample Round1 Package data.
 */
export interface Round1PackageData {
  commitment: Uint8Array[];
  proofOfKnowledge: Uint8Array;
}

export function round1PackageData(): Round1PackageData {
  return {
    commitment: [element1()],
    proofOfKnowledge: proofOfKnowledge(),
  };
}

/**
 * Sample Round2 SecretPackage data.
 */
export interface Round2SecretPackageData {
  identifier: number;
  commitment: Uint8Array[];
  secretShare: Uint8Array;
  minSigners: number;
  maxSigners: number;
}

export function round2SecretPackageData(): Round2SecretPackageData {
  return {
    identifier: 42,
    commitment: [element1()],
    secretShare: scalar1(),
    minSigners: 2,
    maxSigners: 3,
  };
}

/**
 * Sample Round2 Package data.
 */
export interface Round2PackageData {
  signingShare: Uint8Array;
}

export function round2PackageData(): Round2PackageData {
  return {
    signingShare: scalar1(),
  };
}

// ---------------------------------------------------------------------------
// Sample Object Factory Functions
// These create actual FROST objects for testing (matching Rust samples.rs)
// ---------------------------------------------------------------------------

import {
  Secp256K1Sha256,
  SigningCommitments,
  NonceCommitment,
  SigningNonces,
  Nonce,
  SignatureShare,
  Signature as _Signature,
  Identifier,
  keys,
} from "../../src/index.js";

import {
  type SigningPackage,
  SigningPackageImpl,
  SigningShare,
  VerifyingShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  VerifiableSecretSharingCommitment,
  type Round1Package,
  type Round1SecretPackage,
  type Round2Package,
  type Round2SecretPackage,
} from "@frosts/core";

// Get DKG module from keys
const { dkg } = keys;

// Type aliases for return types
type SecretShareType = SecretShare<typeof Secp256K1Sha256>;
type KeyPackageType = KeyPackage<typeof Secp256K1Sha256>;
type PublicKeyPackageType = PublicKeyPackage<typeof Secp256K1Sha256>;
type VerifyingShareType = VerifyingShare<typeof Secp256K1Sha256>;
type Round1SecretPackageType = Round1SecretPackage<typeof Secp256K1Sha256>;
type Round1PackageType = Round1Package<typeof Secp256K1Sha256>;
type Round2SecretPackageType = Round2SecretPackage<typeof Secp256K1Sha256>;
type Round2PackageType = Round2Package<typeof Secp256K1Sha256>;

/**
 * Create a sample SigningNonces object.
 * Matches Rust: samples::signing_nonces()
 */
export function signingNonces(): SigningNonces<typeof Secp256K1Sha256> {
  const hidingNonce = Nonce.deserialize(Secp256K1Sha256, scalar1());
  const bindingNonce = Nonce.deserialize(Secp256K1Sha256, scalar1());
  return SigningNonces.fromNonces(Secp256K1Sha256, hidingNonce, bindingNonce);
}

/**
 * Create a sample SigningCommitments object.
 * Matches Rust: samples::signing_commitments()
 */
export function signingCommitments(): SigningCommitments<typeof Secp256K1Sha256> {
  const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, element1());
  const bindingCommitment = NonceCommitment.deserialize(Secp256K1Sha256, element2());
  return new SigningCommitments(Secp256K1Sha256, hidingCommitment, bindingCommitment);
}

/**
 * Create a sample SigningPackage object.
 * Matches Rust: samples::signing_package()
 */
export function signingPackage(): SigningPackage<typeof Secp256K1Sha256> {
  const identifier = Identifier.fromU16(Secp256K1Sha256, 42);
  const commitments = new Map<
    Identifier<typeof Secp256K1Sha256>,
    SigningCommitments<typeof Secp256K1Sha256>
  >();
  commitments.set(identifier, signingCommitments());
  const message = new TextEncoder().encode("hello world");

  return SigningPackageImpl.create(Secp256K1Sha256, commitments, message);
}

/**
 * Create a sample SignatureShare object.
 * Matches Rust: samples::signature_share()
 */
export function signatureShare(): SignatureShare<typeof Secp256K1Sha256> {
  return SignatureShare.deserialize(Secp256K1Sha256, scalar1());
}

/**
 * Create a sample SecretShare object.
 * Matches Rust: samples::secret_share()
 */
export function secretShare(): SecretShareType {
  const identifier = Identifier.fromU16(Secp256K1Sha256, 42);
  const signingShareObj = SigningShare.deserialize(Secp256K1Sha256, scalar1());
  const vssCommitment = VerifiableSecretSharingCommitment.deserialize(Secp256K1Sha256, [
    element1(),
  ]);
  return new SecretShare(Secp256K1Sha256, identifier, signingShareObj, vssCommitment);
}

/**
 * Create a sample KeyPackage object.
 * Matches Rust: samples::key_package()
 */
export function keyPackage(): KeyPackageType {
  const identifier = Identifier.fromU16(Secp256K1Sha256, 42);
  const signingShareObj = SigningShare.deserialize(Secp256K1Sha256, scalar1());
  const verifyingShareObj = VerifyingShare.deserialize(Secp256K1Sha256, element1());
  const verifyingKeyElement = Secp256K1Sha256.deserializeElement(element1());
  return new KeyPackage(
    Secp256K1Sha256,
    identifier,
    signingShareObj,
    verifyingShareObj,
    verifyingKeyElement,
    2,
  );
}

/**
 * Create a sample PublicKeyPackage object (legacy without minSigners).
 * Matches Rust: samples::public_key_package()
 */
export function publicKeyPackage(): PublicKeyPackageType {
  const identifier = Identifier.fromU16(Secp256K1Sha256, 42);
  const verifyingShareObj = VerifyingShare.deserialize(Secp256K1Sha256, element1());
  const verifyingKeyElement = Secp256K1Sha256.deserializeElement(element1());
  const verifyingShares = new Map<string, VerifyingShareType>();
  verifyingShares.set(bytesToHex(identifier.serialize()), verifyingShareObj);
  return new PublicKeyPackage(Secp256K1Sha256, verifyingShares, verifyingKeyElement);
}

/**
 * Create a sample PublicKeyPackage object with minSigners.
 * Matches Rust: samples::public_key_package_new()
 */
export function publicKeyPackageNew(): PublicKeyPackageType {
  const identifier = Identifier.fromU16(Secp256K1Sha256, 42);
  const verifyingShareObj = VerifyingShare.deserialize(Secp256K1Sha256, element1());
  const verifyingKeyElement = Secp256K1Sha256.deserializeElement(element1());
  const verifyingShares = new Map<string, VerifyingShareType>();
  verifyingShares.set(bytesToHex(identifier.serialize()), verifyingShareObj);
  return new PublicKeyPackage(Secp256K1Sha256, verifyingShares, verifyingKeyElement, 2);
}

/**
 * Create a sample round1::SecretPackage object.
 * Matches Rust: samples::round1_secret_package()
 */
export function round1SecretPackage(): Round1SecretPackageType {
  const identifier = Identifier.fromU16(Secp256K1Sha256, 42);
  const scalarBytes1 = scalar1();
  const scalarBytes2 = scalar1();
  const coeff1 = Secp256K1Sha256.deserializeScalar(scalarBytes1);
  const coeff2 = Secp256K1Sha256.deserializeScalar(scalarBytes2);
  const coefficients = [coeff1, coeff2];
  const vssCommitment = VerifiableSecretSharingCommitment.deserialize(Secp256K1Sha256, [
    element1(),
  ]);
  return new dkg.round1.SecretPackage(
    Secp256K1Sha256,
    identifier,
    coefficients,
    vssCommitment,
    2,
    3,
  );
}

/**
 * Create a sample round1::Package object.
 * Matches Rust: samples::round1_package()
 */
export function round1Package(): Round1PackageType {
  const vssCommitment = VerifiableSecretSharingCommitment.deserialize(Secp256K1Sha256, [
    element1(),
  ]);
  // Proof of knowledge is a DkgSignature with R (element) and z (scalar)
  const R = Secp256K1Sha256.deserializeElement(element1());
  const z = Secp256K1Sha256.deserializeScalar(scalar1());
  const proofOfKnowledgeSignature = { R, z };
  return new dkg.round1.Package(Secp256K1Sha256, vssCommitment, proofOfKnowledgeSignature);
}

/**
 * Create a sample round2::SecretPackage object.
 * Matches Rust: samples::round2_secret_package()
 */
export function round2SecretPackage(): Round2SecretPackageType {
  const identifier = Identifier.fromU16(Secp256K1Sha256, 42);
  const vssCommitment = VerifiableSecretSharingCommitment.deserialize(Secp256K1Sha256, [
    element1(),
  ]);
  const secretShareScalar = Secp256K1Sha256.deserializeScalar(scalar1());
  return new dkg.round2.SecretPackage(
    Secp256K1Sha256,
    identifier,
    vssCommitment,
    secretShareScalar,
    2,
    3,
  );
}

/**
 * Create a sample round2::Package object.
 * Matches Rust: samples::round2_package()
 */
export function round2Package(): Round2PackageType {
  const signingShareObj = SigningShare.deserialize(Secp256K1Sha256, scalar1());
  return new dkg.round2.Package(Secp256K1Sha256, signingShareObj);
}

// Type exports for the sample objects
export type { SigningNonces, SigningCommitments, SignatureShare } from "@frosts/core";

export type {
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  SigningShare,
  VerifyingShare,
  VerifiableSecretSharingCommitment,
} from "../../src/keys/index.js";
