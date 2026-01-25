/**
 * Generate sample, fixed instances of structs for testing.
 * Ported from frost-ristretto255/tests/helpers/samples.rs
 *
 * These samples provide deterministic test data for serialization
 * and recreation tests.
 */

// Test vector data from samples.json
const SAMPLES = {
  identifier:
    "2a00000000000000000000000000000000000000000000000000000000000000",
  proofOfKnowledge:
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
  element1:
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
  element2:
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
  scalar1:
    "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
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
 * Get the first sample element (generator point).
 */
export function element1(): Uint8Array {
  return hexToBytes(SAMPLES.element1);
}

/**
 * Get the second sample element (2 * generator).
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
 * Get the sample proof of knowledge.
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
