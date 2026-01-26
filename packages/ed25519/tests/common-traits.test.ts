/**
 * Common traits tests for FROST Ed25519-SHA512.
 * Ported from frost-ed25519/tests/common_traits_tests.rs
 *
 * These tests verify that all FROST types implement common traits:
 * - Clone (deep copy)
 * - Eq/PartialEq (equality comparison)
 * - Debug (string representation for debugging)
 *
 * In TypeScript, we test equivalent functionality:
 * - clone() method
 * - equals() method
 * - toString() / toDebugString() methods
 * - Proper handling in Result-like patterns
 */

import { describe, it, expect } from "vitest";
import { createSecureRng } from "./helpers/index.js";
import { element1, element2, scalar1, proofOfKnowledge, bytesToHex } from "./helpers/samples.js";
import {
  Ed25519Sha512,
  SigningKey,
  SigningNonces,
  SigningCommitments,
  NonceCommitment,
  SignatureShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  SigningShare,
  VerifyingShare,
  CoefficientCommitment,
  VerifiableSecretSharingCommitment,
  Identifier,
  Nonce,
} from "../src/index.js";
import { SigningPackageImpl } from "@frosts/core";
import { round1, round2 } from "@frosts/core";

/**
 * Interface representing common traits that all FROST types should implement.
 */
interface CommonTraits {
  clone(): CommonTraits;
  equals(other: CommonTraits): boolean;
  toString(): string;
}

/**
 * Simple Result type for testing.
 */
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

/**
 * Wrap a value in a Result for testing Result-pattern compatibility.
 */
function wrapInResult<T>(value: T): Result<T> {
  return { ok: true, value };
}

/**
 * Helper function to check common traits for a type.
 * Ported from Rust's check_common_traits_for_type function.
 *
 * Tests:
 * 1. Debug printability (toString)
 * 2. Clone and Eq (clone and equals)
 * 3. Usability in Result patterns
 *
 * @param value - The value to test
 * @param _name
 */
function checkCommonTraitsForType<T extends CommonTraits>(value: T, _name: string): void {
  // Test 1: Make sure it can be converted to string (Debug equivalent)
  // This also catches if the implementation has endless recursion
  const debugString = value.toString();
  expect(debugString).toBeDefined();
  expect(typeof debugString).toBe("string");
  expect(debugString.length).toBeGreaterThan(0);

  // Test 2: Test Clone and Eq
  const cloned = value.clone() as T;
  expect(value.equals(cloned)).toBe(true);

  // Test 3: Make sure it can be used in Result-like patterns
  // (In Rust this requires Debug; in TS we just verify the type works in try/catch)
  const result = wrapInResult(value);
  expect(result.ok).toBe(true);
  if (result.ok) {
    expect(value.equals(result.value)).toBe(true);
  }
}

// Helper to create sample objects
const ciphersuite = Ed25519Sha512;

/**
 * Create a sample identifier (value 42).
 */
function createSampleIdentifier() {
  return Identifier.fromU16(ciphersuite, 42);
}

/**
 * Create a sample SigningShare.
 */
function createSampleSigningShare() {
  const scalar = ciphersuite.deserializeScalar(scalar1());
  return new SigningShare(ciphersuite, scalar);
}

/**
 * Create a sample VerifyingShare.
 */
function createSampleVerifyingShare() {
  const element = ciphersuite.deserializeElement(element1());
  return new VerifyingShare(ciphersuite, element);
}

/**
 * Create a sample CoefficientCommitment.
 */
function createSampleCoefficientCommitment() {
  const element = ciphersuite.deserializeElement(element1());
  return new CoefficientCommitment(ciphersuite, element);
}

/**
 * Create a sample VerifiableSecretSharingCommitment.
 */
function createSampleCommitment() {
  const coefficients = [createSampleCoefficientCommitment()];
  return new VerifiableSecretSharingCommitment(ciphersuite, coefficients);
}

/**
 * Create sample SigningNonces.
 */
function createSampleSigningNonces() {
  const hidingScalar = ciphersuite.deserializeScalar(scalar1());
  const bindingScalar = ciphersuite.deserializeScalar(scalar1());
  const hiding = Nonce.fromScalar(ciphersuite, hidingScalar);
  const binding = Nonce.fromScalar(ciphersuite, bindingScalar);
  return SigningNonces.fromNonces(ciphersuite, hiding, binding);
}

/**
 * Create sample SigningCommitments.
 */
function createSampleSigningCommitments() {
  const hiding = NonceCommitment.fromElement(
    ciphersuite,
    ciphersuite.deserializeElement(element1()),
  );
  const binding = NonceCommitment.fromElement(
    ciphersuite,
    ciphersuite.deserializeElement(element2()),
  );
  return new SigningCommitments(ciphersuite, hiding, binding);
}

/**
 * Create sample SigningPackageImpl.
 */
function createSampleSigningPackage() {
  const identifier = createSampleIdentifier();
  const commitments = createSampleSigningCommitments();
  const message = new TextEncoder().encode("hello world");

  const signingCommitments = new Map();
  signingCommitments.set(identifier, commitments);

  return new SigningPackageImpl(ciphersuite, signingCommitments, message);
}

/**
 * Create sample SignatureShare.
 */
function createSampleSignatureShare() {
  const scalar = ciphersuite.deserializeScalar(scalar1());
  return SignatureShare.fromScalar(ciphersuite, scalar);
}

/**
 * Create sample SecretShare.
 */
function createSampleSecretShare() {
  const identifier = createSampleIdentifier();
  const signingShare = createSampleSigningShare();
  const commitment = createSampleCommitment();
  return new SecretShare(ciphersuite, identifier, signingShare, commitment);
}

/**
 * Create sample KeyPackage.
 */
function createSampleKeyPackage() {
  const identifier = createSampleIdentifier();
  const signingShare = createSampleSigningShare();
  const verifyingShare = createSampleVerifyingShare();
  const verifyingKey = ciphersuite.deserializeElement(element1());
  const minSigners = 2;
  return new KeyPackage(
    ciphersuite,
    identifier,
    signingShare,
    verifyingShare,
    verifyingKey,
    minSigners,
  );
}

/**
 * Create sample PublicKeyPackage.
 */
function createSamplePublicKeyPackage() {
  const identifier = createSampleIdentifier();
  const verifyingShare = createSampleVerifyingShare();
  const verifyingKey = ciphersuite.deserializeElement(element1());
  const verifyingShares = new Map<string, VerifyingShare<typeof ciphersuite>>();
  verifyingShares.set(bytesToHex(identifier.serialize()), verifyingShare);
  return new PublicKeyPackage(ciphersuite, verifyingShares, verifyingKey, 2);
}

/**
 * Create sample Round1 Package.
 */
function createSampleRound1Package() {
  const commitment = createSampleCommitment();
  const pokBytes = proofOfKnowledge();
  // Parse proof of knowledge: first 32 bytes is R, next 32 is z
  const R = ciphersuite.deserializeElement(pokBytes.slice(0, 32));
  const z = ciphersuite.deserializeScalar(pokBytes.slice(32, 64));
  const pok = { R, z };
  return new round1.Package(ciphersuite, commitment, pok);
}

/**
 * Create sample Round1 SecretPackage.
 */
function createSampleRound1SecretPackage() {
  const identifier = createSampleIdentifier();
  const coefficients = [
    ciphersuite.deserializeScalar(scalar1()),
    ciphersuite.deserializeScalar(scalar1()),
  ];
  const commitment = createSampleCommitment();
  return new round1.SecretPackage(ciphersuite, identifier, coefficients, commitment, 2, 3);
}

/**
 * Create sample Round2 Package.
 */
function createSampleRound2Package() {
  const signingShare = createSampleSigningShare();
  return new round2.Package(ciphersuite, signingShare);
}

/**
 * Create sample Round2 SecretPackage.
 */
function createSampleRound2SecretPackage() {
  const identifier = createSampleIdentifier();
  const commitment = createSampleCommitment();
  const secretShare = ciphersuite.deserializeScalar(scalar1());
  return new round2.SecretPackage(ciphersuite, identifier, commitment, secretShare, 2, 3);
}

describe("FROST Ed25519-SHA512 Common Traits Tests", () => {
  describe("SigningKey Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_signing_key_common_traits
      const rng = createSecureRng();
      const signingKey = SigningKey.generate(ciphersuite, rng);
      checkCommonTraitsForType(signingKey, "SigningKey");
    });
  });

  describe("SigningNonces Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_signing_nonces_common_traits
      const nonces = createSampleSigningNonces();
      checkCommonTraitsForType(nonces, "SigningNonces");
    });
  });

  describe("SigningCommitments Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_signing_commitments_common_traits
      const commitments = createSampleSigningCommitments();
      checkCommonTraitsForType(commitments, "SigningCommitments");
    });
  });

  describe("SigningPackage Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_signing_package_common_traits
      const signingPackage = createSampleSigningPackage();
      checkCommonTraitsForType(signingPackage, "SigningPackage");
    });
  });

  describe("SignatureShare Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_signature_share_common_traits
      const signatureShare = createSampleSignatureShare();
      checkCommonTraitsForType(signatureShare, "SignatureShare");
    });
  });

  describe("SecretShare Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_secret_share_common_traits
      const secretShare = createSampleSecretShare();
      checkCommonTraitsForType(secretShare, "SecretShare");
    });
  });

  describe("KeyPackage Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_key_package_common_traits
      const keyPackage = createSampleKeyPackage();
      checkCommonTraitsForType(keyPackage, "KeyPackage");
    });
  });

  describe("PublicKeyPackage Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_public_key_package_common_traits
      const publicKeyPackage = createSamplePublicKeyPackage();
      checkCommonTraitsForType(publicKeyPackage, "PublicKeyPackage");
    });
  });

  describe("Round1 Package Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_round1_package_common_traits
      const round1Package = createSampleRound1Package();
      checkCommonTraitsForType(round1Package, "round1::Package");
    });
  });

  describe("Round1 SecretPackage Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_round1_secret_package_common_traits
      const round1SecretPackage = createSampleRound1SecretPackage();
      checkCommonTraitsForType(round1SecretPackage, "round1::SecretPackage");
    });
  });

  describe("Round2 Package Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_round2_package_common_traits
      const round2Package = createSampleRound2Package();
      checkCommonTraitsForType(round2Package, "round2::Package");
    });
  });

  describe("Round2 SecretPackage Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      // Ported from: check_round2_secret_package_common_traits
      const round2SecretPackage = createSampleRound2SecretPackage();
      checkCommonTraitsForType(round2SecretPackage, "round2::SecretPackage");
    });
  });

  describe("Identifier Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      const identifier = createSampleIdentifier();
      checkCommonTraitsForType(identifier, "Identifier");
    });
  });

  describe("SigningShare Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      const signingShare = createSampleSigningShare();
      checkCommonTraitsForType(signingShare, "SigningShare");
    });
  });

  describe("VerifyingShare Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      const verifyingShare = createSampleVerifyingShare();
      checkCommonTraitsForType(verifyingShare, "VerifyingShare");
    });
  });

  describe("CoefficientCommitment Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      const coefficientCommitment = createSampleCoefficientCommitment();
      checkCommonTraitsForType(coefficientCommitment, "CoefficientCommitment");
    });
  });

  describe("VerifiableSecretSharingCommitment Common Traits", () => {
    it("should implement Clone, Eq, and Debug", () => {
      const commitment = createSampleCommitment();
      checkCommonTraitsForType(commitment, "VerifiableSecretSharingCommitment");
    });
  });
});

describe("Common Traits Concepts", () => {
  describe("Clone Trait", () => {
    it("should create deep copies", () => {
      // Clone should create a completely independent copy
      // Modifying the clone should not affect the original
      const original = createSampleKeyPackage();
      const cloned = original.clone();

      expect(original.equals(cloned)).toBe(true);
      expect(original).not.toBe(cloned); // Different object references
    });

    it("should be useful for passing values to multiple consumers", () => {
      // In Rust, Clone is needed when you want to use a value multiple times
      // In TypeScript, we use clone() methods for the same purpose
      const original = createSampleSignatureShare();
      const copy1 = original.clone();
      const copy2 = original.clone();

      expect(original.equals(copy1)).toBe(true);
      expect(original.equals(copy2)).toBe(true);
      expect(copy1.equals(copy2)).toBe(true);
    });
  });

  describe("Eq/PartialEq Trait", () => {
    it("should provide equality comparison", () => {
      // Eq allows comparing two values for equality
      // This is essential for assertions and deduplication
      const a = createSampleIdentifier();
      const b = Identifier.fromU16(ciphersuite, 42);
      const c = Identifier.fromU16(ciphersuite, 43);

      expect(a.equals(b)).toBe(true);
      expect(a.equals(c)).toBe(false);
    });

    it("should be reflexive (a == a)", () => {
      // Any value should equal itself
      const a = createSampleKeyPackage();
      expect(a.equals(a)).toBe(true);
    });

    it("should be symmetric (a == b implies b == a)", () => {
      // If a equals b, then b should equal a
      const a = createSampleKeyPackage();
      const b = a.clone();
      expect(a.equals(b)).toBe(true);
      expect(b.equals(a)).toBe(true);
    });

    it("should be transitive (a == b && b == c implies a == c)", () => {
      // If a equals b and b equals c, then a should equal c
      const a = createSampleKeyPackage();
      const b = a.clone();
      const c = b.clone();
      expect(a.equals(b)).toBe(true);
      expect(b.equals(c)).toBe(true);
      expect(a.equals(c)).toBe(true);
    });
  });

  describe("Debug Trait", () => {
    it("should provide human-readable string representation", () => {
      // Debug is used for printing values in error messages and logs
      // It should show the structure and contents of the value
      const keyPackage = createSampleKeyPackage();
      const debugStr = keyPackage.toString();

      expect(debugStr).toContain("KeyPackage");
      expect(debugStr.length).toBeGreaterThan(0);
    });

    it("should not have endless recursion", () => {
      // A common mistake is implementing Debug in a way that causes
      // infinite recursion (e.g., when there are circular references)
      // The tests catch this by actually calling the debug method

      // Test all types for no endless recursion
      const types = [
        createSampleIdentifier(),
        createSampleSigningShare(),
        createSampleVerifyingShare(),
        createSampleCoefficientCommitment(),
        createSampleCommitment(),
        createSampleSigningNonces(),
        createSampleSigningCommitments(),
        createSampleSigningPackage(),
        createSampleSignatureShare(),
        createSampleSecretShare(),
        createSampleKeyPackage(),
        createSamplePublicKeyPackage(),
        createSampleRound1Package(),
        createSampleRound1SecretPackage(),
        createSampleRound2Package(),
        createSampleRound2SecretPackage(),
      ];

      for (const value of types) {
        const str = value.toString();
        expect(str.length).toBeGreaterThan(0);
      }
    });

    it("should be required for use in Result::unwrap()", () => {
      // In Rust, Debug is required for types used in Result
      // so that error messages can include the value
      // In TypeScript, toString() serves a similar purpose
      const value = createSampleKeyPackage();
      const result = wrapInResult(value);

      if (!result.ok) {
        // If we had an error, we'd want to print the context
        // which requires toString() to work
        throw new Error(`Failed with: ${value.toString()}`);
      }
    });
  });
});

describe("TypeScript Equivalents", () => {
  it("should understand Rust trait to TypeScript mapping", () => {
    // Rust trait mappings to TypeScript:
    // - Clone -> clone() method
    // - Eq/PartialEq -> equals() method
    // - Debug -> toString() or toDebugString() method
    // - Default -> static default() or constructor with no args
    // - From/Into -> static from() methods or constructor
    // - Serialize/Deserialize -> toJson()/fromJson() or serialize()/deserialize()

    const identifier = createSampleIdentifier();

    // Clone
    const cloned = identifier.clone();
    expect(cloned).not.toBe(identifier);

    // Eq
    expect(identifier.equals(cloned)).toBe(true);

    // Debug
    expect(typeof identifier.toString()).toBe("string");
  });

  it("should implement proper equality semantics", () => {
    // In TypeScript, === only checks reference equality for objects
    // We need explicit equals() methods for value equality
    const a = Identifier.fromU16(ciphersuite, 42);
    const b = Identifier.fromU16(ciphersuite, 42);

    // Reference equality (different objects)
    expect(a === b).toBe(false);

    // Value equality (same values)
    expect(a.equals(b)).toBe(true);
  });

  it("should implement proper cloning semantics", () => {
    // In TypeScript, assignment creates references, not copies
    // We need explicit clone() methods for deep copies
    const a = createSampleKeyPackage();
    const b = a; // b and a are the same object
    const c = a.clone(); // c is a separate copy

    // Reference equality
    expect(a === b).toBe(true);
    expect(a === c).toBe(false);

    // Value equality
    expect(a.equals(b)).toBe(true);
    expect(a.equals(c)).toBe(true);
  });
});
