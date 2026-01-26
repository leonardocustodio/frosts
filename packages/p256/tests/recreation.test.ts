/**
 * Recreation tests for FROST P256-SHA256.
 * Ported from frost-p256/tests/recreation_tests.rs
 *
 * These tests verify that packages can be recreated from their components,
 * which demonstrates that they can be serialized and deserialized as the
 * user wishes (e.g., using custom serialization formats).
 *
 * Key differences from secp256k1:
 * - Uses P-256 curve constants
 * - Same byte lengths: ELEMENT_LENGTH = 33, SIGNATURE_LENGTH = 65
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  signingNoncesData,
  signingCommitmentsData,
  signingPackageData,
  signatureShareData,
  secretShareData,
  keyPackageData,
  publicKeyPackageData as _publicKeyPackageData,
  publicKeyPackageNewData,
  round1SecretPackageData,
  round1PackageData,
  round2SecretPackageData,
  round2PackageData,
  SCALAR_LENGTH,
  ELEMENT_LENGTH,
  SIGNATURE_LENGTH,
  createSecureRng,
  type CryptoRng,
} from "./helpers/index.js";

import {
  P256Sha256,
  SigningCommitments,
  SignatureShare,
  Identifier,
  NonceCommitment,
  Nonce,
  SigningNonces,
} from "../src/index.js";

describe("FROST P256-SHA256 Recreation Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("SigningNonces Recreation", () => {
    it("should recreate SigningNonces from component nonces", () => {
      // Create original nonces
      const hidingScalar = P256Sha256.scalarRandom(rng);
      const bindingScalar = P256Sha256.scalarRandom(rng);

      const hidingNonce = Nonce.fromScalar(P256Sha256, hidingScalar);
      const bindingNonce = Nonce.fromScalar(P256Sha256, bindingScalar);

      const original = SigningNonces.fromNonces(P256Sha256, hidingNonce, bindingNonce);

      // Extract components and recreate
      const extractedHiding = original.hiding;
      const extractedBinding = original.binding;

      const recreated = SigningNonces.fromNonces(P256Sha256, extractedHiding, extractedBinding);

      // Verify equality through commitments
      const originalCommitments = original.commitments;
      const recreatedCommitments = recreated.commitments;

      expect(
        P256Sha256.elementsEqual(
          originalCommitments.hiding.toElement(),
          recreatedCommitments.hiding.toElement(),
        ),
      ).toBe(true);
      expect(
        P256Sha256.elementsEqual(
          originalCommitments.binding.toElement(),
          recreatedCommitments.binding.toElement(),
        ),
      ).toBe(true);
    });

    it("should have extractable nonce components", () => {
      const data = signingNoncesData();
      expect(data.hiding.length).toBe(SCALAR_LENGTH);
      expect(data.binding.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SigningCommitments Recreation", () => {
    it("should recreate SigningCommitments from component commitments", () => {
      // Create original commitments
      const scalar1 = P256Sha256.scalarRandom(rng);
      const scalar2 = P256Sha256.scalarRandom(rng);
      const hidingElement = P256Sha256.scalarBaseMult(scalar1);
      const bindingElement = P256Sha256.scalarBaseMult(scalar2);

      const hidingCommitment = NonceCommitment.fromElement(P256Sha256, hidingElement);
      const bindingCommitment = NonceCommitment.fromElement(P256Sha256, bindingElement);

      const original = new SigningCommitments(P256Sha256, hidingCommitment, bindingCommitment);

      // Extract components and recreate
      const extractedHiding = original.hiding;
      const extractedBinding = original.binding;

      const recreated = new SigningCommitments(P256Sha256, extractedHiding, extractedBinding);

      // Verify equality
      expect(
        P256Sha256.elementsEqual(original.hiding.toElement(), recreated.hiding.toElement()),
      ).toBe(true);
      expect(
        P256Sha256.elementsEqual(original.binding.toElement(), recreated.binding.toElement()),
      ).toBe(true);
    });

    it("should have extractable commitment components", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH); // 33 bytes for P256
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SignatureShare Recreation", () => {
    it("should recreate SignatureShare via serialization", () => {
      const scalar = P256Sha256.scalarRandom(rng);
      const original = SignatureShare.fromScalar(P256Sha256, scalar);

      // Serialize and deserialize
      const bytes = original.serialize();
      const recreated = SignatureShare.deserialize(P256Sha256, bytes);

      expect(P256Sha256.scalarsEqual(original.toScalar(), recreated.toScalar())).toBe(true);
    });

    it("should have serializable share data", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("Identifier Recreation", () => {
    it("should recreate Identifier from serialized form", () => {
      const original = Identifier.fromU16(P256Sha256, 42);

      // Serialize and deserialize
      const bytes = original.serialize();
      const recreated = Identifier.deserialize(P256Sha256, bytes);

      expect(original.compare(recreated)).toBe(0);
    });

    it("should have extractable identifier components", () => {
      const id = Identifier.fromU16(P256Sha256, 42);
      const scalar = id.toScalar();
      expect(scalar).toBeDefined();
      expect(scalar.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("NonceCommitment Recreation", () => {
    it("should recreate NonceCommitment from element", () => {
      const scalar = P256Sha256.scalarRandom(rng);
      const element = P256Sha256.scalarBaseMult(scalar);
      const original = NonceCommitment.fromElement(P256Sha256, element);

      // Extract element and recreate
      const extractedElement = original.toElement();
      const recreated = NonceCommitment.fromElement(P256Sha256, extractedElement);

      expect(P256Sha256.elementsEqual(original.toElement(), recreated.toElement())).toBe(true);
    });
  });
});

describe("Recreation Data Validation", () => {
  it("should have valid signing package data", () => {
    const data = signingPackageData();
    expect(data.identifier).toBe(42);
    expect(data.commitments.hiding.length).toBe(ELEMENT_LENGTH);
    expect(data.message.length).toBeGreaterThan(0);
  });

  it("should have valid secret share data", () => {
    const data = secretShareData();
    expect(data.identifier).toBe(42);
    expect(data.signingShare.length).toBe(SCALAR_LENGTH);
    expect(data.commitment.length).toBeGreaterThan(0);
  });

  it("should have valid key package data", () => {
    const data = keyPackageData();
    expect(data.identifier).toBe(42);
    expect(data.signingShare.length).toBe(SCALAR_LENGTH);
    expect(data.verifyingShare.length).toBe(ELEMENT_LENGTH);
    expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
    expect(data.minSigners).toBe(2);
  });

  it("should have valid public key package data", () => {
    const data = publicKeyPackageNewData();
    expect(data.verifyingShares.size).toBe(1);
    expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
    expect(data.minSigners).toBe(2);
  });

  it("should have valid round1 secret package data", () => {
    const data = round1SecretPackageData();
    expect(data.identifier).toBe(42);
    expect(data.coefficients.length).toBe(2);
    expect(data.commitment.length).toBeGreaterThan(0);
    expect(data.minSigners).toBe(2);
    expect(data.maxSigners).toBe(3);
  });

  it("should have valid round1 package data", () => {
    const data = round1PackageData();
    expect(data.commitment.length).toBeGreaterThan(0);
    expect(data.proofOfKnowledge.length).toBe(SIGNATURE_LENGTH); // 65 bytes for P256
  });

  it("should have valid round2 secret package data", () => {
    const data = round2SecretPackageData();
    expect(data.identifier).toBe(42);
    expect(data.commitment.length).toBeGreaterThan(0);
    expect(data.secretShare.length).toBe(SCALAR_LENGTH);
    expect(data.minSigners).toBe(2);
    expect(data.maxSigners).toBe(3);
  });

  it("should have valid round2 package data", () => {
    const data = round2PackageData();
    expect(data.signingShare.length).toBe(SCALAR_LENGTH);
  });
});

describe("Recreation Principles", () => {
  it("should demonstrate component extraction and reconstruction pattern", () => {
    // The recreation tests demonstrate that all FROST data structures
    // can be broken down into their component parts and reconstructed.
    //
    // This is important for:
    // 1. Custom serialization formats (not just postcard)
    // 2. Storing components in databases
    // 3. Transmitting components over different protocols
    // 4. Interoperability with other implementations
    const rng = createSecureRng();
    const scalar = P256Sha256.scalarRandom(rng);
    const share = SignatureShare.fromScalar(P256Sha256, scalar);

    // Extract scalar
    const extracted = share.toScalar();

    // Recreate from scalar
    const recreated = SignatureShare.fromScalar(P256Sha256, extracted);

    expect(P256Sha256.scalarsEqual(share.toScalar(), recreated.toScalar())).toBe(true);
  });

  it("should maintain equality after recreation", () => {
    // All recreation tests verify that:
    // original == recreated
    //
    // This ensures no information is lost during the extraction
    // and reconstruction process.
    const rng = createSecureRng();
    void rng; // Available for future tests requiring randomness
    const id = Identifier.fromU16(P256Sha256, 123);
    const bytes = id.serialize();
    const recreated = Identifier.deserialize(P256Sha256, bytes);

    expect(id.compare(recreated)).toBe(0);
  });
});
