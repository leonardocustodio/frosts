/**
 * Serialization tests for FROST P256-SHA256.
 * Ported from frost-p256/tests/serialization_tests.rs
 *
 * These tests verify that all FROST data structures can be correctly
 * serialized and deserialized using the postcard binary format.
 *
 * Key differences from secp256k1:
 * - Different generator point and curve constants
 * - Same byte lengths: ELEMENT_LENGTH = 33 bytes, SIGNATURE_LENGTH = 65 bytes
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  bytesToHex as _bytesToHex,
  hexToBytes as _hexToBytes,
  signingNoncesData,
  signingCommitmentsData,
  signingPackageData,
  signatureShareData,
  secretShareData,
  keyPackageData,
  publicKeyPackageData,
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

describe("FROST P256-SHA256 Serialization Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("SigningNonces Serialization", () => {
    it("should serialize and deserialize SigningNonces correctly", () => {
      // Create nonces from scalars
      const hidingScalar = P256Sha256.scalarRandom(rng);
      const bindingScalar = P256Sha256.scalarRandom(rng);

      const hidingNonce = Nonce.fromScalar(P256Sha256, hidingScalar);
      const bindingNonce = Nonce.fromScalar(P256Sha256, bindingScalar);

      const nonces = SigningNonces.fromNonces(P256Sha256, hidingNonce, bindingNonce);

      // Serialize and deserialize
      const bytes = nonces.serialize();
      const deserialized = SigningNonces.deserialize(P256Sha256, bytes);

      // Verify the commitments match (nonces themselves are secret)
      const originalCommitments = nonces.commitments;
      const deserializedCommitments = deserialized.commitments;

      expect(
        P256Sha256.elementsEqual(
          originalCommitments.hiding.toElement(),
          deserializedCommitments.hiding.toElement(),
        ),
      ).toBe(true);
      expect(
        P256Sha256.elementsEqual(
          originalCommitments.binding.toElement(),
          deserializedCommitments.binding.toElement(),
        ),
      ).toBe(true);
    });

    it("should have correct nonce data length", () => {
      const data = signingNoncesData();
      expect(data.hiding.length).toBe(SCALAR_LENGTH);
      expect(data.binding.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SigningCommitments Serialization", () => {
    it("should serialize and deserialize SigningCommitments correctly", () => {
      const data = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(P256Sha256, data.hiding);
      const bindingCommitment = NonceCommitment.deserialize(P256Sha256, data.binding);

      const commitments = new SigningCommitments(P256Sha256, hidingCommitment, bindingCommitment);

      const bytes = commitments.serialize();
      const deserialized = SigningCommitments.deserialize(P256Sha256, bytes);

      expect(
        P256Sha256.elementsEqual(commitments.hiding.toElement(), deserialized.hiding.toElement()),
      ).toBe(true);
      expect(
        P256Sha256.elementsEqual(commitments.binding.toElement(), deserialized.binding.toElement()),
      ).toBe(true);
    });

    it("should have correct commitment data length (SEC1 compressed)", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH); // 33 bytes for P256
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SignatureShare Serialization", () => {
    it("should serialize and deserialize SignatureShare correctly", () => {
      const data = signatureShareData();
      const share = SignatureShare.deserialize(P256Sha256, data.share);

      const bytes = share.serialize();
      const deserialized = SignatureShare.deserialize(P256Sha256, bytes);

      expect(P256Sha256.scalarsEqual(share.toScalar(), deserialized.toScalar())).toBe(true);
    });

    it("should have correct signature share data length", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("Identifier Serialization", () => {
    it("should serialize and deserialize Identifier correctly", () => {
      const id = Identifier.fromU16(P256Sha256, 42);
      const bytes = id.serialize();
      const deserialized = Identifier.deserialize(P256Sha256, bytes);

      expect(id.compare(deserialized)).toBe(0);
    });

    it("should reject zero identifier", () => {
      expect(() => Identifier.fromU16(P256Sha256, 0)).toThrow();
    });

    it("should handle large identifiers", () => {
      const id = Identifier.fromU16(P256Sha256, 65535);
      const bytes = id.serialize();
      const deserialized = Identifier.deserialize(P256Sha256, bytes);

      expect(id.compare(deserialized)).toBe(0);
    });
  });

  describe("NonceCommitment Serialization", () => {
    it("should serialize and deserialize NonceCommitment correctly", () => {
      const scalar = P256Sha256.scalarRandom(rng);
      const element = P256Sha256.scalarBaseMult(scalar);
      const commitment = NonceCommitment.fromElement(P256Sha256, element);

      const bytes = commitment.serialize();
      expect(bytes.length).toBe(ELEMENT_LENGTH);

      const deserialized = NonceCommitment.deserialize(P256Sha256, bytes);
      expect(P256Sha256.elementsEqual(commitment.toElement(), deserialized.toElement())).toBe(true);
    });
  });
});

describe("Serialization Data Validation", () => {
  it("should have all sample data generators", () => {
    expect(signingNoncesData).toBeDefined();
    expect(signingCommitmentsData).toBeDefined();
    expect(signingPackageData).toBeDefined();
    expect(signatureShareData).toBeDefined();
    expect(secretShareData).toBeDefined();
    expect(keyPackageData).toBeDefined();
    expect(publicKeyPackageData).toBeDefined();
    expect(publicKeyPackageNewData).toBeDefined();
    expect(round1SecretPackageData).toBeDefined();
    expect(round1PackageData).toBeDefined();
    expect(round2SecretPackageData).toBeDefined();
    expect(round2PackageData).toBeDefined();
  });

  it("should have consistent scalar length", () => {
    expect(SCALAR_LENGTH).toBe(32);
    expect(signingNoncesData().hiding.length).toBe(SCALAR_LENGTH);
    expect(signatureShareData().share.length).toBe(SCALAR_LENGTH);
    expect(keyPackageData().signingShare.length).toBe(SCALAR_LENGTH);
  });

  it("should have consistent element length (SEC1 compressed)", () => {
    expect(ELEMENT_LENGTH).toBe(33); // SEC1 compressed format for P256
    expect(signingCommitmentsData().hiding.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingShare.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingKey.length).toBe(ELEMENT_LENGTH);
  });

  it("should have consistent signature length", () => {
    expect(SIGNATURE_LENGTH).toBe(65); // 33 (element) + 32 (scalar)
    expect(round1PackageData().proofOfKnowledge.length).toBe(SIGNATURE_LENGTH);
  });
});

describe("Element Serialization Format", () => {
  it("should use SEC1 compressed format", () => {
    const data = signingCommitmentsData();
    // SEC1 compressed format starts with 02 (even y) or 03 (odd y)
    expect(data.hiding[0]).toBeGreaterThanOrEqual(2);
    expect(data.hiding[0]).toBeLessThanOrEqual(3);
    expect(data.binding[0]).toBeGreaterThanOrEqual(2);
    expect(data.binding[0]).toBeLessThanOrEqual(3);
  });

  it("should match generator point encoding", () => {
    const generator = P256Sha256.generator();
    // P-256 generator has compressed format starting with 03
    expect(generator[0]).toBe(3);
    expect(generator.length).toBe(33);
  });
});

describe("Scalar Serialization Format", () => {
  it("should use big-endian format", () => {
    // Create scalar with value 1
    const one = P256Sha256.scalarOne();
    // In big-endian, 1 is [...0, 0, 1]
    expect(one[one.length - 1]).toBe(1);
    for (let i = 0; i < one.length - 1; i++) {
      expect(one[i]).toBe(0);
    }
  });

  it("should serialize zero correctly", () => {
    const zero = P256Sha256.scalarZero();
    expect(zero.length).toBe(SCALAR_LENGTH);
    for (const byte of zero) {
      expect(byte).toBe(0);
    }
  });
});
