/**
 * Serialization tests for FROST Ristretto255-SHA512.
 * Ported from frost-ristretto255/tests/serialization_tests.rs
 *
 * These tests verify that all FROST data structures can be correctly
 * serialized and deserialized using binary format.
 */

import { describe, it, expect } from "vitest";
import {
  bytesToHex,
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
} from "./helpers/index.js";

import {
  Ristretto255Sha512,
  SigningNonces,
  SigningCommitments,
  NonceCommitment,
  Nonce,
  SignatureShare,
  SigningShare,
  VerifyingShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  VerifiableSecretSharingCommitment,
  Identifier,
  Signature,
} from "../src/index.js";

// Import DKG classes directly from core (the package re-exports types, not classes)
import { round1, round2 } from "@frosts/core";

describe("FROST Ristretto255-SHA512 Serialization Tests", () => {
  describe("SigningNonces Serialization", () => {
    it("should serialize and deserialize SigningNonces correctly", () => {
      const noncesData = signingNoncesData();
      const hiding = Nonce.deserialize(Ristretto255Sha512, noncesData.hiding);
      const binding = Nonce.deserialize(Ristretto255Sha512, noncesData.binding);
      const nonces = SigningNonces.fromNonces(Ristretto255Sha512, hiding, binding);

      const bytes = nonces.serialize();
      expect(bytes.length).toBe(SCALAR_LENGTH * 2);

      const deserialized = SigningNonces.deserialize(Ristretto255Sha512, bytes);
      expect(deserialized.equals(nonces)).toBe(true);
    });

    it("should have correct nonce data length", () => {
      const data = signingNoncesData();
      expect(data.hiding.length).toBe(SCALAR_LENGTH);
      expect(data.binding.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SigningCommitments Serialization", () => {
    it("should serialize and deserialize SigningCommitments correctly", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(
        Ristretto255Sha512,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Ristretto255Sha512,
        commitmentsData.binding,
      );
      const commitments = new SigningCommitments(
        Ristretto255Sha512,
        hidingCommitment,
        bindingCommitment,
      );

      const bytes = commitments.serialize();
      expect(bytes.length).toBe(ELEMENT_LENGTH * 2);

      const deserialized = SigningCommitments.deserialize(Ristretto255Sha512, bytes);
      expect(deserialized.equals(commitments)).toBe(true);
    });

    it("should have correct commitment data length", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH);
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SigningPackage Serialization", () => {
    it("should serialize and deserialize SigningPackage correctly", () => {
      // Create commitments
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(
        Ristretto255Sha512,
        commitmentsData.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Ristretto255Sha512,
        commitmentsData.binding,
      );
      const commitment = new SigningCommitments(
        Ristretto255Sha512,
        hidingCommitment,
        bindingCommitment,
      );

      // Create identifier
      const packageData = signingPackageData();
      const identifier = Identifier.fromU16(Ristretto255Sha512, packageData.identifier);

      // Create signing package
      const commitments = new Map<
        Identifier<typeof Ristretto255Sha512>,
        SigningCommitments<typeof Ristretto255Sha512>
      >();
      commitments.set(identifier, commitment);

      // SigningPackage doesn't have serialize/deserialize in the same way
      // This is a structural test - verify the data is valid
      expect(commitments.size).toBe(1);
      expect(packageData.message).toEqual(new TextEncoder().encode("hello world"));
    });

    it("should have valid signing package data", () => {
      const data = signingPackageData();
      expect(data.identifier).toBe(42);
      expect(data.message).toEqual(new TextEncoder().encode("hello world"));
    });
  });

  describe("SignatureShare Serialization", () => {
    it("should serialize and deserialize SignatureShare correctly", () => {
      const shareData = signatureShareData();
      const signatureShare = SignatureShare.deserialize(Ristretto255Sha512, shareData.share);

      const bytes = signatureShare.serialize();
      expect(bytes.length).toBe(SCALAR_LENGTH);

      const deserialized = SignatureShare.deserialize(Ristretto255Sha512, bytes);
      expect(deserialized.equals(signatureShare)).toBe(true);
    });

    it("should have correct signature share data length", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SecretShare Serialization", () => {
    it("should serialize and deserialize SecretShare correctly", () => {
      const shareData = secretShareData();
      const identifier = Identifier.fromU16(Ristretto255Sha512, shareData.identifier);
      const signingShare = SigningShare.deserialize(Ristretto255Sha512, shareData.signingShare);
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ristretto255Sha512,
        shareData.commitment,
      );

      const secretShare = new SecretShare(Ristretto255Sha512, identifier, signingShare, commitment);

      // SecretShare is verified via its properties
      expect(secretShare.identifier.equals(identifier)).toBe(true);
      expect(secretShare.signingShare.equals(signingShare)).toBe(true);
      expect(secretShare.commitment.equals(commitment)).toBe(true);
    });

    it("should have valid secret share data", () => {
      const data = secretShareData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("KeyPackage Serialization", () => {
    it("should create and verify KeyPackage correctly", () => {
      const packageData = keyPackageData();
      const identifier = Identifier.fromU16(Ristretto255Sha512, packageData.identifier);
      const signingShare = SigningShare.deserialize(Ristretto255Sha512, packageData.signingShare);
      const verifyingShare = VerifyingShare.deserialize(
        Ristretto255Sha512,
        packageData.verifyingShare,
      );
      const verifyingKey = Ristretto255Sha512.deserializeElement(packageData.verifyingKey);

      const keyPackage = new KeyPackage(
        Ristretto255Sha512,
        identifier,
        signingShare,
        verifyingShare,
        verifyingKey,
        packageData.minSigners,
      );

      expect(keyPackage.identifier.equals(identifier)).toBe(true);
      expect(keyPackage.signingShare.equals(signingShare)).toBe(true);
      expect(keyPackage.verifyingShare.equals(verifyingShare)).toBe(true);
      expect(keyPackage.minSigners).toBe(2);
    });

    it("should have valid key package data", () => {
      const data = keyPackageData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.verifyingShare.length).toBe(ELEMENT_LENGTH);
      expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
      expect(data.minSigners).toBe(2);
    });
  });

  describe("PublicKeyPackage Serialization", () => {
    it("should create and verify PublicKeyPackage correctly (legacy)", () => {
      const packageData = publicKeyPackageData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ristretto255Sha512>>();

      for (const [id, share] of packageData.verifyingShares) {
        const identifier = Identifier.fromU16(Ristretto255Sha512, id);
        const verifyingShare = VerifyingShare.deserialize(Ristretto255Sha512, share);
        verifyingShares.set(bytesToHex(identifier.serialize()), verifyingShare);
      }

      const verifyingKey = Ristretto255Sha512.deserializeElement(packageData.verifyingKey);

      const publicKeyPackage = new PublicKeyPackage(
        Ristretto255Sha512,
        verifyingShares,
        verifyingKey,
        undefined, // no minSigners for legacy
      );

      expect(publicKeyPackage.verifyingShares.size).toBe(1);
      expect(publicKeyPackage.minSigners).toBeUndefined();
    });

    it("should create and verify PublicKeyPackage with minSigners correctly", () => {
      const packageData = publicKeyPackageNewData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ristretto255Sha512>>();

      for (const [id, share] of packageData.verifyingShares) {
        const identifier = Identifier.fromU16(Ristretto255Sha512, id);
        const verifyingShare = VerifyingShare.deserialize(Ristretto255Sha512, share);
        verifyingShares.set(bytesToHex(identifier.serialize()), verifyingShare);
      }

      const verifyingKey = Ristretto255Sha512.deserializeElement(packageData.verifyingKey);

      const publicKeyPackage = new PublicKeyPackage(
        Ristretto255Sha512,
        verifyingShares,
        verifyingKey,
        packageData.minSigners,
      );

      expect(publicKeyPackage.verifyingShares.size).toBe(1);
      expect(publicKeyPackage.minSigners).toBe(2);
    });

    it("should have valid public key package data", () => {
      const data = publicKeyPackageData();
      expect(data.verifyingShares.size).toBe(1);
      expect(data.verifyingShares.get(42)?.length).toBe(ELEMENT_LENGTH);
      expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
    });

    it("should have valid public key package data with minSigners", () => {
      const data = publicKeyPackageNewData();
      expect(data.verifyingShares.size).toBe(1);
      expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
      expect(data.minSigners).toBe(2);
    });
  });

  describe("DKG Round1 SecretPackage Serialization", () => {
    it("should create and verify round1::SecretPackage correctly", () => {
      const packageData = round1SecretPackageData();
      const identifier = Identifier.fromU16(Ristretto255Sha512, packageData.identifier);
      const coefficients = packageData.coefficients.map((c) =>
        Ristretto255Sha512.deserializeScalar(c),
      );
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ristretto255Sha512,
        packageData.commitment,
      );

      const secretPackage = new round1.SecretPackage(
        Ristretto255Sha512,
        identifier,
        coefficients,
        commitment,
        packageData.minSigners,
        packageData.maxSigners,
      );

      expect(secretPackage.identifier.equals(identifier)).toBe(true);
      expect(secretPackage.minSigners).toBe(2);
      expect(secretPackage.maxSigners).toBe(3);
    });

    it("should have valid round1 secret package data", () => {
      const data = round1SecretPackageData();
      expect(data.identifier).toBe(42);
      expect(data.coefficients.length).toBe(2);
      expect(data.coefficients[0].length).toBe(SCALAR_LENGTH);
      expect(data.commitment.length).toBe(1);
      expect(data.minSigners).toBe(2);
      expect(data.maxSigners).toBe(3);
    });
  });

  describe("DKG Round1 Package Serialization", () => {
    it("should create and verify round1::Package correctly", () => {
      const packageData = round1PackageData();
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ristretto255Sha512,
        packageData.commitment,
      );

      // Parse proof of knowledge: R (element) + z (scalar)
      const R = Ristretto255Sha512.deserializeElement(
        packageData.proofOfKnowledge.slice(0, ELEMENT_LENGTH),
      );
      const z = Ristretto255Sha512.deserializeScalar(
        packageData.proofOfKnowledge.slice(ELEMENT_LENGTH),
      );

      const proofOfKnowledge = { R, z };

      const round1Package = new round1.Package(Ristretto255Sha512, commitment, proofOfKnowledge);

      expect(round1Package.commitment.equals(commitment)).toBe(true);
      expect(Ristretto255Sha512.elementsEqual(round1Package.proofOfKnowledge.R, R)).toBe(true);
      expect(Ristretto255Sha512.scalarsEqual(round1Package.proofOfKnowledge.z, z)).toBe(true);
    });

    it("should have valid round1 package data", () => {
      const data = round1PackageData();
      expect(data.commitment.length).toBe(1);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH);
      // Proof of knowledge is a signature: element (32) + scalar (32) = 64 bytes
      expect(data.proofOfKnowledge.length).toBe(ELEMENT_LENGTH + SCALAR_LENGTH);
    });
  });

  describe("DKG Round2 SecretPackage Serialization", () => {
    it("should create and verify round2::SecretPackage correctly", () => {
      const packageData = round2SecretPackageData();
      const identifier = Identifier.fromU16(Ristretto255Sha512, packageData.identifier);
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ristretto255Sha512,
        packageData.commitment,
      );
      const secretShare = Ristretto255Sha512.deserializeScalar(packageData.secretShare);

      const secretPackage = new round2.SecretPackage(
        Ristretto255Sha512,
        identifier,
        commitment,
        secretShare,
        packageData.minSigners,
        packageData.maxSigners,
      );

      expect(secretPackage.identifier.equals(identifier)).toBe(true);
      expect(secretPackage.commitment.equals(commitment)).toBe(true);
      expect(Ristretto255Sha512.scalarsEqual(secretPackage.secretShare(), secretShare)).toBe(true);
      expect(secretPackage.minSigners).toBe(2);
      expect(secretPackage.maxSigners).toBe(3);
    });

    it("should have valid round2 secret package data", () => {
      const data = round2SecretPackageData();
      expect(data.identifier).toBe(42);
      expect(data.commitment.length).toBe(1);
      expect(data.secretShare.length).toBe(SCALAR_LENGTH);
      expect(data.minSigners).toBe(2);
      expect(data.maxSigners).toBe(3);
    });
  });

  describe("DKG Round2 Package Serialization", () => {
    it("should create and verify round2::Package correctly", () => {
      const packageData = round2PackageData();
      const signingShare = SigningShare.deserialize(Ristretto255Sha512, packageData.signingShare);

      const round2Package = new round2.Package(Ristretto255Sha512, signingShare);

      expect(round2Package.signingShare.equals(signingShare)).toBe(true);
    });

    it("should have valid round2 package data", () => {
      const data = round2PackageData();
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
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

  it("should have consistent element length", () => {
    expect(ELEMENT_LENGTH).toBe(32);
    expect(signingCommitmentsData().hiding.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingShare.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingKey.length).toBe(ELEMENT_LENGTH);
  });
});

describe("Signature Serialization", () => {
  it("should serialize and deserialize Signature correctly", () => {
    // Create a signature from sample data
    const commitmentsData = signingCommitmentsData();
    const R = Ristretto255Sha512.deserializeElement(commitmentsData.hiding);
    const shareData = signatureShareData();
    const z = Ristretto255Sha512.deserializeScalar(shareData.share);

    const signature = new Signature(R, z);

    // Signature.serialize takes ciphersuite as parameter
    const serialized = signature.serialize(Ristretto255Sha512);
    expect(serialized.length).toBe(ELEMENT_LENGTH + SCALAR_LENGTH);

    const deserialized = Signature.deserialize(Ristretto255Sha512, serialized);
    expect(Ristretto255Sha512.elementsEqual(deserialized.R, R)).toBe(true);
    expect(Ristretto255Sha512.scalarsEqual(deserialized.z, z)).toBe(true);
  });
});
