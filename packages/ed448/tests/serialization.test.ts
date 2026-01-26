/**
 * Serialization tests for FROST Ed448-SHAKE256.
 * Ported from frost-ed448/tests/serialization_tests.rs
 *
 * These tests verify that all FROST data structures can be correctly
 * serialized and deserialized. Tests use component-level serialization
 * since FROST types support serializing/deserializing their inner components.
 */

import { describe, it, expect } from "vitest";
import {
  bytesToHex,
  hexToBytes,
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
  Ed448Shake256,
  SigningNonces,
  SigningCommitments,
  NonceCommitment,
  Nonce,
  SignatureShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  SigningShare,
  VerifyingShare,
  VerifiableSecretSharingCommitment,
  Identifier,
  Signature,
} from "../src/index.js";

// Import DKG classes directly from @frosts/core
import { round1, round2 } from "@frosts/core";

describe("FROST Ed448-SHAKE256 Serialization Tests", () => {
  describe("SigningNonces Serialization", () => {
    it("should serialize and deserialize SigningNonces correctly", () => {
      // Ported from: check_signing_nonces_postcard_serialization
      const noncesData = signingNoncesData();
      const hidingNonce = Nonce.deserialize(Ed448Shake256, noncesData.hiding);
      const bindingNonce = Nonce.deserialize(Ed448Shake256, noncesData.binding);
      const nonces = SigningNonces.fromNonces(Ed448Shake256, hidingNonce, bindingNonce);

      const bytes = nonces.serialize();
      const deserialized = SigningNonces.deserialize(Ed448Shake256, bytes);

      expect(nonces.equals(deserialized)).toBe(true);
    });

    it("should have correct nonce data length", () => {
      const data = signingNoncesData();
      expect(data.hiding.length).toBe(SCALAR_LENGTH);
      expect(data.binding.length).toBe(SCALAR_LENGTH);
    });

    it("should produce expected serialization format", () => {
      const noncesData = signingNoncesData();
      const hidingNonce = Nonce.deserialize(Ed448Shake256, noncesData.hiding);
      const bindingNonce = Nonce.deserialize(Ed448Shake256, noncesData.binding);
      const nonces = SigningNonces.fromNonces(Ed448Shake256, hidingNonce, bindingNonce);

      const bytes = nonces.serialize();
      // Serialization should contain both nonces (hiding + binding)
      expect(bytes.length).toBe(SCALAR_LENGTH * 2);
    });
  });

  describe("SigningCommitments Serialization", () => {
    it("should serialize and deserialize SigningCommitments correctly", () => {
      // Ported from: check_signing_commitments_postcard_serialization
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(Ed448Shake256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(Ed448Shake256, commitmentsData.binding);
      const commitments = new SigningCommitments(
        Ed448Shake256,
        hidingCommitment,
        bindingCommitment,
      );

      const bytes = commitments.serialize();
      const deserialized = SigningCommitments.deserialize(Ed448Shake256, bytes);

      expect(commitments.equals(deserialized)).toBe(true);
    });

    it("should have correct commitment data length", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH);
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });

    it("should produce expected serialization format", () => {
      const commitmentsData = signingCommitmentsData();
      const hidingCommitment = NonceCommitment.deserialize(Ed448Shake256, commitmentsData.hiding);
      const bindingCommitment = NonceCommitment.deserialize(Ed448Shake256, commitmentsData.binding);
      const commitments = new SigningCommitments(
        Ed448Shake256,
        hidingCommitment,
        bindingCommitment,
      );

      const bytes = commitments.serialize();
      // Serialization should contain both commitments (hiding + binding)
      expect(bytes.length).toBe(ELEMENT_LENGTH * 2);
    });
  });

  describe("SigningPackage Serialization", () => {
    it("should preserve signing package components through serialization", () => {
      // SigningPackage serialization tests component preservation
      const packageData = signingPackageData();
      const hidingCommitment = NonceCommitment.deserialize(
        Ed448Shake256,
        packageData.commitments.hiding,
      );
      const bindingCommitment = NonceCommitment.deserialize(
        Ed448Shake256,
        packageData.commitments.binding,
      );
      const commitments = new SigningCommitments(
        Ed448Shake256,
        hidingCommitment,
        bindingCommitment,
      );

      const identifier = Identifier.fromU16(Ed448Shake256, packageData.identifier);

      // Verify commitment serialization roundtrip
      const serializedCommitments = commitments.serialize();
      const deserializedCommitments = SigningCommitments.deserialize(
        Ed448Shake256,
        serializedCommitments,
      );
      expect(commitments.equals(deserializedCommitments)).toBe(true);

      // Verify identifier serialization roundtrip
      const serializedId = identifier.serialize();
      const deserializedId = Identifier.deserialize(Ed448Shake256, serializedId);
      expect(identifier.equals(deserializedId)).toBe(true);
    });

    it("should have valid signing package data", () => {
      const data = signingPackageData();
      expect(data.identifier).toBe(42);
      expect(data.message).toEqual(new TextEncoder().encode("hello world"));
    });
  });

  describe("SignatureShare Serialization", () => {
    it("should serialize and deserialize SignatureShare correctly", () => {
      // Ported from: check_signature_share_postcard_serialization
      const shareData = signatureShareData();
      const signatureShare = SignatureShare.deserialize(Ed448Shake256, shareData.share);

      const bytes = signatureShare.serialize();
      const deserialized = SignatureShare.deserialize(Ed448Shake256, bytes);

      expect(signatureShare.equals(deserialized)).toBe(true);
    });

    it("should have correct signature share data length", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });

    it("should produce expected serialization format", () => {
      const shareData = signatureShareData();
      const signatureShare = SignatureShare.deserialize(Ed448Shake256, shareData.share);

      const bytes = signatureShare.serialize();
      expect(bytes.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SecretShare Serialization", () => {
    it("should serialize and deserialize SecretShare components correctly", () => {
      // Ported from: check_secret_share_postcard_serialization
      // SecretShare uses component-level serialization
      const shareData = secretShareData();
      const identifier = Identifier.fromU16(Ed448Shake256, shareData.identifier);
      const signingShare = SigningShare.deserialize(Ed448Shake256, shareData.signingShare);
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed448Shake256,
        shareData.commitment,
      );

      const secretShare = new SecretShare(Ed448Shake256, identifier, signingShare, commitment);

      // Verify component roundtrips
      const idBytes = secretShare.identifier.serialize();
      const deserializedId = Identifier.deserialize(Ed448Shake256, idBytes);
      expect(secretShare.identifier.equals(deserializedId)).toBe(true);

      const shareBytes = secretShare.signingShare.serialize();
      const deserializedShare = SigningShare.deserialize(Ed448Shake256, shareBytes);
      expect(secretShare.signingShare.equals(deserializedShare)).toBe(true);

      const commitmentBytes = secretShare.commitment.serializeWhole();
      const deserializedCommitment = VerifiableSecretSharingCommitment.deserialize(Ed448Shake256, [
        commitmentBytes,
      ]);
      expect(secretShare.commitment.equals(deserializedCommitment)).toBe(true);

      // Verify recreation from components
      const recreated = new SecretShare(
        Ed448Shake256,
        deserializedId,
        deserializedShare,
        deserializedCommitment,
      );
      expect(secretShare.equals(recreated)).toBe(true);
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
    it("should serialize and deserialize KeyPackage components correctly", () => {
      // Ported from: check_key_package_postcard_serialization
      // KeyPackage uses component-level serialization
      const packageData = keyPackageData();
      const identifier = Identifier.fromU16(Ed448Shake256, packageData.identifier);
      const signingShare = SigningShare.deserialize(Ed448Shake256, packageData.signingShare);
      const verifyingShare = VerifyingShare.deserialize(Ed448Shake256, packageData.verifyingShare);
      const verifyingKey = Ed448Shake256.deserializeElement(packageData.verifyingKey);

      const keyPackage = new KeyPackage(
        Ed448Shake256,
        identifier,
        signingShare,
        verifyingShare,
        verifyingKey,
        packageData.minSigners,
      );

      // Verify component roundtrips
      const idBytes = keyPackage.identifier.serialize();
      const deserializedId = Identifier.deserialize(Ed448Shake256, idBytes);
      expect(keyPackage.identifier.equals(deserializedId)).toBe(true);

      const shareBytes = keyPackage.signingShare.serialize();
      const deserializedShare = SigningShare.deserialize(Ed448Shake256, shareBytes);
      expect(keyPackage.signingShare.equals(deserializedShare)).toBe(true);

      const vShareBytes = keyPackage.verifyingShare.serialize();
      const deserializedVShare = VerifyingShare.deserialize(Ed448Shake256, vShareBytes);
      expect(keyPackage.verifyingShare.equals(deserializedVShare)).toBe(true);

      const vKeyBytes = Ed448Shake256.serializeElement(keyPackage.verifyingKey);
      const deserializedVKey = Ed448Shake256.deserializeElement(vKeyBytes);
      expect(Ed448Shake256.elementsEqual(keyPackage.verifyingKey, deserializedVKey)).toBe(true);

      // Verify recreation from components
      const recreated = new KeyPackage(
        Ed448Shake256,
        deserializedId,
        deserializedShare,
        deserializedVShare,
        deserializedVKey,
        keyPackage.minSigners,
      );
      expect(keyPackage.equals(recreated)).toBe(true);
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
    it("should serialize and deserialize PublicKeyPackage components correctly (legacy)", () => {
      // Ported from: check_public_key_package_postcard_serialization
      const packageData = publicKeyPackageData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ed448Shake256>>();
      for (const [id, share] of packageData.verifyingShares) {
        const identifier = Identifier.fromU16(Ed448Shake256, id);
        const idKey = bytesToHex(identifier.serialize());
        verifyingShares.set(idKey, VerifyingShare.deserialize(Ed448Shake256, share));
      }
      const verifyingKey = Ed448Shake256.deserializeElement(packageData.verifyingKey);

      const publicKeyPackage = new PublicKeyPackage(
        Ed448Shake256,
        verifyingShares,
        verifyingKey,
        undefined,
      );

      // Verify verifying key roundtrip
      const vKeyBytes = Ed448Shake256.serializeElement(publicKeyPackage.verifyingKey);
      const deserializedVKey = Ed448Shake256.deserializeElement(vKeyBytes);
      expect(Ed448Shake256.elementsEqual(publicKeyPackage.verifyingKey, deserializedVKey)).toBe(
        true,
      );

      // Verify verifying shares roundtrip
      for (const [_idKey, share] of publicKeyPackage.verifyingShares) {
        const shareBytes = share.serialize();
        const deserializedShare = VerifyingShare.deserialize(Ed448Shake256, shareBytes);
        expect(share.equals(deserializedShare)).toBe(true);
      }
    });

    it("should serialize and deserialize PublicKeyPackage components with minSigners correctly", () => {
      // Ported from: check_public_key_package_new_postcard_serialization
      const packageData = publicKeyPackageNewData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ed448Shake256>>();
      for (const [id, share] of packageData.verifyingShares) {
        const identifier = Identifier.fromU16(Ed448Shake256, id);
        const idKey = bytesToHex(identifier.serialize());
        verifyingShares.set(idKey, VerifyingShare.deserialize(Ed448Shake256, share));
      }
      const verifyingKey = Ed448Shake256.deserializeElement(packageData.verifyingKey);

      const publicKeyPackage = new PublicKeyPackage(
        Ed448Shake256,
        verifyingShares,
        verifyingKey,
        packageData.minSigners,
      );

      // Verify minSigners is preserved
      expect(publicKeyPackage.minSigners).toBe(packageData.minSigners);

      // Verify verifying key roundtrip
      const vKeyBytes = Ed448Shake256.serializeElement(publicKeyPackage.verifyingKey);
      const deserializedVKey = Ed448Shake256.deserializeElement(vKeyBytes);
      expect(Ed448Shake256.elementsEqual(publicKeyPackage.verifyingKey, deserializedVKey)).toBe(
        true,
      );
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
    it("should serialize and deserialize round1::SecretPackage components correctly", () => {
      // Ported from: check_round1_secret_package_postcard_serialization
      const packageData = round1SecretPackageData();
      const identifier = Identifier.fromU16(Ed448Shake256, packageData.identifier);
      const coefficients = packageData.coefficients.map((c) => Ed448Shake256.deserializeScalar(c));
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed448Shake256,
        packageData.commitment,
      );

      const round1SecretPackage = new round1.SecretPackage(
        Ed448Shake256,
        identifier,
        coefficients,
        commitment,
        packageData.minSigners,
        packageData.maxSigners,
      );

      // Verify component roundtrips
      const idBytes = round1SecretPackage.identifier.serialize();
      const deserializedId = Identifier.deserialize(Ed448Shake256, idBytes);
      expect(round1SecretPackage.identifier.equals(deserializedId)).toBe(true);

      const extractedCoeffs = round1SecretPackage.coefficients();
      const coeffBytes = extractedCoeffs.map((c) => Ed448Shake256.serializeScalar(c));
      const deserializedCoeffs = coeffBytes.map((b) => Ed448Shake256.deserializeScalar(b));
      for (let i = 0; i < extractedCoeffs.length; i++) {
        expect(Ed448Shake256.scalarsEqual(extractedCoeffs[i], deserializedCoeffs[i])).toBe(true);
      }

      // Verify recreation from components
      const recreated = new round1.SecretPackage(
        Ed448Shake256,
        deserializedId,
        deserializedCoeffs,
        round1SecretPackage.commitment,
        round1SecretPackage.minSigners,
        round1SecretPackage.maxSigners,
      );
      expect(round1SecretPackage.equals(recreated)).toBe(true);
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
    it("should serialize and deserialize round1::Package components correctly", () => {
      // Ported from: check_round1_package_postcard_serialization
      const packageData = round1PackageData();
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed448Shake256,
        packageData.commitment,
      );
      const signature = Signature.deserialize(Ed448Shake256, packageData.proofOfKnowledge);

      const round1Package = new round1.Package(Ed448Shake256, commitment, {
        R: signature.R,
        z: signature.z,
      });

      // Verify commitment roundtrip
      const commitmentBytes = round1Package.commitment.serializeWhole();
      const deserializedCommitment = VerifiableSecretSharingCommitment.deserialize(Ed448Shake256, [
        commitmentBytes,
      ]);
      expect(round1Package.commitment.equals(deserializedCommitment)).toBe(true);

      // Verify recreation
      const recreated = new round1.Package(
        Ed448Shake256,
        deserializedCommitment,
        round1Package.proofOfKnowledge,
      );
      expect(round1Package.equals(recreated)).toBe(true);
    });

    it("should have valid round1 package data", () => {
      const data = round1PackageData();
      expect(data.commitment.length).toBe(1);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH);
      // Proof of knowledge is a signature: element (57) + scalar (57) = 114 bytes
      expect(data.proofOfKnowledge.length).toBe(ELEMENT_LENGTH + SCALAR_LENGTH);
    });
  });

  describe("DKG Round2 SecretPackage Serialization", () => {
    it("should serialize and deserialize round2::SecretPackage components correctly", () => {
      // Ported from: check_round2_secret_package_postcard_serialization
      const packageData = round2SecretPackageData();
      const identifier = Identifier.fromU16(Ed448Shake256, packageData.identifier);
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed448Shake256,
        packageData.commitment,
      );
      const secretShare = Ed448Shake256.deserializeScalar(packageData.secretShare);

      const round2SecretPackage = new round2.SecretPackage(
        Ed448Shake256,
        identifier,
        commitment,
        secretShare,
        packageData.minSigners,
        packageData.maxSigners,
      );

      // Verify component roundtrips
      const idBytes = round2SecretPackage.identifier.serialize();
      const deserializedId = Identifier.deserialize(Ed448Shake256, idBytes);
      expect(round2SecretPackage.identifier.equals(deserializedId)).toBe(true);

      const extractedSecret = round2SecretPackage.secretShare();
      const secretBytes = Ed448Shake256.serializeScalar(extractedSecret);
      const deserializedSecret = Ed448Shake256.deserializeScalar(secretBytes);
      expect(Ed448Shake256.scalarsEqual(extractedSecret, deserializedSecret)).toBe(true);

      // Verify recreation from components
      const recreated = new round2.SecretPackage(
        Ed448Shake256,
        deserializedId,
        round2SecretPackage.commitment,
        deserializedSecret,
        round2SecretPackage.minSigners,
        round2SecretPackage.maxSigners,
      );
      expect(round2SecretPackage.equals(recreated)).toBe(true);
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
    it("should serialize and deserialize round2::Package components correctly", () => {
      // Ported from: check_round2_package_postcard_serialization
      const packageData = round2PackageData();
      const signingShare = SigningShare.deserialize(Ed448Shake256, packageData.signingShare);

      const round2Package = new round2.Package(Ed448Shake256, signingShare);

      // Verify signing share roundtrip
      const shareBytes = round2Package.signingShare.serialize();
      const deserializedShare = SigningShare.deserialize(Ed448Shake256, shareBytes);
      expect(round2Package.signingShare.equals(deserializedShare)).toBe(true);

      // Verify recreation from components
      const recreated = new round2.Package(Ed448Shake256, deserializedShare);
      expect(round2Package.equals(recreated)).toBe(true);
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
    expect(SCALAR_LENGTH).toBe(57);
    expect(signingNoncesData().hiding.length).toBe(SCALAR_LENGTH);
    expect(signatureShareData().share.length).toBe(SCALAR_LENGTH);
    expect(keyPackageData().signingShare.length).toBe(SCALAR_LENGTH);
  });

  it("should have consistent element length", () => {
    expect(ELEMENT_LENGTH).toBe(57);
    expect(signingCommitmentsData().hiding.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingShare.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingKey.length).toBe(ELEMENT_LENGTH);
  });
});

describe("Cross-Format Serialization", () => {
  it("should maintain hex representation stability", () => {
    const shareData = signatureShareData();
    const signatureShare = SignatureShare.deserialize(Ed448Shake256, shareData.share);
    const bytes = signatureShare.serialize();
    const hex = bytesToHex(bytes);
    const bytesFromHex = hexToBytes(hex);
    const deserialized = SignatureShare.deserialize(Ed448Shake256, bytesFromHex);

    expect(signatureShare.equals(deserialized)).toBe(true);
  });

  it("should handle identifier roundtrip through hex", () => {
    const identifier = Identifier.fromU16(Ed448Shake256, 42);
    const bytes = identifier.serialize();
    const hex = bytesToHex(bytes);
    const bytesFromHex = hexToBytes(hex);
    const deserialized = Identifier.deserialize(Ed448Shake256, bytesFromHex);

    expect(identifier.equals(deserialized)).toBe(true);
  });
});
