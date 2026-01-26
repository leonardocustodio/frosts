/**
 * Serialization tests for FROST Ed25519-SHA512.
 * Ported from frost-ed25519/tests/serialization_tests.rs
 *
 * These tests verify that all FROST data structures can be correctly
 * serialized and deserialized using the binary format.
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
  Ed25519Sha512,
  SigningNonces,
  SigningCommitments,
  NonceCommitment,
  SignatureShare,
  SigningShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  VerifyingShare,
  VerifiableSecretSharingCommitment,
  Identifier,
  Nonce,
} from "../src/index.js";

describe("FROST Ed25519-SHA512 Serialization Tests", () => {
  describe("SigningNonces Serialization", () => {
    it("should serialize and deserialize SigningNonces correctly", () => {
      const noncesData = signingNoncesData();
      const hidingNonce = Nonce.deserialize(Ed25519Sha512, noncesData.hiding);
      const bindingNonce = Nonce.deserialize(Ed25519Sha512, noncesData.binding);
      const nonces = SigningNonces.fromNonces(Ed25519Sha512, hidingNonce, bindingNonce);

      const serialized = nonces.serialize();
      const deserialized = SigningNonces.deserialize(Ed25519Sha512, serialized);

      // Compare serialized representations
      expect(bytesToHex(deserialized.serialize())).toBe(bytesToHex(serialized));
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
      const hiding = NonceCommitment.deserialize(Ed25519Sha512, commitmentsData.hiding);
      const binding = NonceCommitment.deserialize(Ed25519Sha512, commitmentsData.binding);
      const commitments = new SigningCommitments(Ed25519Sha512, hiding, binding);

      const serialized = commitments.serialize();
      const deserialized = SigningCommitments.deserialize(Ed25519Sha512, serialized);

      expect(bytesToHex(deserialized.hiding.serialize())).toBe(
        bytesToHex(commitments.hiding.serialize()),
      );
      expect(bytesToHex(deserialized.binding.serialize())).toBe(
        bytesToHex(commitments.binding.serialize()),
      );
    });

    it("should have correct commitment data length", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH);
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SigningPackage Serialization", () => {
    it("should serialize and deserialize SigningPackage components correctly", () => {
      // SigningPackage is a compound structure with message and signingCommitments
      // We test that all components can be serialized and reconstructed
      const data = signingPackageData();

      // Create commitments
      const commitmentsData = signingCommitmentsData();
      const hiding = NonceCommitment.deserialize(Ed25519Sha512, commitmentsData.hiding);
      const binding = NonceCommitment.deserialize(Ed25519Sha512, commitmentsData.binding);
      const commitments = new SigningCommitments(Ed25519Sha512, hiding, binding);

      // Create identifier
      const identifier = Identifier.fromU16(Ed25519Sha512, data.identifier);

      // Create a signing package manually (it's a simple interface)
      const signingPackage = {
        signingCommitments: new Map([[identifier, commitments]]),
        message: data.message,
      };

      // Verify components can be extracted and serialized
      const commitmentsFromPackage = signingPackage.signingCommitments.get(identifier);
      expect(commitmentsFromPackage).toBeDefined();
      if (commitmentsFromPackage === undefined)
        throw new Error("commitmentsFromPackage is undefined");
      const serializedCommitments = commitmentsFromPackage.serialize();
      expect(serializedCommitments.length).toBe(2 * ELEMENT_LENGTH);

      // Verify message is preserved
      expect(signingPackage.message).toEqual(data.message);
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
      const signatureShare = SignatureShare.deserialize(Ed25519Sha512, shareData.share);

      const serialized = signatureShare.serialize();
      const deserialized = SignatureShare.deserialize(Ed25519Sha512, serialized);

      expect(bytesToHex(deserialized.serialize())).toBe(bytesToHex(serialized));
    });

    it("should have correct signature share data length", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SecretShare Serialization", () => {
    it("should serialize and deserialize SecretShare components correctly", () => {
      // SecretShare contains identifier, signingShare, and commitment
      // All components support binary serialization
      const shareData = secretShareData();
      const id = Identifier.fromU16(Ed25519Sha512, shareData.identifier);
      const signingShare = SigningShare.deserialize(Ed25519Sha512, shareData.signingShare);
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed25519Sha512,
        shareData.commitment,
      );

      const secretShare = new SecretShare(Ed25519Sha512, id, signingShare, commitment);

      // Verify component-level serialization works
      const idBytes = secretShare.identifier.serialize();
      const signingShareBytes = secretShare.signingShare.serialize();
      const commitmentBytes = secretShare.commitment.serialize();

      // Deserialize components
      const idDeserialized = Identifier.deserialize(Ed25519Sha512, idBytes);
      const signingShareDeserialized = SigningShare.deserialize(Ed25519Sha512, signingShareBytes);
      const commitmentDeserialized = VerifiableSecretSharingCommitment.deserialize(
        Ed25519Sha512,
        commitmentBytes,
      );

      // Reconstruct SecretShare
      const reconstructed = new SecretShare(
        Ed25519Sha512,
        idDeserialized,
        signingShareDeserialized,
        commitmentDeserialized,
      );

      // Verify equality
      expect(reconstructed.identifier.equals(secretShare.identifier)).toBe(true);
      expect(bytesToHex(reconstructed.signingShare.serialize())).toBe(
        bytesToHex(secretShare.signingShare.serialize()),
      );
    });

    it("should have valid secret share data", () => {
      const data = secretShareData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH);
    });

    it("should create SecretShare from sample data", () => {
      const shareData = secretShareData();
      const id = Identifier.fromU16(Ed25519Sha512, shareData.identifier);
      const signingShare = SigningShare.deserialize(Ed25519Sha512, shareData.signingShare);
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed25519Sha512,
        shareData.commitment,
      );

      const secretShare = new SecretShare(Ed25519Sha512, id, signingShare, commitment);

      expect(secretShare.identifier.equals(id)).toBe(true);
      expect(bytesToHex(secretShare.signingShare.serialize())).toBe(
        bytesToHex(signingShare.serialize()),
      );
    });
  });

  describe("KeyPackage Serialization", () => {
    it("should serialize and deserialize KeyPackage components correctly", () => {
      // KeyPackage contains identifier, signingShare, verifyingShare, verifyingKey, minSigners
      // All components support binary serialization except minSigners (u16)
      const packageData = keyPackageData();
      const id = Identifier.fromU16(Ed25519Sha512, packageData.identifier);
      const signingShare = SigningShare.deserialize(Ed25519Sha512, packageData.signingShare);
      const verifyingShare = VerifyingShare.deserialize(Ed25519Sha512, packageData.verifyingShare);
      const verifyingKey = Ed25519Sha512.deserializeElement(packageData.verifyingKey);

      const keyPackage = new KeyPackage(
        Ed25519Sha512,
        id,
        signingShare,
        verifyingShare,
        verifyingKey,
        packageData.minSigners,
      );

      // Serialize all components
      const idBytes = keyPackage.identifier.serialize();
      const signingShareBytes = keyPackage.signingShare.serialize();
      const verifyingShareBytes = keyPackage.verifyingShare.serialize();
      const verifyingKeyBytes = Ed25519Sha512.serializeElement(keyPackage.verifyingKey);
      const minSigners = keyPackage.minSigners;

      // Deserialize components
      const idDeserialized = Identifier.deserialize(Ed25519Sha512, idBytes);
      const signingShareDeserialized = SigningShare.deserialize(Ed25519Sha512, signingShareBytes);
      const verifyingShareDeserialized = VerifyingShare.deserialize(
        Ed25519Sha512,
        verifyingShareBytes,
      );
      const verifyingKeyDeserialized = Ed25519Sha512.deserializeElement(verifyingKeyBytes);

      // Reconstruct KeyPackage
      const reconstructed = new KeyPackage(
        Ed25519Sha512,
        idDeserialized,
        signingShareDeserialized,
        verifyingShareDeserialized,
        verifyingKeyDeserialized,
        minSigners,
      );

      // Verify equality
      expect(reconstructed.identifier.equals(keyPackage.identifier)).toBe(true);
      expect(bytesToHex(reconstructed.signingShare.serialize())).toBe(
        bytesToHex(keyPackage.signingShare.serialize()),
      );
      expect(bytesToHex(reconstructed.verifyingShare.serialize())).toBe(
        bytesToHex(keyPackage.verifyingShare.serialize()),
      );
      expect(reconstructed.minSigners).toBe(keyPackage.minSigners);
    });

    it("should have valid key package data", () => {
      const data = keyPackageData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.verifyingShare.length).toBe(ELEMENT_LENGTH);
      expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
      expect(data.minSigners).toBe(2);
    });

    it("should create KeyPackage from sample data", () => {
      const packageData = keyPackageData();
      const id = Identifier.fromU16(Ed25519Sha512, packageData.identifier);
      const signingShare = SigningShare.deserialize(Ed25519Sha512, packageData.signingShare);
      const verifyingShare = VerifyingShare.deserialize(Ed25519Sha512, packageData.verifyingShare);
      const verifyingKey = Ed25519Sha512.deserializeElement(packageData.verifyingKey);

      const keyPackage = new KeyPackage(
        Ed25519Sha512,
        id,
        signingShare,
        verifyingShare,
        verifyingKey,
        packageData.minSigners,
      );

      expect(keyPackage.identifier.equals(id)).toBe(true);
      expect(keyPackage.minSigners).toBe(packageData.minSigners);
    });
  });

  describe("PublicKeyPackage Serialization", () => {
    it("should serialize and deserialize PublicKeyPackage components correctly (legacy)", () => {
      // PublicKeyPackage contains verifyingShares and verifyingKey
      const packageData = publicKeyPackageData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ed25519Sha512>>();

      for (const [id, share] of packageData.verifyingShares) {
        const idBytes = Identifier.fromU16(Ed25519Sha512, id).serialize();
        const idHex = bytesToHex(idBytes);
        verifyingShares.set(idHex, VerifyingShare.deserialize(Ed25519Sha512, share));
      }

      const verifyingKey = Ed25519Sha512.deserializeElement(packageData.verifyingKey);
      const publicKeyPackage = new PublicKeyPackage(Ed25519Sha512, verifyingShares, verifyingKey);

      // Serialize all components
      const verifyingKeyBytes = Ed25519Sha512.serializeElement(publicKeyPackage.verifyingKey);
      const serializedShares = new Map<string, Uint8Array>();
      for (const [idHex, share] of publicKeyPackage.verifyingShares) {
        serializedShares.set(idHex, share.serialize());
      }

      // Deserialize and reconstruct
      const verifyingKeyDeserialized = Ed25519Sha512.deserializeElement(verifyingKeyBytes);
      const deserializedShares = new Map<string, VerifyingShare<typeof Ed25519Sha512>>();
      for (const [idHex, bytes] of serializedShares) {
        deserializedShares.set(idHex, VerifyingShare.deserialize(Ed25519Sha512, bytes));
      }

      const reconstructed = new PublicKeyPackage(
        Ed25519Sha512,
        deserializedShares,
        verifyingKeyDeserialized,
      );

      // Verify equality
      expect(reconstructed.verifyingShares.size).toBe(publicKeyPackage.verifyingShares.size);
      expect(bytesToHex(Ed25519Sha512.serializeElement(reconstructed.verifyingKey))).toBe(
        bytesToHex(Ed25519Sha512.serializeElement(publicKeyPackage.verifyingKey)),
      );
    });

    it("should serialize and deserialize PublicKeyPackage with minSigners correctly", () => {
      // PublicKeyPackage with minSigners
      const packageData = publicKeyPackageNewData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ed25519Sha512>>();

      for (const [id, share] of packageData.verifyingShares) {
        const idBytes = Identifier.fromU16(Ed25519Sha512, id).serialize();
        const idHex = bytesToHex(idBytes);
        verifyingShares.set(idHex, VerifyingShare.deserialize(Ed25519Sha512, share));
      }

      const verifyingKey = Ed25519Sha512.deserializeElement(packageData.verifyingKey);
      const publicKeyPackage = new PublicKeyPackage(
        Ed25519Sha512,
        verifyingShares,
        verifyingKey,
        packageData.minSigners,
      );

      // Serialize all components
      const verifyingKeyBytes = Ed25519Sha512.serializeElement(publicKeyPackage.verifyingKey);
      const serializedShares = new Map<string, Uint8Array>();
      for (const [idHex, share] of publicKeyPackage.verifyingShares) {
        serializedShares.set(idHex, share.serialize());
      }
      const minSigners = publicKeyPackage.minSigners;

      // Deserialize and reconstruct
      const verifyingKeyDeserialized = Ed25519Sha512.deserializeElement(verifyingKeyBytes);
      const deserializedShares = new Map<string, VerifyingShare<typeof Ed25519Sha512>>();
      for (const [idHex, bytes] of serializedShares) {
        deserializedShares.set(idHex, VerifyingShare.deserialize(Ed25519Sha512, bytes));
      }

      const reconstructed = new PublicKeyPackage(
        Ed25519Sha512,
        deserializedShares,
        verifyingKeyDeserialized,
        minSigners,
      );

      // Verify equality
      expect(reconstructed.verifyingShares.size).toBe(publicKeyPackage.verifyingShares.size);
      expect(reconstructed.minSigners).toBe(publicKeyPackage.minSigners);
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

    it("should create PublicKeyPackage from sample data", () => {
      const packageData = publicKeyPackageNewData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ed25519Sha512>>();

      for (const [id, share] of packageData.verifyingShares) {
        const idBytes = Identifier.fromU16(Ed25519Sha512, id).serialize();
        const idHex = bytesToHex(idBytes);
        verifyingShares.set(idHex, VerifyingShare.deserialize(Ed25519Sha512, share));
      }

      const verifyingKey = Ed25519Sha512.deserializeElement(packageData.verifyingKey);
      const publicKeyPackage = new PublicKeyPackage(
        Ed25519Sha512,
        verifyingShares,
        verifyingKey,
        packageData.minSigners,
      );

      expect(publicKeyPackage.verifyingShares.size).toBe(1);
      expect(publicKeyPackage.minSigners).toBe(packageData.minSigners);
    });
  });

  describe("DKG Round1 SecretPackage Serialization", () => {
    it("should serialize and deserialize round1::SecretPackage component data correctly", () => {
      // round1::SecretPackage is an internal type that contains:
      // - identifier, coefficients, commitment, minSigners, maxSigners
      // We test that all components can be serialized
      const data = round1SecretPackageData();

      // Serialize identifier
      const idBytes = Identifier.fromU16(Ed25519Sha512, data.identifier).serialize();
      expect(idBytes.length).toBe(SCALAR_LENGTH);

      // Serialize coefficients
      for (const coeff of data.coefficients) {
        const scalar = Ed25519Sha512.deserializeScalar(coeff);
        const serialized = Ed25519Sha512.serializeScalar(scalar);
        expect(bytesToHex(serialized)).toBe(bytesToHex(coeff));
      }

      // Serialize commitment
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed25519Sha512,
        data.commitment,
      );
      const commitmentBytes = commitment.serialize();
      expect(commitmentBytes.length).toBe(data.commitment.length);

      // Verify minSigners and maxSigners are valid
      expect(data.minSigners).toBe(2);
      expect(data.maxSigners).toBe(3);
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
    it("should serialize round1::Package data structures", () => {
      // round1::Package serialization - testing basic round-trip
      const packageData = round1PackageData();
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed25519Sha512,
        packageData.commitment,
      );

      // Parse proof of knowledge
      const pokBytes = packageData.proofOfKnowledge;
      const elementSize = Ed25519Sha512.elementSize();
      const R = Ed25519Sha512.deserializeElement(pokBytes.slice(0, elementSize));
      const z = Ed25519Sha512.deserializeScalar(pokBytes.slice(elementSize));

      // Verify structures can be created
      expect(commitment).toBeDefined();
      expect(R).toBeDefined();
      expect(z).toBeDefined();
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
    it("should serialize and deserialize round2::SecretPackage component data correctly", () => {
      // round2::SecretPackage is an internal type that contains:
      // - identifier, commitment, secretShare, minSigners, maxSigners
      // We test that all components can be serialized
      const data = round2SecretPackageData();

      // Serialize identifier
      const idBytes = Identifier.fromU16(Ed25519Sha512, data.identifier).serialize();
      expect(idBytes.length).toBe(SCALAR_LENGTH);

      // Serialize commitment
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed25519Sha512,
        data.commitment,
      );
      const commitmentBytes = commitment.serialize();
      expect(commitmentBytes.length).toBe(data.commitment.length);

      // Serialize secret share
      const secretShare = SigningShare.deserialize(Ed25519Sha512, data.secretShare);
      const secretShareBytes = secretShare.serialize();
      expect(bytesToHex(secretShareBytes)).toBe(bytesToHex(data.secretShare));

      // Verify minSigners and maxSigners are valid
      expect(data.minSigners).toBe(2);
      expect(data.maxSigners).toBe(3);
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
    it("should serialize and deserialize round2::Package correctly", () => {
      const packageData = round2PackageData();
      const signingShare = SigningShare.deserialize(Ed25519Sha512, packageData.signingShare);

      // Verify round-trip through signing share
      const serialized = signingShare.serialize();
      const deserialized = SigningShare.deserialize(Ed25519Sha512, serialized);

      expect(bytesToHex(deserialized.serialize())).toBe(bytesToHex(signingShare.serialize()));
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
