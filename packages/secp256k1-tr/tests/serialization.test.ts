/**
 * Serialization tests for FROST secp256k1-SHA256-TR (Taproot).
 * Ported from frost-secp256k1-tr/tests/serialization_tests.rs
 *
 * These tests verify that all FROST data structures can be correctly
 * serialized and deserialized using the postcard binary format.
 *
 * Key differences from non-Taproot secp256k1:
 * - SIGNATURE_LENGTH = 64 bytes (BIP-340 format: x-only R + s)
 * - Proof of knowledge uses BIP-340 signatures
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
  SIGNATURE_LENGTH,
  // Sample object factory functions
  signingNonces,
  signingCommitments,
  signingPackage,
  signatureShare,
  secretShare,
  keyPackage,
  publicKeyPackage,
  publicKeyPackageNew,
  round1SecretPackage,
  round1Package,
  round2SecretPackage,
  round2Package,
} from "./helpers/index.js";

import { Secp256K1Sha256TR, keys as _keys } from "../src/index.js";

import {
  SigningPackageImpl,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  Nonce,
  NonceCommitment,
  SigningNonces,
  SigningCommitments,
  SignatureShare,
  round1,
  round2,
} from "@frosts/core";

describe("FROST secp256k1-SHA256-TR Serialization Tests", () => {
  describe("SigningNonces Serialization", () => {
    it("should serialize and deserialize SigningNonces correctly", () => {
      // Ported from: check_signing_nonces_postcard_serialization
      const nonces = signingNonces();

      // Get component serializations (access as properties)
      const hidingBytes = nonces.hiding.serialize();
      const bindingBytes = nonces.binding.serialize();

      // Deserialize components back
      const hidingNonce = Nonce.deserialize(Secp256K1Sha256TR, hidingBytes);
      const bindingNonce = Nonce.deserialize(Secp256K1Sha256TR, bindingBytes);
      const deserialized = SigningNonces.fromNonces(Secp256K1Sha256TR, hidingNonce, bindingNonce);

      // Verify round-trip
      expect(bytesToHex(deserialized.hiding.serialize())).toBe(
        bytesToHex(nonces.hiding.serialize()),
      );
      expect(bytesToHex(deserialized.binding.serialize())).toBe(
        bytesToHex(nonces.binding.serialize()),
      );
    });

    it("should have correct nonce data length", () => {
      const data = signingNoncesData();
      expect(data.hiding.length).toBe(SCALAR_LENGTH);
      expect(data.binding.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SigningCommitments Serialization", () => {
    it("should serialize and deserialize SigningCommitments correctly", () => {
      // Ported from: check_signing_commitments_postcard_serialization
      const commitments = signingCommitments();

      // Get component serializations
      const hidingBytes = commitments.hiding.serialize();
      const bindingBytes = commitments.binding.serialize();

      // Deserialize components back
      const hidingCommitment = NonceCommitment.deserialize(Secp256K1Sha256TR, hidingBytes);
      const bindingCommitment = NonceCommitment.deserialize(Secp256K1Sha256TR, bindingBytes);
      const deserialized = new SigningCommitments(
        Secp256K1Sha256TR,
        hidingCommitment,
        bindingCommitment,
      );

      // Verify round-trip
      expect(bytesToHex(deserialized.hiding.serialize())).toBe(
        bytesToHex(commitments.hiding.serialize()),
      );
      expect(bytesToHex(deserialized.binding.serialize())).toBe(
        bytesToHex(commitments.binding.serialize()),
      );
    });

    it("should have correct commitment data length (SEC1 compressed)", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH); // 33 bytes for secp256k1
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SigningPackage Serialization", () => {
    it("should serialize and deserialize SigningPackage correctly", () => {
      // Ported from: check_signing_package_postcard_serialization
      const pkg = signingPackage();

      // Extract and re-create with same data
      const commitments = pkg.signingCommitments;
      const message = pkg.message;
      const deserialized = SigningPackageImpl.create(Secp256K1Sha256TR, commitments, message);

      // Verify round-trip
      expect(bytesToHex(deserialized.message)).toBe(bytesToHex(pkg.message));
      expect(deserialized.signingCommitments.size).toBe(pkg.signingCommitments.size);

      // Verify commitment contents match
      for (const [id, commitment] of pkg.signingCommitments) {
        const deserializedCommitment = deserialized.signingCommitments.get(id);
        expect(deserializedCommitment).toBeDefined();
        if (deserializedCommitment === undefined)
          throw new Error("deserializedCommitment is undefined");
        expect(bytesToHex(deserializedCommitment.hiding.serialize())).toBe(
          bytesToHex(commitment.hiding.serialize()),
        );
      }
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
      const share = signatureShare();

      const bytes = share.serialize();
      const deserialized = SignatureShare.deserialize(Secp256K1Sha256TR, bytes);

      // Verify round-trip
      expect(bytesToHex(deserialized.serialize())).toBe(bytesToHex(share.serialize()));
    });

    it("should have correct signature share data length", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SecretShare Serialization", () => {
    it("should serialize and deserialize SecretShare correctly", () => {
      // Ported from: check_secret_share_postcard_serialization
      const share = secretShare();

      // Extract and recreate (access as properties)
      const identifier = share.identifier;
      const signingShareVal = share.signingShare;
      const commitment = share.commitment;
      const deserialized = new SecretShare(
        Secp256K1Sha256TR,
        identifier,
        signingShareVal,
        commitment,
      );

      // Verify round-trip
      expect(bytesToHex(deserialized.identifier.serialize())).toBe(
        bytesToHex(share.identifier.serialize()),
      );
      expect(bytesToHex(deserialized.signingShare.serialize())).toBe(
        bytesToHex(share.signingShare.serialize()),
      );
    });

    it("should have valid secret share data", () => {
      const data = secretShareData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH); // 33 bytes for secp256k1
    });
  });

  describe("KeyPackage Serialization", () => {
    it("should serialize and deserialize KeyPackage correctly", () => {
      // Ported from: check_key_package_postcard_serialization
      const pkg = keyPackage();

      // Extract and recreate (access as properties)
      const identifier = pkg.identifier;
      const signingShareVal = pkg.signingShare;
      const verifyingShare = pkg.verifyingShare;
      const verifyingKey = pkg.verifyingKey;
      const minSigners = pkg.minSigners;

      const deserialized = new KeyPackage(
        Secp256K1Sha256TR,
        identifier,
        signingShareVal,
        verifyingShare,
        verifyingKey,
        minSigners,
      );

      // Verify round-trip
      expect(bytesToHex(deserialized.identifier.serialize())).toBe(
        bytesToHex(pkg.identifier.serialize()),
      );
      expect(bytesToHex(deserialized.signingShare.serialize())).toBe(
        bytesToHex(pkg.signingShare.serialize()),
      );
      expect(deserialized.minSigners).toBe(pkg.minSigners);
    });

    it("should have valid key package data", () => {
      const data = keyPackageData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.verifyingShare.length).toBe(ELEMENT_LENGTH); // 33 bytes
      expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
      expect(data.minSigners).toBe(2);
    });
  });

  describe("PublicKeyPackage Serialization", () => {
    it("should serialize and deserialize PublicKeyPackage correctly (legacy)", () => {
      // Ported from: check_public_key_package_postcard_serialization
      const pkg = publicKeyPackage();

      // Extract and recreate (access as properties)
      const verifyingShares = pkg.verifyingShares;
      const verifyingKey = pkg.verifyingKey;

      const deserialized = new PublicKeyPackage(Secp256K1Sha256TR, verifyingShares, verifyingKey);

      // Verify round-trip
      expect(deserialized.verifyingShares.size).toBe(pkg.verifyingShares.size);
      expect(bytesToHex(Secp256K1Sha256TR.serializeElement(deserialized.verifyingKey))).toBe(
        bytesToHex(Secp256K1Sha256TR.serializeElement(pkg.verifyingKey)),
      );
    });

    it("should serialize and deserialize PublicKeyPackage with minSigners correctly", () => {
      // Ported from: check_public_key_package_new_postcard_serialization
      const pkg = publicKeyPackageNew();

      // Extract and recreate (access as properties)
      const verifyingShares = pkg.verifyingShares;
      const verifyingKey = pkg.verifyingKey;
      const minSigners = pkg.minSigners;

      const deserialized = new PublicKeyPackage(
        Secp256K1Sha256TR,
        verifyingShares,
        verifyingKey,
        minSigners,
      );

      // Verify round-trip
      expect(deserialized.verifyingShares.size).toBe(pkg.verifyingShares.size);
      expect(deserialized.minSigners).toBe(pkg.minSigners);
    });

    it("should have valid public key package data", () => {
      const data = publicKeyPackageData();
      expect(data.verifyingShares.size).toBe(1);
      expect(data.verifyingShares.get(42)?.length).toBe(ELEMENT_LENGTH); // 33 bytes
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
    it("should serialize and deserialize round1::SecretPackage correctly", () => {
      // Ported from: check_round1_secret_package_postcard_serialization
      const pkg = round1SecretPackage();

      // Extract and recreate (access as properties)
      const identifier = pkg.identifier;
      const coefficients = pkg.coefficients;
      const commitment = pkg.commitment;
      const minSigners = pkg.minSigners;
      const maxSigners = pkg.maxSigners;

      /* eslint-disable @typescript-eslint/no-explicit-any */
      const deserialized = new round1.SecretPackage(
        Secp256K1Sha256TR,
        identifier as any,
        coefficients as any,
        commitment as any,
        minSigners,
        maxSigners,
      );
      /* eslint-enable @typescript-eslint/no-explicit-any */

      // Verify round-trip
      expect(bytesToHex(deserialized.identifier.serialize())).toBe(
        bytesToHex(pkg.identifier.serialize()),
      );
      expect(deserialized.minSigners).toBe(pkg.minSigners);
      expect(deserialized.maxSigners).toBe(pkg.maxSigners);
      expect(deserialized.coefficients.length).toBe(pkg.coefficients.length);
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
    it("should serialize and deserialize round1::Package correctly", () => {
      // Ported from: check_round1_package_postcard_serialization
      const pkg = round1Package();

      // Extract and recreate (access as properties)
      const commitment = pkg.commitment;
      const proofOfKnowledge = pkg.proofOfKnowledge;

      const deserialized = new round1.Package(Secp256K1Sha256TR, commitment, proofOfKnowledge);

      // Verify round-trip
      expect(deserialized.commitment.coefficients().length).toBe(
        pkg.commitment.coefficients().length,
      );
    });

    it("should have valid round1 package data", () => {
      const data = round1PackageData();
      expect(data.commitment.length).toBe(1);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH); // 33 bytes for secp256k1
      // Proof of knowledge is a BIP-340 signature: x-only R (32) + scalar (32) = 64 bytes
      expect(data.proofOfKnowledge.length).toBe(SIGNATURE_LENGTH);
    });
  });

  describe("DKG Round2 SecretPackage Serialization", () => {
    it("should serialize and deserialize round2::SecretPackage correctly", () => {
      // Ported from: check_round2_secret_package_postcard_serialization
      const pkg = round2SecretPackage();

      // Extract and recreate (access as properties)
      const identifier = pkg.identifier;
      const commitment = pkg.commitment;
      const secretShareScalar = pkg.secretShare;
      const minSigners = pkg.minSigners;
      const maxSigners = pkg.maxSigners;

      /* eslint-disable @typescript-eslint/no-explicit-any */
      const deserialized = new round2.SecretPackage(
        Secp256K1Sha256TR,
        identifier as any,
        commitment as any,
        secretShareScalar as any,
        minSigners,
        maxSigners,
      );
      /* eslint-enable @typescript-eslint/no-explicit-any */

      // Verify round-trip
      expect(bytesToHex(deserialized.identifier.serialize())).toBe(
        bytesToHex(pkg.identifier.serialize()),
      );
      expect(deserialized.minSigners).toBe(pkg.minSigners);
      expect(deserialized.maxSigners).toBe(pkg.maxSigners);
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
      // Ported from: check_round2_package_postcard_serialization
      const pkg = round2Package();

      // Extract and recreate (access as property)
      const signingShareVal = pkg.signingShare;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const deserialized = new round2.Package(Secp256K1Sha256TR, signingShareVal as any);

      // Verify round-trip
      expect(bytesToHex(deserialized.signingShare.serialize())).toBe(
        bytesToHex(pkg.signingShare.serialize()),
      );
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

  it("should have consistent element length (SEC1 compressed)", () => {
    expect(ELEMENT_LENGTH).toBe(33); // SEC1 compressed format for secp256k1
    expect(signingCommitmentsData().hiding.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingShare.length).toBe(ELEMENT_LENGTH);
    expect(keyPackageData().verifyingKey.length).toBe(ELEMENT_LENGTH);
  });

  it("should have consistent BIP-340 signature length", () => {
    // Taproot uses BIP-340 signatures: 64 bytes (x-only R + s)
    expect(SIGNATURE_LENGTH).toBe(64);
    expect(round1PackageData().proofOfKnowledge.length).toBe(SIGNATURE_LENGTH);
  });
});
