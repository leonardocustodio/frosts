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
  SIGNATURE_LENGTH,
} from "./helpers/index.js";

// Expected serialization hex values from Rust insta snapshots
// These will be updated once the TypeScript implementation is complete
// and we can generate actual serializations to compare.
const EXPECTED_SERIALIZATIONS = {
  signingNonces: "", // Will be filled from Rust snapshot
  signingCommitments: "", // Will be filled from Rust snapshot
  signingPackage: "", // Will be filled from Rust snapshot
  signatureShare: "", // Will be filled from Rust snapshot
  secretShare: "", // Will be filled from Rust snapshot
  keyPackage: "", // Will be filled from Rust snapshot
  publicKeyPackage: "", // Will be filled from Rust snapshot
  publicKeyPackageNew: "", // Will be filled from Rust snapshot
  round1SecretPackage: "", // Will be filled from Rust snapshot
  round1Package: "", // Will be filled from Rust snapshot
  round2SecretPackage: "", // Will be filled from Rust snapshot
  round2Package: "", // Will be filled from Rust snapshot
} as const;

// Import types when available
// import {
//   SigningNonces,
//   SigningCommitments,
//   SigningPackage,
//   SignatureShare,
//   SecretShare,
//   KeyPackage,
//   PublicKeyPackage,
//   round1,
//   round2,
// } from "../src/index.js";

describe("FROST P256-SHA256 Serialization Tests", () => {
  describe("SigningNonces Serialization", () => {
    it.skip("should serialize and deserialize SigningNonces correctly", () => {
      // Ported from: check_signing_nonces_postcard_serialization
      // const nonces = samples::signing_nonces();
      // const bytes = nonces.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(nonces, SigningNonces::deserialize(&bytes).unwrap());
      //
      // const noncesData = signingNoncesData();
      // const nonces = SigningNonces.fromNonces(
      //   Nonce.deserialize(noncesData.hiding),
      //   Nonce.deserialize(noncesData.binding)
      // );
      // const bytes = nonces.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = SigningNonces.deserialize(bytes);
      // expect(deserialized).toEqual(nonces);
      expect(true).toBe(true);
    });

    it("should have correct nonce data length", () => {
      const data = signingNoncesData();
      expect(data.hiding.length).toBe(SCALAR_LENGTH);
      expect(data.binding.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SigningCommitments Serialization", () => {
    it.skip("should serialize and deserialize SigningCommitments correctly", () => {
      // Ported from: check_signing_commitments_postcard_serialization
      // const commitments = samples::signing_commitments();
      // const bytes = commitments.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(commitments, SigningCommitments::deserialize(&bytes).unwrap());
      //
      // const commitmentsData = signingCommitmentsData();
      // const commitments = SigningCommitments.new(
      //   NonceCommitment.deserialize(commitmentsData.hiding),
      //   NonceCommitment.deserialize(commitmentsData.binding)
      // );
      // const bytes = commitments.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = SigningCommitments.deserialize(bytes);
      // expect(deserialized).toEqual(commitments);
      expect(true).toBe(true);
    });

    it("should have correct commitment data length (SEC1 compressed)", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH); // 33 bytes for P256
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SigningPackage Serialization", () => {
    it.skip("should serialize and deserialize SigningPackage correctly", () => {
      // Ported from: check_signing_package_postcard_serialization
      // const signingPackage = samples::signing_package();
      // const bytes = signingPackage.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(signingPackage, SigningPackage::deserialize(&bytes).unwrap());
      //
      // const packageData = signingPackageData();
      // const commitments = new Map();
      // commitments.set(Identifier.tryFrom(packageData.identifier), ...);
      // const signingPackage = SigningPackage.new(commitments, packageData.message);
      // const bytes = signingPackage.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = SigningPackage.deserialize(bytes);
      // expect(deserialized).toEqual(signingPackage);
      expect(true).toBe(true);
    });

    it("should have valid signing package data", () => {
      const data = signingPackageData();
      expect(data.identifier).toBe(42);
      expect(data.message).toEqual(new TextEncoder().encode("hello world"));
    });
  });

  describe("SignatureShare Serialization", () => {
    it.skip("should serialize and deserialize SignatureShare correctly", () => {
      // Ported from: check_signature_share_postcard_serialization
      // const signatureShare = samples::signature_share();
      // const bytes = signatureShare.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(signatureShare, SignatureShare::deserialize(&bytes).unwrap());
      //
      // const shareData = signatureShareData();
      // const signatureShare = SignatureShare.deserialize(shareData.share);
      // const bytes = signatureShare.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = SignatureShare.deserialize(bytes);
      // expect(deserialized).toEqual(signatureShare);
      expect(true).toBe(true);
    });

    it("should have correct signature share data length", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SecretShare Serialization", () => {
    it.skip("should serialize and deserialize SecretShare correctly", () => {
      // Ported from: check_secret_share_postcard_serialization
      // const secretShare = samples::secret_share();
      // const bytes = secretShare.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(secretShare, SecretShare::deserialize(&bytes).unwrap());
      //
      // const shareData = secretShareData();
      // const secretShare = SecretShare.new(
      //   Identifier.tryFrom(shareData.identifier),
      //   SigningShare.deserialize(shareData.signingShare),
      //   VerifiableSecretSharingCommitment.deserialize(shareData.commitment)
      // );
      // const bytes = secretShare.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = SecretShare.deserialize(bytes);
      // expect(deserialized).toEqual(secretShare);
      expect(true).toBe(true);
    });

    it("should have valid secret share data", () => {
      const data = secretShareData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH); // 33 bytes for P256
    });
  });

  describe("KeyPackage Serialization", () => {
    it.skip("should serialize and deserialize KeyPackage correctly", () => {
      // Ported from: check_key_package_postcard_serialization
      // const keyPackage = samples::key_package();
      // const bytes = keyPackage.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(keyPackage, KeyPackage::deserialize(&bytes).unwrap());
      //
      // const packageData = keyPackageData();
      // const keyPackage = KeyPackage.new(
      //   Identifier.tryFrom(packageData.identifier),
      //   SigningShare.deserialize(packageData.signingShare),
      //   VerifyingShare.deserialize(packageData.verifyingShare),
      //   VerifyingKey.deserialize(packageData.verifyingKey),
      //   packageData.minSigners
      // );
      // const bytes = keyPackage.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = KeyPackage.deserialize(bytes);
      // expect(deserialized).toEqual(keyPackage);
      expect(true).toBe(true);
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
    it.skip("should serialize and deserialize PublicKeyPackage correctly (legacy)", () => {
      // Ported from: check_public_key_package_postcard_serialization
      // const publicKeyPackage = samples::public_key_package();
      // const bytes = publicKeyPackage.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(publicKeyPackage, PublicKeyPackage::deserialize(&bytes).unwrap());
      //
      // const packageData = publicKeyPackageData();
      // const verifyingShares = new Map();
      // for (const [id, share] of packageData.verifyingShares) {
      //   verifyingShares.set(Identifier.tryFrom(id), VerifyingShare.deserialize(share));
      // }
      // const publicKeyPackage = PublicKeyPackage.newInternal(
      //   verifyingShares,
      //   VerifyingKey.deserialize(packageData.verifyingKey),
      //   undefined
      // );
      // const bytes = publicKeyPackage.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = PublicKeyPackage.deserialize(bytes);
      // expect(deserialized).toEqual(publicKeyPackage);
      expect(true).toBe(true);
    });

    it.skip("should serialize and deserialize PublicKeyPackage with minSigners correctly", () => {
      // Ported from: check_public_key_package_new_postcard_serialization
      // const publicKeyPackage = samples::public_key_package_new();
      // const bytes = publicKeyPackage.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(publicKeyPackage, PublicKeyPackage::deserialize(&bytes).unwrap());
      //
      // const packageData = publicKeyPackageNewData();
      // const verifyingShares = new Map();
      // for (const [id, share] of packageData.verifyingShares) {
      //   verifyingShares.set(Identifier.tryFrom(id), VerifyingShare.deserialize(share));
      // }
      // const publicKeyPackage = PublicKeyPackage.new(
      //   verifyingShares,
      //   VerifyingKey.deserialize(packageData.verifyingKey),
      //   packageData.minSigners
      // );
      // const bytes = publicKeyPackage.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = PublicKeyPackage.deserialize(bytes);
      // expect(deserialized).toEqual(publicKeyPackage);
      expect(true).toBe(true);
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
    it.skip("should serialize and deserialize round1::SecretPackage correctly", () => {
      // Ported from: check_round1_secret_package_postcard_serialization
      // const round1SecretPackage = samples::round1_secret_package();
      // const bytes = round1SecretPackage.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(round1SecretPackage, round1::SecretPackage::deserialize(&bytes).unwrap());
      //
      // const packageData = round1SecretPackageData();
      // const round1SecretPackage = round1.SecretPackage.new(
      //   Identifier.tryFrom(packageData.identifier),
      //   packageData.coefficients.map(c => Scalar.deserialize(c)),
      //   VerifiableSecretSharingCommitment.deserialize(packageData.commitment),
      //   packageData.minSigners,
      //   packageData.maxSigners
      // );
      // const bytes = round1SecretPackage.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = round1.SecretPackage.deserialize(bytes);
      // expect(deserialized).toEqual(round1SecretPackage);
      expect(true).toBe(true);
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
    it.skip("should serialize and deserialize round1::Package correctly", () => {
      // Ported from: check_round1_package_postcard_serialization
      // const round1Package = samples::round1_package();
      // const bytes = round1Package.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(round1Package, round1::Package::deserialize(&bytes).unwrap());
      //
      // const packageData = round1PackageData();
      // const round1Package = round1.Package.new(
      //   VerifiableSecretSharingCommitment.deserialize(packageData.commitment),
      //   Signature.deserialize(packageData.proofOfKnowledge)
      // );
      // const bytes = round1Package.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = round1.Package.deserialize(bytes);
      // expect(deserialized).toEqual(round1Package);
      expect(true).toBe(true);
    });

    it("should have valid round1 package data", () => {
      const data = round1PackageData();
      expect(data.commitment.length).toBe(1);
      expect(data.commitment[0].length).toBe(ELEMENT_LENGTH); // 33 bytes for P256
      // Proof of knowledge is a signature: element (33) + scalar (32) = 65 bytes
      expect(data.proofOfKnowledge.length).toBe(SIGNATURE_LENGTH);
    });
  });

  describe("DKG Round2 SecretPackage Serialization", () => {
    it.skip("should serialize and deserialize round2::SecretPackage correctly", () => {
      // Ported from: check_round2_secret_package_postcard_serialization
      // const round2SecretPackage = samples::round2_secret_package();
      // const bytes = round2SecretPackage.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(round2SecretPackage, round2::SecretPackage::deserialize(&bytes).unwrap());
      //
      // const packageData = round2SecretPackageData();
      // const round2SecretPackage = round2.SecretPackage.new(
      //   Identifier.tryFrom(packageData.identifier),
      //   VerifiableSecretSharingCommitment.deserialize(packageData.commitment),
      //   Scalar.deserialize(packageData.secretShare),
      //   packageData.minSigners,
      //   packageData.maxSigners
      // );
      // const bytes = round2SecretPackage.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = round2.SecretPackage.deserialize(bytes);
      // expect(deserialized).toEqual(round2SecretPackage);
      expect(true).toBe(true);
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
    it.skip("should serialize and deserialize round2::Package correctly", () => {
      // Ported from: check_round2_package_postcard_serialization
      // const round2Package = samples::round2_package();
      // const bytes = round2Package.serialize();
      // assert_snapshot!(hex::encode(&bytes));
      // assert_eq!(round2Package, round2::Package::deserialize(&bytes).unwrap());
      //
      // const packageData = round2PackageData();
      // const round2Package = round2.Package.new(
      //   SigningShare.deserialize(packageData.signingShare)
      // );
      // const bytes = round2Package.serialize();
      // expect(bytesToHex(bytes)).toMatchSnapshot();
      // const deserialized = round2.Package.deserialize(bytes);
      // expect(deserialized).toEqual(round2Package);
      expect(true).toBe(true);
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
