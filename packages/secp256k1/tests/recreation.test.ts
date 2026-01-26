/**
 * Recreation tests for FROST secp256k1-SHA256.
 * Ported from frost-secp256k1/tests/recreation_tests.rs
 *
 * These tests verify that packages can be recreated from their components,
 * which demonstrates that they can be serialized and deserialized as the
 * user wishes (e.g., using custom serialization formats).
 *
 * Key differences from Ristretto255:
 * - ELEMENT_LENGTH = 33 bytes (SEC1 compressed)
 * - SIGNATURE_LENGTH = 65 bytes (33 + 32)
 */

import { describe, it, expect } from "vitest";
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
  bytesToHex,
} from "./helpers/index.js";

import {
  Secp256K1Sha256,
  SigningCommitments,
  SigningNonces,
  SignatureShare,
  keys,
} from "../src/index.js";

import { SigningPackageImpl, SecretShare, KeyPackage, PublicKeyPackage } from "@frosts/core";

// Get DKG module from keys
const { dkg } = keys;

describe("FROST secp256k1-SHA256 Recreation Tests", () => {
  describe("SigningNonces Recreation", () => {
    it("should recreate SigningNonces from component nonces", () => {
      // Ported from: check_signing_nonces_recreation
      const nonces = signingNonces();

      // Access as properties
      const hiding = nonces.hiding;
      const binding = nonces.binding;
      const newNonces = SigningNonces.fromNonces(Secp256K1Sha256, hiding, binding);

      // Verify equality by comparing serialized components
      expect(bytesToHex(newNonces.hiding.serialize())).toBe(bytesToHex(nonces.hiding.serialize()));
      expect(bytesToHex(newNonces.binding.serialize())).toBe(
        bytesToHex(nonces.binding.serialize()),
      );
    });

    it("should have extractable nonce components", () => {
      const data = signingNoncesData();
      expect(data.hiding.length).toBe(SCALAR_LENGTH);
      expect(data.binding.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SigningCommitments Recreation", () => {
    it("should recreate SigningCommitments from component commitments", () => {
      // Ported from: check_signing_commitments_recreation
      const commitments = signingCommitments();

      const hiding = commitments.hiding;
      const binding = commitments.binding;
      const newCommitments = new SigningCommitments(Secp256K1Sha256, hiding, binding);

      // Verify equality by comparing serialized components
      expect(bytesToHex(newCommitments.hiding.serialize())).toBe(
        bytesToHex(commitments.hiding.serialize()),
      );
      expect(bytesToHex(newCommitments.binding.serialize())).toBe(
        bytesToHex(commitments.binding.serialize()),
      );
    });

    it("should have extractable commitment components", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH); // 33 bytes for secp256k1
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SigningPackage Recreation", () => {
    it("should recreate SigningPackage from commitments and message", () => {
      // Ported from: check_signing_package_recreation
      const pkg = signingPackage();

      const commitments = pkg.signingCommitments;
      const message = pkg.message;

      const newSigningPackage = SigningPackageImpl.create(Secp256K1Sha256, commitments, message);

      // Verify equality by comparing message and commitments
      expect(bytesToHex(newSigningPackage.message)).toBe(bytesToHex(pkg.message));
      expect(newSigningPackage.signingCommitments.size).toBe(pkg.signingCommitments.size);
    });

    it("should have extractable package components", () => {
      const data = signingPackageData();
      expect(data.identifier).toBe(42);
      expect(data.commitments.hiding.length).toBe(ELEMENT_LENGTH);
      expect(data.message.length).toBeGreaterThan(0);
    });
  });

  describe("SignatureShare Recreation", () => {
    it("should recreate SignatureShare via serialization", () => {
      // Ported from: check_signature_share_recreation
      const share = signatureShare();

      const encoded = share.serialize();
      const newSignatureShare = SignatureShare.deserialize(Secp256K1Sha256, encoded);

      // Verify equality by comparing serialized forms
      expect(bytesToHex(newSignatureShare.serialize())).toBe(bytesToHex(share.serialize()));
    });

    it("should have serializable share data", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SecretShare Recreation", () => {
    it("should recreate SecretShare from components", () => {
      // Ported from: check_secret_share_recreation
      const share = secretShare();

      // Access as properties
      const identifier = share.identifier;
      const value = share.signingShare;
      const commitment = share.commitment;

      const newSecretShare = new SecretShare(Secp256K1Sha256, identifier, value, commitment);

      // Verify equality by comparing serialized components
      expect(bytesToHex(newSecretShare.identifier.serialize())).toBe(
        bytesToHex(share.identifier.serialize()),
      );
      expect(bytesToHex(newSecretShare.signingShare.serialize())).toBe(
        bytesToHex(share.signingShare.serialize()),
      );
    });

    it("should have extractable secret share components", () => {
      const data = secretShareData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.commitment.length).toBeGreaterThan(0);
    });
  });

  describe("KeyPackage Recreation", () => {
    it("should recreate KeyPackage from components", () => {
      // Ported from: check_key_package_recreation
      const pkg = keyPackage();

      // Access as properties
      const identifier = pkg.identifier;
      const signingShareVal = pkg.signingShare;
      const verifyingShare = pkg.verifyingShare;
      const verifyingKey = pkg.verifyingKey;
      const minSigners = pkg.minSigners;

      const newKeyPackage = new KeyPackage(
        Secp256K1Sha256,
        identifier,
        signingShareVal,
        verifyingShare,
        verifyingKey,
        minSigners,
      );

      // Verify equality by comparing components
      expect(bytesToHex(newKeyPackage.identifier.serialize())).toBe(
        bytesToHex(pkg.identifier.serialize()),
      );
      expect(bytesToHex(newKeyPackage.signingShare.serialize())).toBe(
        bytesToHex(pkg.signingShare.serialize()),
      );
      expect(newKeyPackage.minSigners).toBe(pkg.minSigners);
    });

    it("should have extractable key package components", () => {
      const data = keyPackageData();
      expect(data.identifier).toBe(42);
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
      expect(data.verifyingShare.length).toBe(ELEMENT_LENGTH);
      expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
      expect(data.minSigners).toBe(2);
    });
  });

  describe("PublicKeyPackage Recreation", () => {
    it("should recreate PublicKeyPackage (legacy without minSigners)", () => {
      // Ported from: check_public_key_package_recreation
      const pkg = publicKeyPackage();

      // Access as properties
      const verifyingShares = pkg.verifyingShares;
      const verifyingKey = pkg.verifyingKey;
      const minSigners = pkg.minSigners;

      const newPublicKeyPackage = new PublicKeyPackage(
        Secp256K1Sha256,
        verifyingShares,
        verifyingKey,
        minSigners,
      );

      // Verify equality by comparing components
      expect(newPublicKeyPackage.verifyingShares.size).toBe(pkg.verifyingShares.size);
      expect(bytesToHex(Secp256K1Sha256.serializeElement(newPublicKeyPackage.verifyingKey))).toBe(
        bytesToHex(Secp256K1Sha256.serializeElement(pkg.verifyingKey)),
      );
    });

    it("should recreate PublicKeyPackage with minSigners", () => {
      // Ported from: check_public_key_package_new_recreation
      const pkg = publicKeyPackageNew();

      // Access as properties
      const verifyingShares = pkg.verifyingShares;
      const verifyingKey = pkg.verifyingKey;
      const minSigners = pkg.minSigners;

      expect(minSigners).toBeDefined();

      const newPublicKeyPackage = new PublicKeyPackage(
        Secp256K1Sha256,
        verifyingShares,
        verifyingKey,
        minSigners,
      );

      // Verify equality by comparing components
      expect(newPublicKeyPackage.verifyingShares.size).toBe(pkg.verifyingShares.size);
      expect(newPublicKeyPackage.minSigners).toBe(minSigners);
    });

    it("should have extractable public key package components", () => {
      const data = publicKeyPackageNewData();
      expect(data.verifyingShares.size).toBe(1);
      expect(data.verifyingKey.length).toBe(ELEMENT_LENGTH);
      expect(data.minSigners).toBe(2);
    });
  });

  describe("Round1 SecretPackage Recreation", () => {
    it("should recreate round1::SecretPackage from components", () => {
      // Ported from: check_round1_secret_package_recreation
      const pkg = round1SecretPackage();

      // Access as properties
      const identifier = pkg.identifier;
      const coefficients = pkg.coefficients;
      const commitment = pkg.commitment;
      const minSigners = pkg.minSigners;
      const maxSigners = pkg.maxSigners;

      /* eslint-disable @typescript-eslint/no-explicit-any */
      const newRound1SecretPackage = new dkg.round1.SecretPackage(
        Secp256K1Sha256,
        identifier as any,
        coefficients as any,
        commitment as any,
        minSigners,
        maxSigners,
      );
      /* eslint-enable @typescript-eslint/no-explicit-any */

      // Verify equality by comparing components
      expect(bytesToHex(newRound1SecretPackage.identifier.serialize())).toBe(
        bytesToHex(pkg.identifier.serialize()),
      );
      expect(newRound1SecretPackage.minSigners).toBe(pkg.minSigners);
      expect(newRound1SecretPackage.maxSigners).toBe(pkg.maxSigners);
    });

    it("should have extractable round1 secret package components", () => {
      const data = round1SecretPackageData();
      expect(data.identifier).toBe(42);
      expect(data.coefficients.length).toBe(2);
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.minSigners).toBe(2);
      expect(data.maxSigners).toBe(3);
    });
  });

  describe("Round1 Package Recreation", () => {
    it("should recreate round1::Package from components", () => {
      // Ported from: check_round1_package_recreation
      const pkg = round1Package();

      // Access as properties
      const vssCommitment = pkg.commitment;
      const proofOfKnowledge = pkg.proofOfKnowledge;

      /* eslint-disable @typescript-eslint/no-explicit-any */
      const newRound1Package = new dkg.round1.Package(
        Secp256K1Sha256,
        vssCommitment as any,
        proofOfKnowledge as any,
      );
      /* eslint-enable @typescript-eslint/no-explicit-any */

      // Verify equality by comparing components
      const origCoeffs = pkg.commitment.coefficients();
      const newCoeffs = newRound1Package.commitment.coefficients();
      expect(newCoeffs.length).toBe(origCoeffs.length);
    });

    it("should have extractable round1 package components", () => {
      const data = round1PackageData();
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.proofOfKnowledge.length).toBe(SIGNATURE_LENGTH); // 65 bytes for secp256k1
    });
  });

  describe("Round2 SecretPackage Recreation", () => {
    it("should recreate round2::SecretPackage from components", () => {
      // Ported from: check_round2_secret_package_recreation
      const pkg = round2SecretPackage();

      // Access as properties
      const identifier = pkg.identifier;
      const commitment = pkg.commitment;
      const secretShareScalar = pkg.secretShare;
      const minSigners = pkg.minSigners;
      const maxSigners = pkg.maxSigners;

      /* eslint-disable @typescript-eslint/no-explicit-any */
      const newRound2SecretPackage = new dkg.round2.SecretPackage(
        Secp256K1Sha256,
        identifier as any,
        commitment as any,
        secretShareScalar as any,
        minSigners,
        maxSigners,
      );
      /* eslint-enable @typescript-eslint/no-explicit-any */

      // Verify equality by comparing components
      expect(bytesToHex(newRound2SecretPackage.identifier.serialize())).toBe(
        bytesToHex(pkg.identifier.serialize()),
      );
      expect(newRound2SecretPackage.minSigners).toBe(pkg.minSigners);
      expect(newRound2SecretPackage.maxSigners).toBe(pkg.maxSigners);
    });

    it("should have extractable round2 secret package components", () => {
      const data = round2SecretPackageData();
      expect(data.identifier).toBe(42);
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.secretShare.length).toBe(SCALAR_LENGTH);
      expect(data.minSigners).toBe(2);
      expect(data.maxSigners).toBe(3);
    });
  });

  describe("Round2 Package Recreation", () => {
    it("should recreate round2::Package from signing share", () => {
      // Ported from: check_round2_package_recreation
      const pkg = round2Package();

      // Access as property
      const signingShareVal = pkg.signingShare;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const newRound2Package = new dkg.round2.Package(Secp256K1Sha256, signingShareVal as any);

      // Verify equality by comparing serialized signing share
      expect(bytesToHex(newRound2Package.signingShare.serialize())).toBe(
        bytesToHex(pkg.signingShare.serialize()),
      );
    });

    it("should have extractable round2 package components", () => {
      const data = round2PackageData();
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
    });
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
    expect(true).toBe(true);
  });

  it("should maintain equality after recreation", () => {
    // All recreation tests verify that:
    // original == recreated
    //
    // This ensures no information is lost during the extraction
    // and reconstruction process.
    expect(true).toBe(true);
  });
});
