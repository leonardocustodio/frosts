/**
 * Recreation tests for FROST Ristretto255-SHA512.
 * Ported from frost-ristretto255/tests/recreation_tests.rs
 *
 * These tests verify that packages can be recreated from their components,
 * which demonstrates that they can be serialized and deserialized as the
 * user wishes (e.g., using custom serialization formats).
 */

import { describe, it, expect } from "vitest";
import {
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
  element1,
  element2 as _element2,
  scalar1,
  proofOfKnowledge as _proofOfKnowledge,
  bytesToHex,
} from "./helpers/samples.js";
import { SCALAR_LENGTH, ELEMENT_LENGTH } from "./helpers/index.js";
import {
  Ristretto255Sha512,
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
import { SigningPackageImpl, round1, round2 } from "@frosts/core";

const ciphersuite = Ristretto255Sha512;

describe("FROST Ristretto255-SHA512 Recreation Tests", () => {
  describe("SigningNonces Recreation", () => {
    it("should recreate SigningNonces from component nonces", () => {
      // Ported from: check_signing_nonces_recreation
      // Create nonces from raw scalars (need to wrap in Nonce objects)
      const data = signingNoncesData();
      const hidingNonce = Nonce.fromScalar(ciphersuite, ciphersuite.deserializeScalar(data.hiding));
      const bindingNonce = Nonce.fromScalar(
        ciphersuite,
        ciphersuite.deserializeScalar(data.binding),
      );
      const nonces = SigningNonces.fromNonces(ciphersuite, hidingNonce, bindingNonce);

      // Extract components (these are Nonce objects via readonly properties)
      const extractedHiding = nonces.hiding;
      const extractedBinding = nonces.binding;

      // Recreate from components (extract scalars and wrap back into Nonce)
      const newHidingNonce = Nonce.fromScalar(ciphersuite, extractedHiding.toScalar());
      const newBindingNonce = Nonce.fromScalar(ciphersuite, extractedBinding.toScalar());
      const newNonces = SigningNonces.fromNonces(ciphersuite, newHidingNonce, newBindingNonce);

      expect(nonces.equals(newNonces)).toBe(true);
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
      const data = signingCommitmentsData();
      const hiding = NonceCommitment.fromElement(
        ciphersuite,
        ciphersuite.deserializeElement(data.hiding),
      );
      const binding = NonceCommitment.fromElement(
        ciphersuite,
        ciphersuite.deserializeElement(data.binding),
      );
      const commitments = new SigningCommitments(ciphersuite, hiding, binding);

      // Extract components
      const extractedHiding = commitments.hiding;
      const extractedBinding = commitments.binding;

      // Recreate from components
      const newCommitments = new SigningCommitments(ciphersuite, extractedHiding, extractedBinding);

      expect(commitments.equals(newCommitments)).toBe(true);
    });

    it("should have extractable commitment components", () => {
      const data = signingCommitmentsData();
      expect(data.hiding.length).toBe(ELEMENT_LENGTH);
      expect(data.binding.length).toBe(ELEMENT_LENGTH);
    });
  });

  describe("SigningPackage Recreation", () => {
    it("should recreate SigningPackage from commitments and message", () => {
      // Ported from: check_signing_package_recreation
      const data = signingPackageData();

      // Create identifier
      const identifier = Identifier.fromU16(ciphersuite, data.identifier);

      // Create commitments
      const hiding = NonceCommitment.fromElement(
        ciphersuite,
        ciphersuite.deserializeElement(data.commitments.hiding),
      );
      const binding = NonceCommitment.fromElement(
        ciphersuite,
        ciphersuite.deserializeElement(data.commitments.binding),
      );
      const commitments = new SigningCommitments(ciphersuite, hiding, binding);

      // Create signing package
      const signingCommitments = new Map();
      signingCommitments.set(identifier, commitments);
      const signingPackage = new SigningPackageImpl(ciphersuite, signingCommitments, data.message);

      // Extract components
      const extractedCommitments = signingPackage.signingCommitments;
      const extractedMessage = signingPackage.message;

      // Recreate from components
      const newSigningPackage = new SigningPackageImpl(
        ciphersuite,
        extractedCommitments,
        extractedMessage,
      );

      expect(signingPackage.equals(newSigningPackage)).toBe(true);
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
      const data = signatureShareData();
      const signatureShare = SignatureShare.deserialize(ciphersuite, data.share);

      // Serialize
      const encoded = signatureShare.serialize();

      // Deserialize (recreate)
      const newSignatureShare = SignatureShare.deserialize(ciphersuite, encoded);

      expect(signatureShare.equals(newSignatureShare)).toBe(true);
    });

    it("should recreate SignatureShare from scalar", () => {
      // Test recreation via scalar extraction
      const scalar = ciphersuite.deserializeScalar(scalar1());
      const signatureShare = SignatureShare.fromScalar(ciphersuite, scalar);

      // Extract scalar
      const extractedScalar = signatureShare.toScalar();

      // Recreate from scalar
      const newSignatureShare = SignatureShare.fromScalar(ciphersuite, extractedScalar);

      expect(signatureShare.equals(newSignatureShare)).toBe(true);
    });

    it("should have serializable share data", () => {
      const data = signatureShareData();
      expect(data.share.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("SecretShare Recreation", () => {
    it("should recreate SecretShare from components", () => {
      // Ported from: check_secret_share_recreation
      const data = secretShareData();

      // Create components
      const identifier = Identifier.fromU16(ciphersuite, data.identifier);
      const signingShare = SigningShare.deserialize(ciphersuite, data.signingShare);
      const coefficientCommitments = data.commitment.map(
        (bytes) => new CoefficientCommitment(ciphersuite, ciphersuite.deserializeElement(bytes)),
      );
      const commitment = new VerifiableSecretSharingCommitment(ciphersuite, coefficientCommitments);

      // Create secret share
      const secretShare = new SecretShare(ciphersuite, identifier, signingShare, commitment);

      // Extract components
      const extractedIdentifier = secretShare.identifier;
      const extractedSigningShare = secretShare.signingShare;
      const extractedCommitment = secretShare.commitment;

      // Recreate from components
      const newSecretShare = new SecretShare(
        ciphersuite,
        extractedIdentifier.clone(),
        extractedSigningShare.clone(),
        extractedCommitment.clone(),
      );

      expect(secretShare.equals(newSecretShare)).toBe(true);
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
      const data = keyPackageData();

      // Create components
      const identifier = Identifier.fromU16(ciphersuite, data.identifier);
      const signingShare = SigningShare.deserialize(ciphersuite, data.signingShare);
      const verifyingShare = VerifyingShare.deserialize(ciphersuite, data.verifyingShare);
      const verifyingKey = ciphersuite.deserializeElement(data.verifyingKey);
      const minSigners = data.minSigners;

      // Create key package
      const keyPackage = new KeyPackage(
        ciphersuite,
        identifier,
        signingShare,
        verifyingShare,
        verifyingKey,
        minSigners,
      );

      // Extract components
      const extractedIdentifier = keyPackage.identifier;
      const extractedSigningShare = keyPackage.signingShare;
      const extractedVerifyingShare = keyPackage.verifyingShare;
      const extractedVerifyingKey = keyPackage.verifyingKey;
      const extractedMinSigners = keyPackage.minSigners;

      // Recreate from components
      const newKeyPackage = new KeyPackage(
        ciphersuite,
        extractedIdentifier.clone(),
        extractedSigningShare.clone(),
        extractedVerifyingShare.clone(),
        extractedVerifyingKey,
        extractedMinSigners,
      );

      expect(keyPackage.equals(newKeyPackage)).toBe(true);
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
      const data = publicKeyPackageData();

      // Create verifying shares map
      const verifyingShares = new Map<string, VerifyingShare<typeof ciphersuite>>();
      for (const [id, share] of data.verifyingShares) {
        const identifier = Identifier.fromU16(ciphersuite, id);
        const verifyingShare = VerifyingShare.deserialize(ciphersuite, share);
        verifyingShares.set(bytesToHex(identifier.serialize()), verifyingShare);
      }

      // Create public key package (without minSigners)
      const verifyingKey = ciphersuite.deserializeElement(data.verifyingKey);
      const publicKeyPackage = new PublicKeyPackage(
        ciphersuite,
        verifyingShares,
        verifyingKey,
        undefined,
      );

      // Extract components
      const extractedShares = publicKeyPackage.verifyingShares;
      const extractedKey = publicKeyPackage.verifyingKey;
      const extractedMinSigners = publicKeyPackage.minSigners;

      // Recreate from components
      const clonedShares = new Map<string, VerifyingShare<typeof ciphersuite>>();
      for (const [key, share] of extractedShares) {
        clonedShares.set(key, share.clone());
      }
      const newPublicKeyPackage = new PublicKeyPackage(
        ciphersuite,
        clonedShares,
        extractedKey,
        extractedMinSigners,
      );

      expect(publicKeyPackage.equals(newPublicKeyPackage)).toBe(true);
    });

    it("should recreate PublicKeyPackage with minSigners", () => {
      // Ported from: check_public_key_package_new_recreation
      const data = publicKeyPackageNewData();

      // Create verifying shares map
      const verifyingShares = new Map<string, VerifyingShare<typeof ciphersuite>>();
      for (const [id, share] of data.verifyingShares) {
        const identifier = Identifier.fromU16(ciphersuite, id);
        const verifyingShare = VerifyingShare.deserialize(ciphersuite, share);
        verifyingShares.set(bytesToHex(identifier.serialize()), verifyingShare);
      }

      // Create public key package (with minSigners)
      const verifyingKey = ciphersuite.deserializeElement(data.verifyingKey);
      const publicKeyPackage = new PublicKeyPackage(
        ciphersuite,
        verifyingShares,
        verifyingKey,
        data.minSigners,
      );

      // Extract components
      const extractedShares = publicKeyPackage.verifyingShares;
      const extractedKey = publicKeyPackage.verifyingKey;
      const extractedMinSigners = publicKeyPackage.minSigners;

      // Recreate from components
      const clonedShares = new Map<string, VerifyingShare<typeof ciphersuite>>();
      for (const [key, share] of extractedShares) {
        clonedShares.set(key, share.clone());
      }
      const newPublicKeyPackage = new PublicKeyPackage(
        ciphersuite,
        clonedShares,
        extractedKey,
        extractedMinSigners,
      );

      expect(publicKeyPackage.equals(newPublicKeyPackage)).toBe(true);
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
      const data = round1SecretPackageData();

      // Create components
      const identifier = Identifier.fromU16(ciphersuite, data.identifier);
      const coefficients = data.coefficients.map((bytes) => ciphersuite.deserializeScalar(bytes));
      const coefficientCommitments = data.commitment.map(
        (bytes) => new CoefficientCommitment(ciphersuite, ciphersuite.deserializeElement(bytes)),
      );
      const commitment = new VerifiableSecretSharingCommitment(ciphersuite, coefficientCommitments);
      const minSigners = data.minSigners;
      const maxSigners = data.maxSigners;

      // Create round1 secret package
      const round1SecretPackage = new round1.SecretPackage(
        ciphersuite,
        identifier,
        coefficients,
        commitment,
        minSigners,
        maxSigners,
      );

      // Extract components
      const extractedIdentifier = round1SecretPackage.identifier;
      const extractedCoefficients = round1SecretPackage.coefficients();
      const extractedCommitment = round1SecretPackage.commitment;
      const extractedMinSigners = round1SecretPackage.minSigners;
      const extractedMaxSigners = round1SecretPackage.maxSigners;

      // Recreate from components
      const newRound1SecretPackage = new round1.SecretPackage(
        ciphersuite,
        extractedIdentifier.clone(),
        [...extractedCoefficients],
        extractedCommitment.clone(),
        extractedMinSigners,
        extractedMaxSigners,
      );

      expect(round1SecretPackage.equals(newRound1SecretPackage)).toBe(true);
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
      const data = round1PackageData();

      // Create components
      const coefficientCommitments = data.commitment.map(
        (bytes) => new CoefficientCommitment(ciphersuite, ciphersuite.deserializeElement(bytes)),
      );
      const commitment = new VerifiableSecretSharingCommitment(ciphersuite, coefficientCommitments);

      // Parse proof of knowledge: first 32 bytes is R, next 32 is z
      const pokBytes = data.proofOfKnowledge;
      const R = ciphersuite.deserializeElement(pokBytes.slice(0, 32));
      const z = ciphersuite.deserializeScalar(pokBytes.slice(32, 64));
      const pok = { R, z };

      // Create round1 package
      const round1Package = new round1.Package(ciphersuite, commitment, pok);

      // Extract components
      const extractedCommitment = round1Package.commitment;
      const extractedPok = round1Package.proofOfKnowledge;

      // Recreate from components
      const newRound1Package = new round1.Package(ciphersuite, extractedCommitment.clone(), {
        R: extractedPok.R,
        z: extractedPok.z,
      });

      expect(round1Package.equals(newRound1Package)).toBe(true);
    });

    it("should have extractable round1 package components", () => {
      const data = round1PackageData();
      expect(data.commitment.length).toBeGreaterThan(0);
      expect(data.proofOfKnowledge.length).toBe(ELEMENT_LENGTH + SCALAR_LENGTH);
    });
  });

  describe("Round2 SecretPackage Recreation", () => {
    it("should recreate round2::SecretPackage from components", () => {
      // Ported from: check_round2_secret_package_recreation
      const data = round2SecretPackageData();

      // Create components
      const identifier = Identifier.fromU16(ciphersuite, data.identifier);
      const coefficientCommitments = data.commitment.map(
        (bytes) => new CoefficientCommitment(ciphersuite, ciphersuite.deserializeElement(bytes)),
      );
      const commitment = new VerifiableSecretSharingCommitment(ciphersuite, coefficientCommitments);
      const secretShare = ciphersuite.deserializeScalar(data.secretShare);
      const minSigners = data.minSigners;
      const maxSigners = data.maxSigners;

      // Create round2 secret package
      const round2SecretPackage = new round2.SecretPackage(
        ciphersuite,
        identifier,
        commitment,
        secretShare,
        minSigners,
        maxSigners,
      );

      // Extract components
      const extractedIdentifier = round2SecretPackage.identifier;
      const extractedCommitment = round2SecretPackage.commitment;
      const extractedSecretShare = round2SecretPackage.secretShare();
      const extractedMinSigners = round2SecretPackage.minSigners;
      const extractedMaxSigners = round2SecretPackage.maxSigners;

      // Recreate from components
      const newRound2SecretPackage = new round2.SecretPackage(
        ciphersuite,
        extractedIdentifier.clone(),
        extractedCommitment.clone(),
        extractedSecretShare,
        extractedMinSigners,
        extractedMaxSigners,
      );

      expect(round2SecretPackage.equals(newRound2SecretPackage)).toBe(true);
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
      const data = round2PackageData();

      // Create components
      const signingShare = SigningShare.deserialize(ciphersuite, data.signingShare);

      // Create round2 package
      const round2Package = new round2.Package(ciphersuite, signingShare);

      // Extract components
      const extractedSigningShare = round2Package.signingShare;

      // Recreate from components
      const newRound2Package = new round2.Package(ciphersuite, extractedSigningShare.clone());

      expect(round2Package.equals(newRound2Package)).toBe(true);
    });

    it("should have extractable round2 package components", () => {
      const data = round2PackageData();
      expect(data.signingShare.length).toBe(SCALAR_LENGTH);
    });
  });

  describe("Identifier Recreation", () => {
    it("should recreate Identifier via serialization", () => {
      const identifier = Identifier.fromU16(ciphersuite, 42);

      // Serialize
      const encoded = identifier.serialize();

      // Deserialize (recreate)
      const newIdentifier = Identifier.deserialize(ciphersuite, encoded);

      expect(identifier.equals(newIdentifier)).toBe(true);
    });

    it("should recreate Identifier from scalar", () => {
      const identifier = Identifier.fromU16(ciphersuite, 42);

      // Extract scalar
      const _scalar = identifier.toScalar();
      void _scalar; // Demonstrates that scalar can be extracted for custom serialization

      // Recreate - since we can't directly create from scalar, we use serialize/deserialize
      const serialized = identifier.serialize();
      const newIdentifier = Identifier.deserialize(ciphersuite, serialized);

      expect(identifier.equals(newIdentifier)).toBe(true);
    });
  });

  describe("SigningShare Recreation", () => {
    it("should recreate SigningShare via serialization", () => {
      const scalarVal = ciphersuite.deserializeScalar(scalar1());
      const signingShare = new SigningShare(ciphersuite, scalarVal);

      // Serialize
      const encoded = signingShare.serialize();

      // Deserialize (recreate)
      const newSigningShare = SigningShare.deserialize(ciphersuite, encoded);

      expect(signingShare.equals(newSigningShare)).toBe(true);
    });
  });

  describe("VerifyingShare Recreation", () => {
    it("should recreate VerifyingShare via serialization", () => {
      const element = ciphersuite.deserializeElement(element1());
      const verifyingShare = new VerifyingShare(ciphersuite, element);

      // Serialize
      const encoded = verifyingShare.serialize();

      // Deserialize (recreate)
      const newVerifyingShare = VerifyingShare.deserialize(ciphersuite, encoded);

      expect(verifyingShare.equals(newVerifyingShare)).toBe(true);
    });
  });

  describe("CoefficientCommitment Recreation", () => {
    it("should recreate CoefficientCommitment via serialization", () => {
      const element = ciphersuite.deserializeElement(element1());
      const coefficientCommitment = new CoefficientCommitment(ciphersuite, element);

      // Serialize
      const encoded = coefficientCommitment.serialize();

      // Deserialize (recreate)
      const newCoefficientCommitment = CoefficientCommitment.deserialize(ciphersuite, encoded);

      expect(coefficientCommitment.equals(newCoefficientCommitment)).toBe(true);
    });
  });

  describe("VerifiableSecretSharingCommitment Recreation", () => {
    it("should recreate VerifiableSecretSharingCommitment via serialization", () => {
      const element = ciphersuite.deserializeElement(element1());
      const coefficient = new CoefficientCommitment(ciphersuite, element);
      const commitment = new VerifiableSecretSharingCommitment(ciphersuite, [coefficient]);

      // Serialize
      const encoded = commitment.serialize();

      // Deserialize (recreate)
      const newCommitment = VerifiableSecretSharingCommitment.deserialize(ciphersuite, encoded);

      expect(commitment.equals(newCommitment)).toBe(true);
    });

    it("should recreate via whole serialization", () => {
      const element = ciphersuite.deserializeElement(element1());
      const coefficient = new CoefficientCommitment(ciphersuite, element);
      const commitment = new VerifiableSecretSharingCommitment(ciphersuite, [coefficient]);

      // Serialize as whole
      const encodedWhole = commitment.serializeWhole();

      // Deserialize (recreate)
      const newCommitment = VerifiableSecretSharingCommitment.deserializeWhole(
        ciphersuite,
        encodedWhole,
      );

      expect(commitment.equals(newCommitment)).toBe(true);
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

    const keyPackage = new KeyPackage(
      ciphersuite,
      Identifier.fromU16(ciphersuite, 42),
      new SigningShare(ciphersuite, ciphersuite.deserializeScalar(scalar1())),
      new VerifyingShare(ciphersuite, ciphersuite.deserializeElement(element1())),
      ciphersuite.deserializeElement(element1()),
      2,
    );

    // Extract all components
    const id = keyPackage.identifier;
    const sigShare = keyPackage.signingShare;
    const verShare = keyPackage.verifyingShare;
    const verKey = keyPackage.verifyingKey;
    const minSig = keyPackage.minSigners;

    // Store/transmit/transform components as needed...
    // Then reconstruct:
    const reconstructed = new KeyPackage(
      ciphersuite,
      id.clone(),
      sigShare.clone(),
      verShare.clone(),
      verKey,
      minSig,
    );

    expect(keyPackage.equals(reconstructed)).toBe(true);
  });

  it("should maintain equality after recreation", () => {
    // All recreation tests verify that:
    // original == recreated
    //
    // This ensures no information is lost during the extraction
    // and reconstruction process.

    const original = SignatureShare.fromScalar(
      ciphersuite,
      ciphersuite.deserializeScalar(scalar1()),
    );

    // Recreation via serialization
    const serialized = original.serialize();
    const recreated = SignatureShare.deserialize(ciphersuite, serialized);

    expect(original.equals(recreated)).toBe(true);

    // Recreation via component extraction
    const scalar = original.toScalar();
    const recreated2 = SignatureShare.fromScalar(ciphersuite, scalar);

    expect(original.equals(recreated2)).toBe(true);
  });

  it("should work with clone as a form of recreation", () => {
    // Clone is essentially recreation from the same components
    const original = Identifier.fromU16(ciphersuite, 42);
    const cloned = original.clone();

    expect(original.equals(cloned)).toBe(true);
    expect(original).not.toBe(cloned); // Different instances
  });
});
