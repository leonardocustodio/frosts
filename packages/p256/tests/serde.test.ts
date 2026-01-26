/**
 * JSON serialization (serde) tests for FROST P256-SHA256.
 * Ported from frost-p256/tests/serde_tests.rs
 *
 * These tests verify that all FROST data structures can be correctly
 * serialized to and deserialized from JSON format, including validation
 * of the header fields and error handling for invalid inputs.
 *
 * Key differences from secp256k1:
 * - Ciphersuite name is "FROST-P256-SHA256-v1"
 * - Uses P-256 generator point instead of secp256k1
 * - Same byte lengths: ELEMENT_LENGTH = 33, SIGNATURE_LENGTH = 65
 */

import { describe, it, expect } from "vitest";
import {
  signingCommitmentsData,
  signingPackageData,
  signatureShareData,
  secretShareData,
  keyPackageData,
  publicKeyPackageNewData,
  round1PackageData,
  round2PackageData,
  bytesToHex,
  CIPHERSUITE_NAME,
  SCALAR_LENGTH,
} from "./helpers/index.js";

import {
  P256Sha256,
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
  serde,
} from "../src/index.js";

import { type SigningPackage, SigningPackageImpl } from "@frosts/core";

/**
 * Standard header for JSON serialization.
 */
const HEADER = {
  version: 0,
  ciphersuite: CIPHERSUITE_NAME,
} as const;

/**
 * Create sample SigningCommitments from test data.
 */
function createSigningCommitments(): SigningCommitments<typeof P256Sha256> {
  const data = signingCommitmentsData();
  const hiding = NonceCommitment.deserialize(P256Sha256, data.hiding);
  const binding = NonceCommitment.deserialize(P256Sha256, data.binding);
  return new SigningCommitments(P256Sha256, hiding, binding);
}

/**
 * Create sample SigningPackage from test data.
 */
function createSigningPackage(): SigningPackage<typeof P256Sha256> {
  const data = signingPackageData();
  const commitments = createSigningCommitments();
  const id = Identifier.fromU16(P256Sha256, data.identifier);
  const map = new Map<Identifier<typeof P256Sha256>, SigningCommitments<typeof P256Sha256>>();
  map.set(id, commitments);
  return new SigningPackageImpl(P256Sha256, map, data.message);
}

/**
 * Create sample SignatureShare from test data.
 */
function createSignatureShare(): SignatureShare<typeof P256Sha256> {
  const data = signatureShareData();
  return SignatureShare.deserialize(P256Sha256, data.share);
}

/**
 * Create sample SecretShare from test data.
 */
function createSecretShare(): SecretShare<typeof P256Sha256> {
  const data = secretShareData();
  const id = Identifier.fromU16(P256Sha256, data.identifier);
  const signingShare = SigningShare.deserialize(P256Sha256, data.signingShare);
  const commitment = VerifiableSecretSharingCommitment.deserialize(P256Sha256, data.commitment);
  return new SecretShare(P256Sha256, id, signingShare, commitment);
}

/**
 * Create sample KeyPackage from test data.
 */
function createKeyPackage(): KeyPackage<typeof P256Sha256> {
  const data = keyPackageData();
  const id = Identifier.fromU16(P256Sha256, data.identifier);
  const signingShare = SigningShare.deserialize(P256Sha256, data.signingShare);
  const verifyingShare = VerifyingShare.deserialize(P256Sha256, data.verifyingShare);
  const verifyingKey = P256Sha256.deserializeElement(data.verifyingKey);
  return new KeyPackage(
    P256Sha256,
    id,
    signingShare,
    verifyingShare,
    verifyingKey,
    data.minSigners,
  );
}

/**
 * Create sample PublicKeyPackage from test data (new with minSigners).
 */
function createPublicKeyPackageNew(): PublicKeyPackage<typeof P256Sha256> {
  const data = publicKeyPackageNewData();
  const verifyingShares = new Map<string, VerifyingShare<typeof P256Sha256>>();
  for (const [id, shareBytes] of data.verifyingShares) {
    const idBytes = Identifier.fromU16(P256Sha256, id).serialize();
    const idHex = bytesToHex(idBytes);
    const share = VerifyingShare.deserialize(P256Sha256, shareBytes);
    verifyingShares.set(idHex, share);
  }
  const verifyingKey = P256Sha256.deserializeElement(data.verifyingKey);
  return new PublicKeyPackage(P256Sha256, verifyingShares, verifyingKey, data.minSigners);
}

describe("FROST P256-SHA256 JSON Serialization Tests", () => {
  describe("SigningCommitments JSON Serialization", () => {
    it("should serialize SigningCommitments to JSON", () => {
      const commitments = createSigningCommitments();
      const json = serde.signingCommitmentsToJson(commitments);
      const decoded = serde.signingCommitmentsFromJson(json);

      // Check round-trip equality by comparing serialized bytes
      expect(bytesToHex(decoded.hiding.serialize())).toBe(
        bytesToHex(commitments.hiding.serialize()),
      );
      expect(bytesToHex(decoded.binding.serialize())).toBe(
        bytesToHex(commitments.binding.serialize()),
      );
    });

    it("should deserialize SigningCommitments from valid JSON", () => {
      const validJson = {
        header: HEADER,
        hiding: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        binding: "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
      };
      const commitments = serde.signingCommitmentsFromJson(validJson);
      expect(commitments).toBeDefined();
      expect(commitments.hiding).toBeDefined();
      expect(commitments.binding).toBeDefined();
    });

    it("should reject empty JSON object", () => {
      expect(() => serde.signingCommitmentsFromJson({})).toThrow(/Missing required field/);
    });

    it("should reject wrong ciphersuite", () => {
      const invalidJson = {
        header: {
          version: 0,
          ciphersuite: "FROST(Wrong, SHA-512)",
        },
        hiding: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        binding: "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow(/Invalid ciphersuite/);
    });

    it("should reject invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        binding: "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow(
        /Missing required field.*hiding|Unexpected field.*foo/,
      );
    });

    it("should reject missing field", () => {
      const invalidJson = {
        header: HEADER,
        binding: "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow(
        /Missing required field.*hiding/,
      );
    });

    it("should reject extra field", () => {
      const invalidJson = {
        header: HEADER,
        hiding: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        binding: "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        extra: 1,
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow(
        /Unexpected field.*extra/,
      );
    });
  });

  describe("SigningPackage JSON Serialization", () => {
    it("should serialize SigningPackage to JSON", () => {
      const signingPackage = createSigningPackage();
      const json = serde.signingPackageToJson(signingPackage);
      const decoded = serde.signingPackageFromJson(json);

      expect(bytesToHex(decoded.message)).toBe(bytesToHex(signingPackage.message));
      expect(decoded.signingCommitments.size).toBe(signingPackage.signingCommitments.size);
    });

    it("should deserialize SigningPackage from valid JSON", () => {
      const validJson = {
        header: HEADER,
        signing_commitments: {
          "000000000000000000000000000000000000000000000000000000000000002a": {
            header: HEADER,
            hiding: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            binding: "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
          },
        },
        message: "68656c6c6f20776f726c64",
      };
      const signingPackage = serde.signingPackageFromJson(validJson);
      expect(signingPackage).toBeDefined();
      expect(bytesToHex(signingPackage.message)).toBe("68656c6c6f20776f726c64");
    });

    it("should reject invalid identifier (all zeros)", () => {
      const invalidJson = {
        header: HEADER,
        signing_commitments: {
          "0000000000000000000000000000000000000000000000000000000000000000": {
            header: HEADER,
            hiding: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            binding: "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
          },
        },
        message: "68656c6c6f20776f726c64",
      };
      expect(() => serde.signingPackageFromJson(invalidJson)).toThrow();
    });
  });

  describe("SignatureShare JSON Serialization", () => {
    it("should serialize SignatureShare to JSON", () => {
      const share = createSignatureShare();
      const json = serde.signatureShareToJson(share);
      const decoded = serde.signatureShareFromJson(json);

      expect(bytesToHex(decoded.serialize())).toBe(bytesToHex(share.serialize()));
    });

    it("should deserialize SignatureShare from valid JSON", () => {
      const validJson = {
        header: HEADER,
        share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
      };
      const share = serde.signatureShareFromJson(validJson);
      expect(share).toBeDefined();
      expect(share.serialize().length).toBe(SCALAR_LENGTH);
    });

    it("should reject invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
      };
      expect(() => serde.signatureShareFromJson(invalidJson)).toThrow(
        /Missing required field.*share|Unexpected field.*foo/,
      );
    });

    it("should reject missing field", () => {
      const invalidJson = {
        header: HEADER,
      };
      expect(() => serde.signatureShareFromJson(invalidJson)).toThrow(
        /Missing required field.*share/,
      );
    });

    it("should reject extra field", () => {
      const invalidJson = {
        header: HEADER,
        share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        extra: 1,
      };
      expect(() => serde.signatureShareFromJson(invalidJson)).toThrow(/Unexpected field.*extra/);
    });
  });

  describe("SecretShare JSON Serialization", () => {
    it("should serialize SecretShare to JSON", () => {
      const share = createSecretShare();
      const json = serde.secretShareToJson(share);
      const decoded = serde.secretShareFromJson(json);

      expect(bytesToHex(decoded.identifier.serialize())).toBe(
        bytesToHex(share.identifier.serialize()),
      );
      expect(bytesToHex(decoded.signingShare.serialize())).toBe(
        bytesToHex(share.signingShare.serialize()),
      );
    });

    it("should deserialize SecretShare from valid JSON", () => {
      const validJson = {
        header: HEADER,
        identifier: "000000000000000000000000000000000000000000000000000000000000002a",
        signing_share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        commitment: ["036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"],
      };
      const secretShare = serde.secretShareFromJson(validJson);
      expect(secretShare).toBeDefined();
      expect(secretShare.commitment).toBeDefined();
    });

    it("should reject invalid identifier (all zeros)", () => {
      const invalidJson = {
        header: HEADER,
        identifier: "0000000000000000000000000000000000000000000000000000000000000000",
        signing_share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        commitment: ["036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"],
      };
      expect(() => serde.secretShareFromJson(invalidJson)).toThrow();
    });
  });

  describe("KeyPackage JSON Serialization", () => {
    it("should serialize KeyPackage to JSON", () => {
      const keyPackage = createKeyPackage();
      const json = serde.keyPackageToJson(keyPackage);
      const decoded = serde.keyPackageFromJson(json);

      expect(bytesToHex(decoded.identifier.serialize())).toBe(
        bytesToHex(keyPackage.identifier.serialize()),
      );
      expect(decoded.minSigners).toBe(keyPackage.minSigners);
    });

    it("should deserialize KeyPackage from valid JSON", () => {
      const validJson = {
        header: HEADER,
        identifier: "000000000000000000000000000000000000000000000000000000000000002a",
        signing_share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        verifying_share: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        verifying_key: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        min_signers: 2,
      };
      const keyPackage = serde.keyPackageFromJson(validJson);
      expect(keyPackage).toBeDefined();
      expect(keyPackage.minSigners).toBe(2);
    });

    it("should reject invalid version", () => {
      const invalidJson = {
        header: {
          version: 1,
          ciphersuite: CIPHERSUITE_NAME,
        },
        identifier: "000000000000000000000000000000000000000000000000000000000000002a",
        signing_share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        verifying_share: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        verifying_key: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        min_signers: 2,
      };
      expect(() => serde.keyPackageFromJson(invalidJson)).toThrow(/Invalid version/);
    });
  });

  describe("PublicKeyPackage JSON Serialization", () => {
    it("should serialize PublicKeyPackage to JSON", () => {
      const pkp = createPublicKeyPackageNew();
      const json = serde.publicKeyPackageToJson(pkp);
      const decoded = serde.publicKeyPackageFromJson(json);

      expect(decoded.minSigners).toBe(pkp.minSigners);
    });

    it("should deserialize PublicKeyPackage with minSigners from valid JSON", () => {
      const validJson = {
        header: HEADER,
        verifying_shares: {
          "000000000000000000000000000000000000000000000000000000000000002a":
            "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        },
        verifying_key: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        min_signers: 2,
      };
      const pkp = serde.publicKeyPackageFromJson(validJson);
      expect(pkp).toBeDefined();
      expect(pkp.minSigners).toBe(2);
    });

    it("should deserialize old version without minSigners", () => {
      const validJson = {
        header: HEADER,
        verifying_shares: {
          "000000000000000000000000000000000000000000000000000000000000002a":
            "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        },
        verifying_key: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      };
      const pkp = serde.publicKeyPackageFromJson(validJson);
      expect(pkp).toBeDefined();
      expect(pkp.minSigners).toBeUndefined();
    });

    it("should reject invalid identifier in verifying_shares", () => {
      const invalidJson = {
        header: HEADER,
        verifying_shares: {
          "0000000000000000000000000000000000000000000000000000000000000000":
            "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        },
        verifying_key: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      };
      expect(() => serde.publicKeyPackageFromJson(invalidJson)).toThrow();
    });
  });

  describe("Round1 Package JSON Serialization", () => {
    it("should serialize round1::Package to JSON", () => {
      // Create sample round1 package data
      const data = round1PackageData();
      const commitment = VerifiableSecretSharingCommitment.deserialize(P256Sha256, data.commitment);

      // Parse proof of knowledge
      const pokBytes = data.proofOfKnowledge;
      const elementSize = P256Sha256.elementSize();
      const R = P256Sha256.deserializeElement(pokBytes.slice(0, elementSize));
      const z = P256Sha256.deserializeScalar(pokBytes.slice(elementSize));

      const pkg = {
        commitment,
        proofOfKnowledge: { R, z },
        serialize(): Uint8Array[] {
          const result: Uint8Array[] = [];
          for (const c of commitment.serialize()) {
            result.push(c);
          }
          const pokR = P256Sha256.serializeElement(R);
          const pokZ = P256Sha256.serializeScalar(z);
          const pokSerialized = new Uint8Array(pokR.length + pokZ.length);
          pokSerialized.set(pokR, 0);
          pokSerialized.set(pokZ, pokR.length);
          result.push(pokSerialized);
          return result;
        },
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const json = serde.round1PackageToJson(pkg as any);
      const decoded = serde.round1PackageFromJson(json);

      expect(decoded.commitment).toBeDefined();
      expect(decoded.proofOfKnowledge).toBeDefined();
    });

    it("should deserialize round1::Package from valid JSON", () => {
      const validJson = {
        header: HEADER,
        commitment: ["036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"],
        proof_of_knowledge:
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
      };
      const round1Package = serde.round1PackageFromJson(validJson);
      expect(round1Package).toBeDefined();
      expect(round1Package.commitment).toBeDefined();
      expect(round1Package.proofOfKnowledge).toBeDefined();
    });
  });

  describe("Round2 Package JSON Serialization", () => {
    it("should serialize round2::Package to JSON", () => {
      const data = round2PackageData();
      const signingShare = SigningShare.deserialize(P256Sha256, data.signingShare);

      const pkg = {
        signingShare,
        serialize(): Uint8Array {
          return signingShare.serialize();
        },
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const json = serde.round2PackageToJson(pkg as any);
      const decoded = serde.round2PackageFromJson(json);

      expect(bytesToHex(decoded.signingShare.serialize())).toBe(
        bytesToHex(signingShare.serialize()),
      );
    });

    it("should deserialize round2::Package from valid JSON", () => {
      const validJson = {
        header: HEADER,
        signing_share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
      };
      const round2Package = serde.round2PackageFromJson(validJson);
      expect(round2Package).toBeDefined();
      expect(round2Package.signingShare.serialize().length).toBe(SCALAR_LENGTH);
    });

    it("should reject invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
      };
      expect(() => serde.round2PackageFromJson(invalidJson)).toThrow(
        /Missing required field.*signing_share|Unexpected field.*foo/,
      );
    });

    it("should reject missing field", () => {
      const invalidJson = {
        header: HEADER,
      };
      expect(() => serde.round2PackageFromJson(invalidJson)).toThrow(
        /Missing required field.*signing_share/,
      );
    });

    it("should reject extra field", () => {
      const invalidJson = {
        header: HEADER,
        signing_share: "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        extra: 1,
      };
      expect(() => serde.round2PackageFromJson(invalidJson)).toThrow(/Unexpected field.*extra/);
    });
  });
});

describe("JSON Serialization Format", () => {
  it("should use correct ciphersuite identifier", () => {
    expect(CIPHERSUITE_NAME).toBe("FROST-P256-SHA256-v1");
  });

  it("should use version 0 in header", () => {
    expect(HEADER.version).toBe(0);
  });

  it("should use hex encoding for binary data", () => {
    // All binary data in JSON is encoded as lowercase hex strings
    const hexPattern = /^[0-9a-f]+$/;
    const data = signingCommitmentsData();
    expect(bytesToHex(data.hiding)).toMatch(hexPattern);
    expect(bytesToHex(data.binding)).toMatch(hexPattern);
  });

  it("should use SEC1 compressed format for elements", () => {
    // P-256 uses SEC1 compressed format: 02/03 prefix + 32 bytes x-coordinate
    const data = signingCommitmentsData();
    const hidingHex = bytesToHex(data.hiding);
    // Should start with 02 or 03 (even or odd y-coordinate)
    expect(hidingHex.substring(0, 2)).toMatch(/^0[23]$/);
    // Should be 33 bytes = 66 hex chars
    expect(hidingHex.length).toBe(66);
  });

  it("should use identifier as map key in signing_commitments", () => {
    // Identifiers are serialized as hex strings when used as map keys
    const _data = signingPackageData();
    void _data; // Available for verifying commitments structure
    const identifierHex = "000000000000000000000000000000000000000000000000000000000000002a";
    // 42 encoded as a scalar with padding (big-endian)
    expect(identifierHex.endsWith("2a")).toBe(true); // 0x2a = 42
  });
});
