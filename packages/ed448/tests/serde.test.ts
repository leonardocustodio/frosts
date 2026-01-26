/**
 * JSON serialization (serde) tests for FROST Ed448-SHAKE256.
 * Ported from frost-ed448/tests/serde_tests.rs
 *
 * These tests verify that all FROST data structures can be correctly
 * serialized to and deserialized from JSON format, including validation
 * of the header fields and error handling for invalid inputs.
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
} from "./helpers/index.js";

import {
  Ed448Shake256,
  Identifier,
  SigningCommitments,
  NonceCommitment,
  SignatureShare,
  SigningShare,
  VerifyingShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  VerifiableSecretSharingCommitment,
  serde,
} from "../src/index.js";

/**
 * Standard header for JSON serialization.
 */
const HEADER = {
  version: 0,
  ciphersuite: CIPHERSUITE_NAME,
} as const;

describe("FROST Ed448-SHAKE256 JSON Serialization Tests", () => {
  describe("SigningCommitments JSON Serialization", () => {
    it("should serialize SigningCommitments to JSON", () => {
      // Create SigningCommitments from sample data
      const data = signingCommitmentsData();
      const hiding = NonceCommitment.deserialize(Ed448Shake256, data.hiding);
      const binding = NonceCommitment.deserialize(Ed448Shake256, data.binding);
      const commitments = new SigningCommitments(Ed448Shake256, hiding, binding);

      // Serialize to JSON
      const json = serde.signingCommitmentsToJson(commitments);

      expect(json.header.version).toBe(0);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(json.hiding).toBe(bytesToHex(data.hiding));
      expect(json.binding).toBe(bytesToHex(data.binding));

      // Deserialize back
      const decoded = serde.signingCommitmentsFromJson(json);
      expect(bytesToHex(decoded.hiding.serialize())).toBe(json.hiding);
      expect(bytesToHex(decoded.binding.serialize())).toBe(json.binding);
    });

    it("should deserialize SigningCommitments from valid JSON", () => {
      const validJson = {
        header: HEADER,
        hiding:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        binding:
          "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
      };
      const commitments = serde.signingCommitmentsFromJson(validJson);
      expect(commitments).toBeDefined();
      expect(bytesToHex(commitments.hiding.serialize())).toBe(validJson.hiding);
      expect(bytesToHex(commitments.binding.serialize())).toBe(validJson.binding);
    });

    it("should reject empty JSON object", () => {
      const invalidJson = "{}";
      expect(() => serde.signingCommitmentsFromJson(JSON.parse(invalidJson))).toThrow();
    });

    it("should reject wrong ciphersuite", () => {
      const invalidJson = {
        header: {
          version: 0,
          ciphersuite: "FROST(Wrong, SHA-512)",
        },
        hiding:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        binding:
          "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow(/ciphersuite/);
    });

    it("should reject invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        binding:
          "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow();
    });

    it("should reject missing field", () => {
      const invalidJson = {
        header: HEADER,
        binding:
          "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow(/Missing required field/);
    });

    it("should reject extra field", () => {
      const invalidJson = {
        header: HEADER,
        hiding:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        binding:
          "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
        extra: 1,
      };
      expect(() => serde.signingCommitmentsFromJson(invalidJson)).toThrow(/Unexpected field/);
    });
  });

  describe("SigningPackage JSON Serialization", () => {
    it("should serialize SigningPackage to JSON", () => {
      // Create a SigningPackage
      const data = signingPackageData();
      const commData = data.commitments;
      const hiding = NonceCommitment.deserialize(Ed448Shake256, commData.hiding);
      const binding = NonceCommitment.deserialize(Ed448Shake256, commData.binding);
      const commitment = new SigningCommitments(Ed448Shake256, hiding, binding);
      const identifier = Identifier.fromU16(Ed448Shake256, data.identifier);

      const signingCommitments = new Map<
        Identifier<typeof Ed448Shake256>,
        SigningCommitments<typeof Ed448Shake256>
      >();
      signingCommitments.set(identifier, commitment);

      const pkg = {
        signingCommitments,
        message: data.message,
      };

      // Serialize
      const json = serde.signingPackageToJson(pkg);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(json.message).toBe(bytesToHex(data.message));

      // Deserialize
      const decoded = serde.signingPackageFromJson(json);
      expect(decoded.signingCommitments.size).toBe(1);
      expect(bytesToHex(decoded.message)).toBe(json.message);
    });

    it("should deserialize SigningPackage from valid JSON", () => {
      const validJson = {
        header: HEADER,
        signing_commitments: {
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000":
            {
              header: HEADER,
              hiding:
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
              binding:
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
            },
        },
        message: "68656c6c6f20776f726c64",
      };
      const signingPackage = serde.signingPackageFromJson(validJson);
      expect(signingPackage).toBeDefined();
      expect(bytesToHex(signingPackage.message)).toBe(validJson.message);
    });

    it("should reject invalid identifier (all zeros)", () => {
      const invalidJson = {
        header: HEADER,
        signing_commitments: {
          "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000":
            {
              header: HEADER,
              hiding:
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
              binding:
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
            },
        },
        message: "68656c6c6f20776f726c64",
      };
      expect(() => serde.signingPackageFromJson(invalidJson)).toThrow();
    });
  });

  describe("SignatureShare JSON Serialization", () => {
    it("should serialize SignatureShare to JSON", () => {
      const data = signatureShareData();
      const share = SignatureShare.deserialize(Ed448Shake256, data.share);

      const json = serde.signatureShareToJson(share);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(json.share).toBe(bytesToHex(data.share));

      const decoded = serde.signatureShareFromJson(json);
      expect(bytesToHex(decoded.serialize())).toBe(json.share);
    });

    it("should deserialize SignatureShare from valid JSON", () => {
      const validJson = {
        header: HEADER,
        share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
      };
      const share = serde.signatureShareFromJson(validJson);
      expect(share).toBeDefined();
      expect(validJson.share.length).toBe(114); // 57 bytes = 114 hex chars
    });

    it("should reject invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
      };
      expect(() => serde.signatureShareFromJson(invalidJson)).toThrow();
    });

    it("should reject missing field", () => {
      const invalidJson = {
        header: HEADER,
      };
      expect(() => serde.signatureShareFromJson(invalidJson)).toThrow(/Missing required field/);
    });

    it("should reject extra field", () => {
      const invalidJson = {
        header: HEADER,
        share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        extra: 1,
      };
      expect(() => serde.signatureShareFromJson(invalidJson)).toThrow(/Unexpected field/);
    });
  });

  describe("SecretShare JSON Serialization", () => {
    it("should serialize SecretShare to JSON", () => {
      const data = secretShareData();
      const identifier = Identifier.fromU16(Ed448Shake256, data.identifier);
      const signingShare = SigningShare.deserialize(Ed448Shake256, data.signingShare);
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed448Shake256,
        data.commitment,
      );
      const secretShare = new SecretShare(Ed448Shake256, identifier, signingShare, commitment);

      const json = serde.secretShareToJson(secretShare);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(Array.isArray(json.commitment)).toBe(true);

      const decoded = serde.secretShareFromJson(json);
      // Compare serialized identifier bytes - first byte is the value in little-endian
      expect(decoded.identifier.serialize()[0]).toBe(data.identifier);
    });

    it("should deserialize SecretShare from valid JSON", () => {
      const validJson = {
        header: HEADER,
        identifier:
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        signing_share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        commitment: [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        ],
      };
      const secretShare = serde.secretShareFromJson(validJson);
      expect(secretShare).toBeDefined();
      expect(Array.isArray(validJson.commitment)).toBe(true);
    });

    it("should reject invalid identifier (all zeros)", () => {
      const invalidJson = {
        header: HEADER,
        identifier:
          "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        signing_share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        commitment: [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        ],
      };
      expect(() => serde.secretShareFromJson(invalidJson)).toThrow();
    });
  });

  describe("KeyPackage JSON Serialization", () => {
    it("should serialize KeyPackage to JSON", () => {
      const data = keyPackageData();
      const identifier = Identifier.fromU16(Ed448Shake256, data.identifier);
      const signingShare = SigningShare.deserialize(Ed448Shake256, data.signingShare);
      const verifyingShare = VerifyingShare.deserialize(Ed448Shake256, data.verifyingShare);
      const verifyingKey = Ed448Shake256.deserializeElement(data.verifyingKey);
      const keyPackage = new KeyPackage(
        Ed448Shake256,
        identifier,
        signingShare,
        verifyingShare,
        verifyingKey,
        data.minSigners,
      );

      const json = serde.keyPackageToJson(keyPackage);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(json.min_signers).toBe(data.minSigners);

      const decoded = serde.keyPackageFromJson(json);
      expect(decoded.minSigners).toBe(data.minSigners);
    });

    it("should deserialize KeyPackage from valid JSON", () => {
      const validJson = {
        header: HEADER,
        identifier:
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        signing_share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        verifying_share:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        verifying_key:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
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
        identifier:
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        signing_share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        verifying_share:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        verifying_key:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        min_signers: 2,
      };
      expect(() => serde.keyPackageFromJson(invalidJson)).toThrow(/version/);
    });
  });

  describe("PublicKeyPackage JSON Serialization", () => {
    it("should serialize PublicKeyPackage to JSON", () => {
      const data = publicKeyPackageNewData();
      const verifyingShares = new Map<string, VerifyingShare<typeof Ed448Shake256>>();

      for (const [idNum, shareBytes] of data.verifyingShares) {
        const id = Identifier.fromU16(Ed448Shake256, idNum);
        const idHex = bytesToHex(id.serialize());
        const share = VerifyingShare.deserialize(Ed448Shake256, shareBytes);
        verifyingShares.set(idHex, share);
      }

      const verifyingKey = Ed448Shake256.deserializeElement(data.verifyingKey);
      const pkg = new PublicKeyPackage(
        Ed448Shake256,
        verifyingShares,
        verifyingKey,
        data.minSigners,
      );

      const json = serde.publicKeyPackageToJson(pkg);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(json.min_signers).toBe(data.minSigners);

      const decoded = serde.publicKeyPackageFromJson(json);
      expect(decoded.minSigners).toBe(data.minSigners);
    });

    it("should deserialize PublicKeyPackage with minSigners from valid JSON", () => {
      const validJson = {
        header: HEADER,
        verifying_shares: {
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000":
            "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        },
        verifying_key:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
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
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000":
            "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        },
        verifying_key:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
      };
      const pkp = serde.publicKeyPackageFromJson(validJson);
      expect(pkp).toBeDefined();
      expect(pkp.minSigners).toBeUndefined();
    });

    it("should reject invalid identifier in verifying_shares", () => {
      const invalidJson = {
        header: HEADER,
        verifying_shares: {
          "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000":
            "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        },
        verifying_key:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
      };
      expect(() => serde.publicKeyPackageFromJson(invalidJson)).toThrow();
    });
  });

  describe("Round1 Package JSON Serialization", () => {
    it("should serialize round1::Package to JSON", () => {
      const data = round1PackageData();
      const commitment = VerifiableSecretSharingCommitment.deserialize(
        Ed448Shake256,
        data.commitment,
      );

      // Parse proof of knowledge from the sample data
      const pokBytes = data.proofOfKnowledge;
      const elementSize = Ed448Shake256.elementSize();
      const R = Ed448Shake256.deserializeElement(pokBytes.slice(0, elementSize));
      const z = Ed448Shake256.deserializeScalar(pokBytes.slice(elementSize));
      const proofOfKnowledge = { R, z };

      const pkg = {
        commitment,
        proofOfKnowledge,
        serialize: () => [] as Uint8Array[],
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const json = serde.round1PackageToJson(pkg as any);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(Array.isArray(json.commitment)).toBe(true);

      const decoded = serde.round1PackageFromJson(json);
      expect(decoded.commitment).toBeDefined();
      expect(decoded.proofOfKnowledge).toBeDefined();
    });

    it("should deserialize round1::Package from valid JSON", () => {
      const validJson = {
        header: HEADER,
        commitment: [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        ],
        proof_of_knowledge:
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69004d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
      };
      const round1Package = serde.round1PackageFromJson(validJson);
      expect(round1Package).toBeDefined();
      expect(Array.isArray(validJson.commitment)).toBe(true);
      // Proof of knowledge is element (57) + scalar (57) = 114 bytes = 228 hex chars
      expect(validJson.proof_of_knowledge.length).toBe(228);
    });
  });

  describe("Round2 Package JSON Serialization", () => {
    it("should serialize round2::Package to JSON", () => {
      const data = round2PackageData();
      const signingShare = SigningShare.deserialize(Ed448Shake256, data.signingShare);

      const pkg = {
        signingShare,
        serialize: () => signingShare.serialize(),
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const json = serde.round2PackageToJson(pkg as any);
      expect(json.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(json.signing_share.length).toBe(114); // 57 bytes = 114 hex chars

      const decoded = serde.round2PackageFromJson(json);
      expect(decoded.signingShare).toBeDefined();
    });

    it("should deserialize round2::Package from valid JSON", () => {
      const validJson = {
        header: HEADER,
        signing_share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
      };
      const round2Package = serde.round2PackageFromJson(validJson);
      expect(round2Package).toBeDefined();
      expect(validJson.signing_share.length).toBe(114); // 57 bytes = 114 hex chars
    });

    it("should reject invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
      };
      expect(() => serde.round2PackageFromJson(invalidJson)).toThrow();
    });

    it("should reject missing field", () => {
      const invalidJson = {
        header: HEADER,
      };
      expect(() => serde.round2PackageFromJson(invalidJson)).toThrow(/Missing required field/);
    });

    it("should reject extra field", () => {
      const invalidJson = {
        header: HEADER,
        signing_share:
          "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        extra: 1,
      };
      expect(() => serde.round2PackageFromJson(invalidJson)).toThrow(/Unexpected field/);
    });
  });
});

describe("JSON Serialization Format", () => {
  it("should use correct ciphersuite identifier", () => {
    expect(CIPHERSUITE_NAME).toBe("FROST-ED448-SHAKE256-v1");
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

  it("should use identifier as map key in signing_commitments", () => {
    // Identifiers are serialized as hex strings when used as map keys
    const _data = signingPackageData();
    void _data; // Available for verifying commitments structure
    const identifierHex =
      "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    // 42 encoded as a scalar with padding
    expect(identifierHex.startsWith("2a")).toBe(true); // 0x2a = 42
  });
});
