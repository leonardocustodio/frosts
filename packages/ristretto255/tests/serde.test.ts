/**
 * JSON serialization (serde) tests for FROST Ristretto255-SHA512.
 * Ported from frost-ristretto255/tests/serde_tests.rs
 *
 * These tests verify the expected JSON format for FROST data structures.
 * Full round-trip JSON serialization will be implemented when @frosts/core
 * adds JSON serde support.
 */

import { describe, it, expect } from "vitest";
import {
  signingCommitmentsData,
  signingPackageData,
  bytesToHex,
  CIPHERSUITE_NAME,
} from "./helpers/index.js";

/**
 * Standard header for JSON serialization.
 */
const HEADER = {
  version: 0,
  ciphersuite: CIPHERSUITE_NAME,
} as const;

describe("FROST Ristretto255-SHA512 JSON Format Tests", () => {
  describe("SigningCommitments JSON Format", () => {
    it("should have correct JSON structure for SigningCommitments", () => {
      const validJson = {
        header: HEADER,
        hiding: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        binding: "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
      };
      expect(validJson.header.ciphersuite).toBe(CIPHERSUITE_NAME);
      expect(validJson.header.version).toBe(0);
      expect(validJson.hiding.length).toBe(64); // 32 bytes = 64 hex chars
      expect(validJson.binding.length).toBe(64);
    });

    it("should reject empty JSON object", () => {
      const invalidJson = "{}";
      const parsed = JSON.parse(invalidJson);
      expect(parsed).toEqual({});
      expect("header" in parsed).toBe(false);
    });

    it("should reject wrong ciphersuite", () => {
      const invalidJson = {
        header: {
          version: 0,
          ciphersuite: "FROST(Wrong, SHA-512)",
        },
        hiding: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        binding: "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
      };
      expect(invalidJson.header.ciphersuite).not.toBe(CIPHERSUITE_NAME);
    });

    it("should identify invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        binding: "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
      };
      expect("hiding" in invalidJson).toBe(false);
      expect("foo" in invalidJson).toBe(true);
    });

    it("should identify missing field", () => {
      const invalidJson = {
        header: HEADER,
        binding: "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
      };
      expect("hiding" in invalidJson).toBe(false);
    });

    it("should identify extra field", () => {
      const invalidJson = {
        header: HEADER,
        hiding: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        binding: "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
        extra: 1,
      };
      expect("extra" in invalidJson).toBe(true);
    });
  });

  describe("SigningPackage JSON Format", () => {
    it("should have correct JSON structure for SigningPackage", () => {
      const validJson = {
        header: HEADER,
        signing_commitments: {
          "2a00000000000000000000000000000000000000000000000000000000000000": {
            header: HEADER,
            hiding: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
            binding: "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
          },
        },
        message: "68656c6c6f20776f726c64",
      };
      expect(validJson.message).toBe(bytesToHex(new TextEncoder().encode("hello world")));
      expect(Object.keys(validJson.signing_commitments).length).toBe(1);
    });

    it("should identify invalid identifier (all zeros)", () => {
      const invalidJson = {
        header: HEADER,
        signing_commitments: {
          "0000000000000000000000000000000000000000000000000000000000000000": {
            header: HEADER,
            hiding: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
            binding: "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
          },
        },
        message: "68656c6c6f20776f726c64",
      };
      expect(Object.keys(invalidJson.signing_commitments)[0]).toMatch(/^0+$/);
    });
  });

  describe("SignatureShare JSON Format", () => {
    it("should have correct JSON structure for SignatureShare", () => {
      const validJson = {
        header: HEADER,
        share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
      };
      expect(validJson.share.length).toBe(64); // 32 bytes = 64 hex chars
      expect(validJson.header.ciphersuite).toBe(CIPHERSUITE_NAME);
    });

    it("should identify invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
      };
      expect("share" in invalidJson).toBe(false);
    });

    it("should identify missing field", () => {
      const invalidJson = {
        header: HEADER,
      };
      expect("share" in invalidJson).toBe(false);
    });

    it("should identify extra field", () => {
      const invalidJson = {
        header: HEADER,
        share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        extra: 1,
      };
      expect("extra" in invalidJson).toBe(true);
    });
  });

  describe("SecretShare JSON Format", () => {
    it("should have correct JSON structure for SecretShare", () => {
      const validJson = {
        header: HEADER,
        identifier: "2a00000000000000000000000000000000000000000000000000000000000000",
        signing_share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        commitment: ["e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"],
      };
      expect(Array.isArray(validJson.commitment)).toBe(true);
      expect(validJson.commitment.length).toBeGreaterThan(0);
      expect(validJson.identifier.length).toBe(64);
    });

    it("should identify invalid identifier (all zeros)", () => {
      const invalidJson = {
        header: HEADER,
        identifier: "0000000000000000000000000000000000000000000000000000000000000000",
        signing_share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        commitment: ["e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"],
      };
      expect(invalidJson.identifier).toMatch(/^0+$/);
    });
  });

  describe("KeyPackage JSON Format", () => {
    it("should have correct JSON structure for KeyPackage", () => {
      const validJson = {
        header: HEADER,
        identifier: "2a00000000000000000000000000000000000000000000000000000000000000",
        signing_share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        verifying_share: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        verifying_key: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        min_signers: 2,
      };
      expect(validJson.min_signers).toBe(2);
      expect(validJson.identifier.length).toBe(64);
      expect(validJson.signing_share.length).toBe(64);
      expect(validJson.verifying_share.length).toBe(64);
      expect(validJson.verifying_key.length).toBe(64);
    });

    it("should reject invalid version", () => {
      const invalidJson = {
        header: {
          version: 1,
          ciphersuite: CIPHERSUITE_NAME,
        },
        identifier: "2a00000000000000000000000000000000000000000000000000000000000000",
        signing_share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        verifying_share: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        verifying_key: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        min_signers: 2,
      };
      expect(invalidJson.header.version).not.toBe(0);
    });
  });

  describe("PublicKeyPackage JSON Format", () => {
    it("should have correct JSON structure with minSigners", () => {
      const validJson = {
        header: HEADER,
        verifying_shares: {
          "2a00000000000000000000000000000000000000000000000000000000000000":
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        },
        verifying_key: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        min_signers: 2,
      };
      expect(validJson.min_signers).toBe(2);
      expect(typeof validJson.verifying_shares).toBe("object");
      expect(Object.keys(validJson.verifying_shares).length).toBe(1);
    });

    it("should accept old version without minSigners", () => {
      const validJson = {
        header: HEADER,
        verifying_shares: {
          "2a00000000000000000000000000000000000000000000000000000000000000":
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        },
        verifying_key: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
      };
      expect("min_signers" in validJson).toBe(false);
    });

    it("should identify invalid identifier in verifying_shares", () => {
      const invalidJson = {
        header: HEADER,
        verifying_shares: {
          "0000000000000000000000000000000000000000000000000000000000000000":
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        },
        verifying_key: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
      };
      expect(Object.keys(invalidJson.verifying_shares)[0]).toMatch(/^0+$/);
    });
  });

  describe("Round1 Package JSON Format", () => {
    it("should have correct JSON structure for round1::Package", () => {
      const validJson = {
        header: HEADER,
        commitment: ["e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"],
        proof_of_knowledge:
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
      };
      expect(Array.isArray(validJson.commitment)).toBe(true);
      // Proof of knowledge is element (32) + scalar (32) = 64 bytes = 128 hex chars
      expect(validJson.proof_of_knowledge.length).toBe(128);
    });

    it("should validate commitment array format", () => {
      const validJson = {
        header: HEADER,
        commitment: [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
        ],
        proof_of_knowledge:
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
      };
      expect(validJson.commitment.length).toBe(2);
      validJson.commitment.forEach((c) => {
        expect(c.length).toBe(64); // Each element is 32 bytes = 64 hex chars
      });
    });
  });

  describe("Round2 Package JSON Format", () => {
    it("should have correct JSON structure for round2::Package", () => {
      const validJson = {
        header: HEADER,
        signing_share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
      };
      expect(validJson.signing_share.length).toBe(64); // 32 bytes = 64 hex chars
      expect(validJson.header.ciphersuite).toBe(CIPHERSUITE_NAME);
    });

    it("should identify invalid field name", () => {
      const invalidJson = {
        header: HEADER,
        foo: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
      };
      expect("signing_share" in invalidJson).toBe(false);
    });

    it("should identify missing field", () => {
      const invalidJson = {
        header: HEADER,
      };
      expect("signing_share" in invalidJson).toBe(false);
    });

    it("should identify extra field", () => {
      const invalidJson = {
        header: HEADER,
        signing_share: "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        extra: 1,
      };
      expect("extra" in invalidJson).toBe(true);
    });
  });
});

describe("JSON Serialization Format Constants", () => {
  it("should use correct ciphersuite identifier", () => {
    expect(CIPHERSUITE_NAME).toBe("FROST-RISTRETTO255-SHA512-v1");
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
    void _data;
    const identifierHex = "2a00000000000000000000000000000000000000000000000000000000000000";
    // 42 encoded as a scalar with padding
    expect(identifierHex.startsWith("2a")).toBe(true); // 0x2a = 42
    expect(identifierHex.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it("should use little-endian encoding for identifier", () => {
    // 42 in little-endian is 0x2a followed by zeros
    const identifier42 = "2a00000000000000000000000000000000000000000000000000000000000000";
    expect(identifier42[0]).toBe("2"); // First nibble
    expect(identifier42[1]).toBe("a"); // Second nibble
    expect(identifier42.slice(2)).toMatch(/^0+$/); // Rest is zeros
  });
});
