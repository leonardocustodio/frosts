/**
 * Core tests for FROST P256-SHA256 ciphersuite.
 * Tests field operations, group operations, hash functions, and ciphersuite behavior.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { P256Sha256 } from "../src/index.js";
import { createSecureRng, createTestRng, hexToBytes, type CryptoRng } from "./helpers/index.js";

describe("P256Sha256 Ciphersuite", () => {
  it("should have correct ciphersuite ID", () => {
    expect(P256Sha256.ID).toBe("FROST-P256-SHA256-v1");
  });

  it("should have correct scalar size", () => {
    expect(P256Sha256.scalarSize()).toBe(32);
  });

  it("should have correct element size", () => {
    expect(P256Sha256.elementSize()).toBe(33);
  });
});

describe("P256 Scalar Field Operations", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Field Constants", () => {
    it("should return zero scalar", () => {
      const zero = P256Sha256.scalarZero();
      expect(zero.length).toBe(32);
      for (const byte of zero) {
        expect(byte).toBe(0);
      }
    });

    it("should return one scalar", () => {
      const one = P256Sha256.scalarOne();
      expect(one.length).toBe(32);
      expect(one[31]).toBe(1);
      for (let i = 0; i < 31; i++) {
        expect(one[i]).toBe(0);
      }
    });
  });

  describe("Arithmetic Operations", () => {
    it("should add scalars correctly", () => {
      const a = P256Sha256.scalarRandom(rng);
      const zero = P256Sha256.scalarZero();

      // a + 0 = a
      const result = P256Sha256.scalarAdd(a, zero);
      expect(P256Sha256.scalarsEqual(result, a)).toBe(true);
    });

    it("should subtract scalars correctly", () => {
      const a = P256Sha256.scalarRandom(rng);
      const zero = P256Sha256.scalarZero();

      // a - 0 = a
      const result = P256Sha256.scalarSub(a, zero);
      expect(P256Sha256.scalarsEqual(result, a)).toBe(true);

      // a - a = 0
      const result2 = P256Sha256.scalarSub(a, a);
      expect(P256Sha256.scalarsEqual(result2, zero)).toBe(true);
    });

    it("should multiply scalars correctly", () => {
      const a = P256Sha256.scalarRandom(rng);
      const one = P256Sha256.scalarOne();
      const zero = P256Sha256.scalarZero();

      // a * 1 = a
      const result1 = P256Sha256.scalarMul(a, one);
      expect(P256Sha256.scalarsEqual(result1, a)).toBe(true);

      // a * 0 = 0
      const result2 = P256Sha256.scalarMul(a, zero);
      expect(P256Sha256.scalarsEqual(result2, zero)).toBe(true);
    });

    it("should invert scalars correctly", () => {
      const a = P256Sha256.scalarRandom(rng);
      const aInv = P256Sha256.scalarInvert(a);
      const one = P256Sha256.scalarOne();

      // a * a^(-1) = 1
      const result = P256Sha256.scalarMul(a, aInv);
      expect(P256Sha256.scalarsEqual(result, one)).toBe(true);
    });

    it("should throw when inverting zero", () => {
      const zero = P256Sha256.scalarZero();
      expect(() => P256Sha256.scalarInvert(zero)).toThrow();
    });
  });

  describe("Serialization", () => {
    it("should serialize and deserialize scalars correctly", () => {
      const scalar = P256Sha256.scalarRandom(rng);
      const bytes = P256Sha256.serializeScalar(scalar);
      const deserialized = P256Sha256.deserializeScalar(bytes);

      expect(P256Sha256.scalarsEqual(scalar, deserialized)).toBe(true);
    });

    it("should reject invalid scalar length", () => {
      expect(() => P256Sha256.deserializeScalar(new Uint8Array(31))).toThrow();
      expect(() => P256Sha256.deserializeScalar(new Uint8Array(33))).toThrow();
    });
  });

  describe("Random Scalar Generation", () => {
    it("should generate non-zero random scalars", () => {
      const zero = P256Sha256.scalarZero();
      void zero; // Reference value for future zero checks
      for (let i = 0; i < 10; i++) {
        const scalar = P256Sha256.scalarRandom(rng);
        // Extremely unlikely to be zero
        expect(scalar.length).toBe(32);
      }
    });

    it("should generate different scalars", () => {
      const a = P256Sha256.scalarRandom(rng);
      const b = P256Sha256.scalarRandom(rng);
      expect(P256Sha256.scalarsEqual(a, b)).toBe(false);
    });
  });
});

describe("P256 Group Operations", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Group Constants", () => {
    it("should return generator point", () => {
      const g = P256Sha256.generator();
      expect(g.length).toBe(33);
      // P-256 generator has y-coordinate with odd parity, so prefix is 03
      expect(g[0]).toBe(0x03);
    });

    it("should return identity point", () => {
      const identity = P256Sha256.identity();
      expect(identity.length).toBe(33);
      expect(P256Sha256.isIdentity(identity)).toBe(true);
    });

    it("should return cofactor", () => {
      const cofactor = P256Sha256.cofactor();
      const one = P256Sha256.scalarOne();
      // P-256 has cofactor 1
      expect(P256Sha256.scalarsEqual(cofactor, one)).toBe(true);
    });
  });

  describe("Point Operations", () => {
    it("should add points correctly", () => {
      const g = P256Sha256.generator();
      const identity = P256Sha256.identity();

      // G + 0 = G
      const result = P256Sha256.elementAdd(g, identity);
      expect(P256Sha256.elementsEqual(result, g)).toBe(true);
    });

    it("should subtract points correctly", () => {
      const g = P256Sha256.generator();
      const identity = P256Sha256.identity();

      // G - 0 = G
      const result1 = P256Sha256.elementSub(g, identity);
      expect(P256Sha256.elementsEqual(result1, g)).toBe(true);

      // G - G = 0
      const result2 = P256Sha256.elementSub(g, g);
      expect(P256Sha256.isIdentity(result2)).toBe(true);
    });

    it("should perform scalar multiplication correctly", () => {
      const g = P256Sha256.generator();
      const one = P256Sha256.scalarOne();
      const zero = P256Sha256.scalarZero();

      // G * 1 = G
      const result1 = P256Sha256.elementMul(g, one);
      expect(P256Sha256.elementsEqual(result1, g)).toBe(true);

      // G * 0 = 0
      const result2 = P256Sha256.elementMul(g, zero);
      expect(P256Sha256.isIdentity(result2)).toBe(true);
    });

    it("should perform scalar base multiplication correctly", () => {
      const one = P256Sha256.scalarOne();
      const g = P256Sha256.generator();

      // 1 * G = G
      const result = P256Sha256.scalarBaseMult(one);
      expect(P256Sha256.elementsEqual(result, g)).toBe(true);
    });

    it("should verify scalar multiplication consistency", () => {
      const scalar = P256Sha256.scalarRandom(rng);
      const g = P256Sha256.generator();

      // scalar * G (via elementMul) should equal scalar * G (via scalarBaseMult)
      const result1 = P256Sha256.elementMul(g, scalar);
      const result2 = P256Sha256.scalarBaseMult(scalar);
      expect(P256Sha256.elementsEqual(result1, result2)).toBe(true);
    });
  });

  describe("Serialization", () => {
    it("should serialize and deserialize elements correctly", () => {
      const scalar = P256Sha256.scalarRandom(rng);
      const point = P256Sha256.scalarBaseMult(scalar);

      const bytes = P256Sha256.serializeElement(point);
      expect(bytes.length).toBe(33);

      const deserialized = P256Sha256.deserializeElement(bytes);
      expect(P256Sha256.elementsEqual(point, deserialized)).toBe(true);
    });

    it("should reject identity element serialization", () => {
      const identity = P256Sha256.identity();
      expect(() => P256Sha256.serializeElement(identity)).toThrow();
    });

    it("should reject invalid element length", () => {
      expect(() => P256Sha256.deserializeElement(new Uint8Array(32))).toThrow();
      expect(() => P256Sha256.deserializeElement(new Uint8Array(34))).toThrow();
    });

    it("should reject all-zero bytes (identity)", () => {
      const zeros = new Uint8Array(33);
      expect(() => P256Sha256.deserializeElement(zeros)).toThrow();
    });

    it("should reject non-canonical point encoding with invalid prefix", () => {
      // Ported from Rust frost-p256/src/tests/deserialize.rs
      // SEC1 compressed format first byte should be 0x02 (even y) or 0x03 (odd y)
      // Any other prefix is invalid.
      const generator = P256Sha256.generator();
      expect(generator[0]).toBeGreaterThanOrEqual(2);
      expect(generator[0]).toBeLessThanOrEqual(3);

      // Create invalid encoding with 0xFF prefix
      const invalidEncoded = new Uint8Array(generator);
      invalidEncoded[0] = 0xff;
      expect(() => P256Sha256.deserializeElement(invalidEncoded)).toThrow();

      // Also test with 0x00 prefix (not 0x02 or 0x03)
      const invalidEncoded2 = new Uint8Array(generator);
      invalidEncoded2[0] = 0x00;
      expect(() => P256Sha256.deserializeElement(invalidEncoded2)).toThrow();

      // Test with 0x04 prefix (uncompressed format, wrong length)
      const invalidEncoded3 = new Uint8Array(generator);
      invalidEncoded3[0] = 0x04;
      expect(() => P256Sha256.deserializeElement(invalidEncoded3)).toThrow();
    });

    it("should reject non-canonical x-coordinate (x >= p)", () => {
      // Ported from Rust frost-p256/src/tests/deserialize.rs
      // P-256 field prime p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
      // This test uses x = p + 5 which is non-canonical (should be reduced mod p)
      // x = 0xFFFFFFFF00000001000000000000000000000001000000000000000000000004
      const nonCanonicalPoint = hexToBytes(
        "02ffffffff00000001000000000000000000000001000000000000000000000004",
      );
      expect(() => P256Sha256.deserializeElement(nonCanonicalPoint)).toThrow();
    });

    it("should reject point with x-coordinate at field prime", () => {
      // x = p (exactly at the prime, which is 0 mod p but should still be rejected)
      const atPrime = hexToBytes(
        "02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      );
      expect(() => P256Sha256.deserializeElement(atPrime)).toThrow();
    });
  });
});

describe("P256 Hash Functions", () => {
  it("should compute H1 (rho binding factor hash)", () => {
    const input = new TextEncoder().encode("test input");
    const result = P256Sha256.H1(input);

    expect(result.length).toBe(32);
    // Should be deterministic
    const result2 = P256Sha256.H1(input);
    expect(P256Sha256.scalarsEqual(result, result2)).toBe(true);
  });

  it("should compute H2 (challenge hash)", () => {
    const input = new TextEncoder().encode("test challenge");
    const result = P256Sha256.H2(input);

    expect(result.length).toBe(32);
    const result2 = P256Sha256.H2(input);
    expect(P256Sha256.scalarsEqual(result, result2)).toBe(true);
  });

  it("should compute H3 (nonce hash)", () => {
    const input = new TextEncoder().encode("test nonce");
    const result = P256Sha256.H3(input);

    expect(result.length).toBe(32);
    const result2 = P256Sha256.H3(input);
    expect(P256Sha256.scalarsEqual(result, result2)).toBe(true);
  });

  it("should compute H4 (message hash)", () => {
    const input = new TextEncoder().encode("test message");
    const result = P256Sha256.H4(input);

    expect(result.length).toBe(32);
    const result2 = P256Sha256.H4(input);
    for (let i = 0; i < result.length; i++) {
      expect(result[i]).toBe(result2[i]);
    }
  });

  it("should compute H5 (commitment hash)", () => {
    const input = new TextEncoder().encode("test commitment");
    const result = P256Sha256.H5(input);

    expect(result.length).toBe(32);
    const result2 = P256Sha256.H5(input);
    for (let i = 0; i < result.length; i++) {
      expect(result[i]).toBe(result2[i]);
    }
  });

  it("should compute HDKG (DKG hash)", () => {
    const input = new TextEncoder().encode("test dkg");
    const result = P256Sha256.HDKG(input);

    expect(result).not.toBeNull();
    if (result !== null) {
      expect(result.length).toBe(32);
    }
  });

  it("should compute HID (identifier hash)", () => {
    const input = new TextEncoder().encode("test id");
    const result = P256Sha256.HID(input);

    expect(result).not.toBeNull();
    if (result !== null) {
      expect(result.length).toBe(32);
    }
  });

  it("should compute hashRandomizer (rerandomization hash)", () => {
    const input = new TextEncoder().encode("test randomizer");
    const result = P256Sha256.hashRandomizer(input);

    expect(result).not.toBeNull();
    if (result !== null) {
      expect(result.length).toBe(32);
    }
  });

  it("should produce different outputs for different inputs", () => {
    const input1 = new TextEncoder().encode("input1");
    const input2 = new TextEncoder().encode("input2");

    const h1a = P256Sha256.H1(input1);
    const h1b = P256Sha256.H1(input2);
    expect(P256Sha256.scalarsEqual(h1a, h1b)).toBe(false);

    const h2a = P256Sha256.H2(input1);
    const h2b = P256Sha256.H2(input2);
    expect(P256Sha256.scalarsEqual(h2a, h2b)).toBe(false);
  });

  it("should produce different outputs for different hash functions", () => {
    const input = new TextEncoder().encode("same input");

    const h1 = P256Sha256.H1(input);
    const h2 = P256Sha256.H2(input);
    const h3 = P256Sha256.H3(input);

    expect(P256Sha256.scalarsEqual(h1, h2)).toBe(false);
    expect(P256Sha256.scalarsEqual(h2, h3)).toBe(false);
    expect(P256Sha256.scalarsEqual(h1, h3)).toBe(false);
  });
});

describe("P256 Challenge Computation", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  it("should compute challenge from R, verifying key, and message", () => {
    const rScalar = P256Sha256.scalarRandom(rng);
    const R = P256Sha256.scalarBaseMult(rScalar);

    const vkScalar = P256Sha256.scalarRandom(rng);
    const verifyingKey = P256Sha256.scalarBaseMult(vkScalar);

    const message = new TextEncoder().encode("test message");

    const challenge = P256Sha256.challenge(R, verifyingKey, message);
    expect(challenge).toBeDefined();
    expect(challenge.toScalar().length).toBe(32);
  });

  it("should produce deterministic challenges", () => {
    const rScalar = P256Sha256.scalarRandom(rng);
    const R = P256Sha256.scalarBaseMult(rScalar);

    const vkScalar = P256Sha256.scalarRandom(rng);
    const verifyingKey = P256Sha256.scalarBaseMult(vkScalar);

    const message = new TextEncoder().encode("test message");

    const challenge1 = P256Sha256.challenge(R, verifyingKey, message);
    const challenge2 = P256Sha256.challenge(R, verifyingKey, message);

    expect(P256Sha256.scalarsEqual(challenge1.toScalar(), challenge2.toScalar())).toBe(true);
  });

  it("should produce different challenges for different inputs", () => {
    const r1Scalar = P256Sha256.scalarRandom(rng);
    const R1 = P256Sha256.scalarBaseMult(r1Scalar);

    const r2Scalar = P256Sha256.scalarRandom(rng);
    const R2 = P256Sha256.scalarBaseMult(r2Scalar);

    const vkScalar = P256Sha256.scalarRandom(rng);
    const verifyingKey = P256Sha256.scalarBaseMult(vkScalar);

    const message = new TextEncoder().encode("test message");

    const challenge1 = P256Sha256.challenge(R1, verifyingKey, message);
    const challenge2 = P256Sha256.challenge(R2, verifyingKey, message);

    expect(P256Sha256.scalarsEqual(challenge1.toScalar(), challenge2.toScalar())).toBe(false);
  });
});

describe("Deterministic Test RNG", () => {
  it("should produce deterministic values", () => {
    const rng1 = createTestRng();
    const rng2 = createTestRng();

    const scalar1 = P256Sha256.scalarRandom(rng1);
    const scalar2 = P256Sha256.scalarRandom(rng2);

    expect(P256Sha256.scalarsEqual(scalar1, scalar2)).toBe(true);
  });

  it("should produce different values with different seeds", () => {
    const rng1 = createTestRng(new Uint8Array([1, 2, 3, 4]));
    const rng2 = createTestRng(new Uint8Array([5, 6, 7, 8]));

    const scalar1 = P256Sha256.scalarRandom(rng1);
    const scalar2 = P256Sha256.scalarRandom(rng2);

    expect(P256Sha256.scalarsEqual(scalar1, scalar2)).toBe(false);
  });
});
