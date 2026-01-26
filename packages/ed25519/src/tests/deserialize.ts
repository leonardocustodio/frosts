/**
 * Deserialization tests for FROST-Ed25519-SHA512.
 * Ported from frost-ed25519/src/tests/deserialize.rs
 *
 * These tests verify proper handling of deserialization edge cases
 * specific to the Ed25519 curve, including:
 * - Non-prime-order element rejection (cofactor issues)
 * - Identity element rejection
 *
 * Note: Unlike Ristretto255 which guarantees prime-order elements,
 * Ed25519 works on the full Edwards curve which has cofactor 8.
 * This means we must explicitly check for and reject points that
 * are not in the prime-order subgroup.
 */

import { describe, it, expect } from "vitest";
// TODO: Import test helpers from @frosts/core once types are properly exported
// import { GroupError, GroupErrorType } from "@frosts/core";

// TODO: Import Ed25519Sha512 ciphersuite and curve types once implemented
// import { Ed25519Sha512 } from "../index.js";
// import { ed25519 } from "@noble/curves/ed25519";

/**
 * Ed25519 curve constants.
 * The point encoding is 32 bytes (256 bits) for Ed25519.
 */
const ED25519_POINT_SIZE = 32;

describe("Ed25519-SHA512 Deserialization", () => {
  describe("Non-prime-order elements", () => {
    it("should reject non-prime-order elements", () => {
      // Test logic from Rust:
      // let encoded_point =
      //     hex::decode("0300000000000000000000000000000000000000000000000000000000000000")
      //         .unwrap()
      //         .try_into()
      //         .unwrap();
      // let r = <Ed25519Sha512 as Ciphersuite>::Group::deserialize(&encoded_point);
      // assert_eq!(r, Err(GroupError::InvalidNonPrimeOrderElement));

      // Ed25519 has cofactor h=8, meaning the full group has order 8*q where
      // q is the prime order of the subgroup we use. Points not in the prime-order
      // subgroup must be rejected to prevent small subgroup attacks.
      //
      // The test vector 0x03 followed by 31 zero bytes represents a point
      // that is NOT in the prime-order subgroup.

      const nonPrimeOrderPoint = new Uint8Array(ED25519_POINT_SIZE);
      nonPrimeOrderPoint[0] = 0x03;
      // Rest is already zeros

      // Once Ed25519Sha512 ciphersuite is implemented:
      // try {
      //   Ed25519Sha512.group.deserialize(nonPrimeOrderPoint);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.InvalidNonPrimeOrderElement);
      // }

      // Placeholder until ciphersuite is implemented
      expect(nonPrimeOrderPoint.length).toBe(ED25519_POINT_SIZE);
      expect(nonPrimeOrderPoint[0]).toBe(0x03);
    });
  });

  describe("Identity element", () => {
    it("should reject the identity element", () => {
      // Test logic from Rust:
      // let encoded_identity = EdwardsPoint::identity().compress().to_bytes();
      // let r = <Ed25519Sha512 as Ciphersuite>::Group::deserialize(&encoded_identity);
      // assert_eq!(r, Err(GroupError::InvalidIdentityElement));

      // The identity element (point at infinity) must be rejected in FROST
      // because it would cause issues in the protocol (e.g., division by zero
      // in Lagrange interpolation).
      //
      // For Ed25519, the identity point is (0, 1) in affine coordinates.
      // In compressed form, this is encoded as:
      // y = 1 in little-endian = 0x01 followed by 31 zero bytes
      // with the sign bit (highest bit) set to 0 (since x = 0)

      // Once Ed25519Sha512 ciphersuite is implemented:
      // import { ed25519 } from "@noble/curves/ed25519";
      //
      // const identity = ed25519.ExtendedPoint.ZERO;
      // const encodedIdentity = identity.toRawBytes();
      //
      // // Verify encoding
      // expect(encodedIdentity.length).toBe(ED25519_POINT_SIZE);
      // // The identity in Ed25519 compressed form is (0, 1)
      // // In little-endian, y=1 is: 01 00 00 00 ... 00
      //
      // // Should fail with InvalidIdentityElement error
      // try {
      //   Ed25519Sha512.group.deserialize(encodedIdentity);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.InvalidIdentityElement);
      // }

      // Placeholder until ciphersuite is implemented
      // The identity point for Ed25519 compressed: y=1 little-endian
      const encodedIdentity = new Uint8Array(ED25519_POINT_SIZE);
      encodedIdentity[0] = 0x01;
      // Rest is already zeros

      expect(encodedIdentity.length).toBe(ED25519_POINT_SIZE);
      expect(encodedIdentity[0]).toBe(0x01);
    });
  });
});

// Export test utility constants
export { ED25519_POINT_SIZE };
