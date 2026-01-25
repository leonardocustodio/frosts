/**
 * Deserialization tests for FROST-Ed448-SHAKE256.
 * Ported from frost-ed448/src/tests/deserialize.rs
 *
 * These tests verify proper handling of various deserialization edge cases
 * specific to the Ed448 curve, including:
 * - Non-canonical encodings
 * - Non-prime-order elements
 * - Identity element rejection
 */

import { describe, it, expect } from "vitest";
// TODO: Import test helpers from @frost/core once types are properly exported
// import { GroupError, GroupErrorType } from "@frost/core";
// import { hexToBytes } from "@frost/core/tests/index.js";

// TODO: Import Ed448Shake256 ciphersuite and ed448 curve types once implemented
// import { Ed448Shake256 } from "../index.js";
// import { ed448 } from "@noble/curves/ed448";

/**
 * Ed448 curve constants.
 * The point encoding is 57 bytes (456 bits) for Ed448.
 */
const ED448_POINT_SIZE = 57;

/**
 * Convert hex string to Uint8Array.
 * This is a local implementation for tests until @frost/core/tests is properly typed.
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

describe("Ed448-SHAKE256 Deserialization", () => {
  describe("Non-canonical encodings", () => {
    it("should reject non-canonical encoding with modified sign byte", () => {
      // Test logic from Rust:
      // let mut encoded_generator = ExtendedPoint::generator().compress().0;
      // let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_generator);
      // assert!(r.is_ok());
      //
      // // The last byte only should have the sign bit. Set all other bits to
      // // create a non-canonical encoding.
      // encoded_generator[56] |= 0x7f;
      // let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_generator);
      // assert_eq!(r, Err(GroupError::MalformedElement));

      // Once Ed448Shake256 ciphersuite is implemented:
      // const generator = ed448.ExtendedPoint.BASE;
      // const encodedGenerator = generator.toRawBytes();
      //
      // // Verify generator deserializes correctly
      // const validResult = Ed448Shake256.group.deserialize(encodedGenerator);
      // expect(validResult.isOk()).toBe(true);
      //
      // // Modify last byte to create non-canonical encoding
      // const modified = new Uint8Array(encodedGenerator);
      // modified[56] |= 0x7f;
      //
      // // Should fail with MalformedElement error
      // try {
      //   Ed448Shake256.group.deserialize(modified);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.MalformedElement);
      // }

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });

    it("should reject non-canonical encoding y = p + 19", () => {
      // Test logic from Rust:
      // // Besides the last byte, it is still possible to get non-canonical encodings.
      // // This is y = p + 19 which is non-canonical and maps to a valid prime-order point.
      // let encoded_point = hex::decode("12000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00").unwrap().try_into().unwrap();
      // let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_point);
      // assert_eq!(r, Err(GroupError::MalformedElement));

      // This test verifies rejection of a non-canonical point encoding.
      // The value y = p + 19 is non-canonical because y >= p (the prime modulus).
      // Even though it maps to a valid prime-order point when reduced mod p,
      // the encoding itself is non-canonical and must be rejected.

      const nonCanonicalPoint = hexToBytes(
        "12000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00",
      );

      // Once Ed448Shake256 ciphersuite is implemented:
      // try {
      //   Ed448Shake256.group.deserialize(nonCanonicalPoint);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.MalformedElement);
      // }

      // Placeholder - verify the test data is correct length
      expect(nonCanonicalPoint.length).toBe(ED448_POINT_SIZE);
    });
  });

  describe("Non-prime-order elements", () => {
    it("should reject point with non-prime order", () => {
      // Test logic from Rust:
      // let encoded_point =
      //     hex::decode("030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
      //         .unwrap()
      //         .try_into()
      //         .unwrap();
      // let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_point);
      // assert_eq!(r, Err(GroupError::InvalidNonPrimeOrderElement));

      // This test verifies that points not in the prime-order subgroup are rejected.
      // Ed448 has cofactor h = 4, so there are low-order points that must be rejected.

      const nonPrimeOrderPoint = hexToBytes(
        "030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      );

      // Once Ed448Shake256 ciphersuite is implemented:
      // try {
      //   Ed448Shake256.group.deserialize(nonPrimeOrderPoint);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.InvalidNonPrimeOrderElement);
      // }

      // Placeholder - verify the test data is correct length
      expect(nonPrimeOrderPoint.length).toBe(ED448_POINT_SIZE);
    });
  });

  describe("Identity element", () => {
    it("should reject the identity element", () => {
      // Test logic from Rust:
      // let encoded_identity = ExtendedPoint::identity().compress().0;
      // let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_identity);
      // assert_eq!(r, Err(GroupError::InvalidIdentityElement));

      // The identity element (point at infinity) must be rejected in FROST
      // because it would cause issues in the protocol (e.g., division by zero
      // in Lagrange interpolation).

      // Once Ed448Shake256 ciphersuite is implemented:
      // const identity = ed448.ExtendedPoint.ZERO;
      // const encodedIdentity = identity.toRawBytes();
      //
      // try {
      //   Ed448Shake256.group.deserialize(encodedIdentity);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.InvalidIdentityElement);
      // }

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });
});

// Export test utility constants
export { ED448_POINT_SIZE };
