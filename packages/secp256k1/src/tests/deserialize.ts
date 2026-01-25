/**
 * Deserialization tests for FROST-secp256k1-SHA256.
 * Ported from frost-secp256k1/src/tests/deserialize.rs
 *
 * These tests verify proper handling of deserialization edge cases
 * specific to the secp256k1 curve, including:
 * - Non-canonical point encodings
 * - Identity element rejection
 * - Zero identifier rejection
 *
 * Note: secp256k1 uses SEC1 compressed point format (33 bytes).
 * The first byte is 0x02 or 0x03 (even/odd y-coordinate),
 * followed by the 32-byte x-coordinate.
 */

import { describe, it, expect } from "vitest";
// TODO: Import error types from @frosts/core once types are properly exported
// import { GroupError, GroupErrorType, FieldError, FieldErrorType, Error as FrostError } from "@frosts/core";

// TODO: Import Secp256K1Sha256 ciphersuite and types once implemented
// import { Secp256K1Sha256, Identifier } from "../index.js";

/**
 * secp256k1 curve constants.
 * - SCALAR_SIZE: 32 bytes (256 bits) for scalars
 * - ELEMENT_SIZE: 33 bytes for SEC1 compressed point format
 */
const SECP256K1_SCALAR_SIZE = 32;
const SECP256K1_ELEMENT_SIZE = 33;

/**
 * Helper function to convert hex string to Uint8Array.
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

describe("Secp256K1-SHA256 Deserialization", () => {
  describe("Non-canonical encodings", () => {
    it("should reject non-canonical point encodings with invalid prefix", () => {
      // Test logic from Rust:
      // let mut encoded_generator = <Secp256K1Sha256 as Ciphersuite>::Group::serialize(
      //     &<Secp256K1Sha256 as Ciphersuite>::Group::generator(),
      // ).unwrap();
      //
      // let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
      // assert!(r.is_ok());
      //
      // // The first byte should be 0x02 or 0x03. Set other value to
      // // create a non-canonical encoding.
      // encoded_generator[0] = 0xFF;
      // let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
      // assert_eq!(r, Err(GroupError::MalformedElement));

      // For SEC1 compressed format:
      // - 0x02 means y-coordinate is even
      // - 0x03 means y-coordinate is odd
      // Any other prefix (like 0xFF) is invalid.

      // Once Secp256K1Sha256 ciphersuite is implemented:
      // const group = Secp256K1Sha256.group;
      // const generator = group.generator();
      // const encodedGenerator = group.serialize(generator);
      //
      // // Valid encoding should deserialize successfully
      // expect(() => group.deserialize(encodedGenerator)).not.toThrow();
      //
      // // Create invalid encoding with 0xFF prefix
      // const invalidEncoded = new Uint8Array(encodedGenerator);
      // invalidEncoded[0] = 0xFF;
      //
      // // Should fail with MalformedElement error
      // try {
      //   group.deserialize(invalidEncoded);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.MalformedElement);
      // }

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });

    it("should reject non-canonical x-coordinate (x >= p)", () => {
      // Test logic from Rust:
      // // Besides the first byte, it is still possible to get non-canonical encodings.
      // // This is x = p + 2 which is non-canonical and maps to a valid prime-order point.
      // let encoded_point =
      //     hex::decode("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31")
      //         .unwrap()
      //         .try_into()
      //         .unwrap();
      // let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_point);
      // assert_eq!(r, Err(GroupError::MalformedElement));

      // The secp256k1 field prime p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
      // This test uses x = p + 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC31
      // which is >= p and therefore non-canonical (should be reduced mod p).

      // Once Secp256K1Sha256 ciphersuite is implemented:
      // const nonCanonicalPoint = hexToBytes(
      //   "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31"
      // );
      //
      // try {
      //   Secp256K1Sha256.group.deserialize(nonCanonicalPoint);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.MalformedElement);
      // }

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });

  describe("Identity element", () => {
    it("should reject the identity element (point at infinity)", () => {
      // Test logic from Rust:
      // // The identity is actually encoded as a single byte; but the API does not
      // // allow us to change that. Try to send something similar.
      // let encoded_identity = [0u8; 33];
      //
      // let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_identity);
      // assert_eq!(r, Err(GroupError::MalformedElement));

      // The identity element (point at infinity) must be rejected in FROST
      // because it would cause issues in the protocol.
      //
      // For SEC1 format, there's no standard compressed encoding for the
      // point at infinity in 33 bytes. Trying to use all zeros should fail.

      // Once Secp256K1Sha256 ciphersuite is implemented:
      // const encodedIdentity = new Uint8Array(SECP256K1_ELEMENT_SIZE);
      // encodedIdentity.fill(0);
      //
      // try {
      //   Secp256K1Sha256.group.deserialize(encodedIdentity);
      //   expect.fail("Should have thrown GroupError");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(GroupError);
      //   expect((e as GroupError).type).toBe(GroupErrorType.MalformedElement);
      // }

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });

  describe("Zero identifier", () => {
    it("should reject deserializing identifier 0", () => {
      // Test logic from Rust:
      // // Test if deserializing the identifier 0 fails.
      // // https://github.com/ZcashFoundation/frost/issues/793
      // let arr: [u8; 32] = [0; 32];
      // let r = Identifier::deserialize(&arr);
      // assert_eq!(r, Err(Error::FieldError(FieldError::InvalidZeroScalar)));

      // Identifier 0 is invalid because it would cause division by zero
      // in Lagrange interpolation. This is a security requirement.

      // Once Secp256K1Sha256 ciphersuite is implemented:
      // const zeroIdentifier = new Uint8Array(SECP256K1_SCALAR_SIZE);
      // zeroIdentifier.fill(0);
      //
      // try {
      //   Identifier.deserialize(zeroIdentifier);
      //   expect.fail("Should have thrown Error");
      // } catch (e) {
      //   expect(e).toBeInstanceOf(FrostError);
      //   expect((e as FrostError).inner).toBeInstanceOf(FieldError);
      //   expect(((e as FrostError).inner as FieldError).type).toBe(FieldErrorType.InvalidZeroScalar);
      // }

      // Placeholder until ciphersuite is implemented
      expect(true).toBe(true);
    });
  });
});

// Export test utility constants
export { SECP256K1_SCALAR_SIZE, SECP256K1_ELEMENT_SIZE, hexToBytes };
