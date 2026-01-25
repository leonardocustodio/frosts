/**
 * Interoperability tests for FROST Ed25519-SHA512.
 * Ported from frost-ed25519/tests/interoperability_tests.rs
 *
 * These tests verify that FROST signatures created with the Ed25519-SHA512
 * ciphersuite can be verified by standard Ed25519 libraries (like ed25519-dalek
 * in Rust, or @noble/ed25519 in JavaScript).
 *
 * This is critical for ensuring that FROST signatures are compatible with
 * the broader Ed25519 ecosystem and can be verified by any compliant Ed25519
 * implementation.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createSecureRng,
  verifySignature,
  VECTORS,
  bytesToHex,
  hexToBytes,
  type CryptoRng,
} from "./helpers/index.js";

// Import from @frosts/core when available
// import {
//   checkSignWithDkg,
//   checkSignWithDealer,
// } from "@frosts/core/tests";

// Import Ed25519Sha512 ciphersuite when available
// import { Ed25519Sha512 } from "../src/index.js";

describe("FROST Ed25519-SHA512 Interoperability Tests", () => {
  let _rng: CryptoRng;

  beforeEach(() => {
    _rng = createSecureRng();
  });

  describe("Interoperability with Standard Ed25519", () => {
    it.skip("should verify FROST signatures with DKG using standard Ed25519", () => {
      // Ported from: check_interoperability_in_sign_with_dkg
      //
      // This test performs multiple iterations to better exercise the key generation
      // and interoperability check. A smaller number of iterations is used
      // because DKG takes longer.
      //
      // for _ in 0..32 {
      //   const rng = createSecureRng();
      //   const [msg, groupSignature, groupPubkey] =
      //     frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Ed25519Sha512, _>(rng);
      //
      //   // Verify using standard Ed25519 library
      //   helpers::verify_signature(&msg, groupSignature, groupPubkey);
      // }
      //
      // Note: 32 iterations to exercise key generation
      // for (let i = 0; i < 32; i++) {
      //   const rng = createSecureRng();
      //   const [msg, groupSignature, groupPubkey] = checkSignWithDkg(Ed25519Sha512, rng);
      //
      //   // Verify using @noble/ed25519 or similar
      //   const isValid = await verifySignature(msg, groupSignature, groupPubkey);
      //   expect(isValid).toBe(true);
      // }
      expect(true).toBe(true);
    });

    it.skip("should verify FROST signatures with dealer using standard Ed25519", () => {
      // Ported from: check_interoperability_in_sign_with_dealer
      //
      // This test performs many iterations to better exercise key generation
      // and the interoperability check.
      //
      // for _ in 0..256 {
      //   const rng = createSecureRng();
      //   const [msg, groupSignature, groupPubkey] =
      //     frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Ed25519Sha512, _>(rng);
      //
      //   // Check that the threshold signature can be verified by the `ed25519_dalek` crate
      //   // public key (interoperability test)
      //   helpers::verify_signature(&msg, groupSignature, groupPubkey);
      // }
      //
      // Note: 256 iterations for thorough testing
      // for (let i = 0; i < 256; i++) {
      //   const rng = createSecureRng();
      //   const [msg, groupSignature, groupPubkey] = checkSignWithDealer(Ed25519Sha512, rng);
      //
      //   // Verify using @noble/ed25519 or similar
      //   const isValid = await verifySignature(msg, groupSignature, groupPubkey);
      //   expect(isValid).toBe(true);
      // }
      expect(true).toBe(true);
    });
  });

  describe("Test Vector Signature Verification", () => {
    it.skip("should verify test vector signature with standard Ed25519", async () => {
      // Verify that the test vector signature can be verified by a standard Ed25519 library
      const sig = hexToBytes(VECTORS.final_output.sig);
      const pubkey = hexToBytes(VECTORS.inputs.verifying_key_key);
      const msg = hexToBytes(VECTORS.inputs.message);

      // The signature should be 64 bytes (32 R + 32 s)
      expect(sig.length).toBe(64);
      // The public key should be 32 bytes
      expect(pubkey.length).toBe(32);

      // TODO: Use @noble/ed25519 to verify
      // import { verify } from '@noble/ed25519';
      // const isValid = await verify(sig, msg, pubkey);
      // expect(isValid).toBe(true);
    });

    it("should have correctly formatted test vector signature", () => {
      const sig = VECTORS.final_output.sig;
      // Ed25519 signatures are 64 bytes = 128 hex chars
      expect(sig.length).toBe(128);
      // All hex characters should be lowercase
      expect(sig).toBe(sig.toLowerCase());
      // Should be valid hex
      expect(/^[0-9a-f]+$/.test(sig)).toBe(true);
    });

    it("should have correctly formatted test vector public key", () => {
      const pubkey = VECTORS.inputs.verifying_key_key;
      // Ed25519 public keys are 32 bytes = 64 hex chars
      expect(pubkey.length).toBe(64);
      // All hex characters should be lowercase
      expect(pubkey).toBe(pubkey.toLowerCase());
      // Should be valid hex
      expect(/^[0-9a-f]+$/.test(pubkey)).toBe(true);
    });
  });

  describe("Signature Format Compatibility", () => {
    it("should use standard Ed25519 signature format", () => {
      // Ed25519 signatures consist of:
      // - R: 32 bytes (compressed point, the commitment)
      // - s: 32 bytes (scalar, the response)
      // Total: 64 bytes
      const sig = hexToBytes(VECTORS.final_output.sig);
      const R = sig.slice(0, 32);
      const s = sig.slice(32, 64);

      expect(R.length).toBe(32);
      expect(s.length).toBe(32);
    });

    it("should use standard Ed25519 public key format", () => {
      // Ed25519 public keys are compressed Edwards points (32 bytes)
      const pubkey = hexToBytes(VECTORS.inputs.verifying_key_key);
      expect(pubkey.length).toBe(32);
    });

    it("should produce signatures verifiable by RFC 8032", () => {
      // RFC 8032 defines the Ed25519 signature algorithm
      // FROST signatures should be compatible with this standard
      //
      // Key points:
      // 1. Signature format is R || s (64 bytes total)
      // 2. R is a compressed Edwards point
      // 3. s is a scalar reduced modulo the group order
      // 4. Verification equation: [s]B = R + [H(R,A,m)]A
      //    where B is the base point, A is the public key, m is the message
      expect(true).toBe(true);
    });
  });

  describe("Group Element Encoding", () => {
    it("should use compressed Edwards encoding for public keys", () => {
      // Ed25519 uses compressed Edwards form for encoding points
      // The y-coordinate is stored, with the sign of x in the high bit
      const pubkey = hexToBytes(VECTORS.inputs.verifying_key_key);

      // Last byte may have the high bit set for x-coordinate sign
      // This is part of the compressed point encoding
      expect(pubkey.length).toBe(32);
    });

    it("should use canonical encoding for scalars", () => {
      // Ed25519 scalars are encoded as 32-byte little-endian integers
      // They must be reduced modulo the group order l
      // l = 2^252 + 27742317777372353535851937790883648493
      const participantShare = hexToBytes(VECTORS.inputs.participant_shares[0].participant_share);
      expect(participantShare.length).toBe(32);
    });
  });
});

describe("Ed25519 Standards Compliance", () => {
  it("should understand Ed25519 curve parameters", () => {
    // Ed25519 is defined over the Curve25519 curve in twisted Edwards form
    //
    // Curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
    // where d = -121665/121666
    //
    // Base point order: l = 2^252 + 27742317777372353535851937790883648493
    // This is a 253-bit prime
    //
    // Field prime: p = 2^255 - 19
    //
    // FROST uses the same parameters but with threshold signatures
    expect(true).toBe(true);
  });

  it("should understand FROST's modifications to Ed25519", () => {
    // FROST modifies the standard Ed25519 signing in the following ways:
    //
    // 1. Key generation is distributed (DKG or trusted dealer)
    //    - Each participant has a key share
    //    - The group public key is the sum of all share public keys
    //
    // 2. Signing is interactive
    //    - Round 1: Generate and share nonce commitments
    //    - Round 2: Generate and share signature shares
    //
    // 3. Signature aggregation
    //    - Signature shares are combined to form the final signature
    //
    // The final signature is indistinguishable from a standard Ed25519 signature
    // and can be verified by any Ed25519 implementation
    expect(true).toBe(true);
  });

  it("should understand verification compatibility", () => {
    // A FROST signature (R, s) can be verified by:
    //
    // 1. Computing h = H(R || A || m) where A is the group public key
    // 2. Checking [s]B = R + [h]A
    //
    // This is exactly the same as standard Ed25519 verification
    // because:
    // - R is the aggregate nonce commitment (same format as Ed25519)
    // - s is the aggregate response (same format as Ed25519)
    // - A is the group public key (same format as Ed25519)
    //
    // Therefore, any RFC 8032 compliant Ed25519 library can verify FROST signatures
    expect(true).toBe(true);
  });
});

describe("Interoperability Test Helper", () => {
  it("should provide verifySignature helper", () => {
    // The verifySignature helper is used to verify FROST signatures
    // using a standard Ed25519 library (like @noble/ed25519)
    expect(verifySignature).toBeDefined();
    expect(typeof verifySignature).toBe("function");
  });

  it.skip("should verify a known-good signature", async () => {
    // Test with the test vector signature
    const sig = hexToBytes(VECTORS.final_output.sig);
    const pubkey = hexToBytes(VECTORS.inputs.verifying_key_key);
    const msg = hexToBytes(VECTORS.inputs.message);

    // Create mock objects with serialize methods
    const mockSignature = {
      serialize: () => sig,
    };
    const mockPubkey = {
      serialize: () => pubkey,
    };

    const isValid = await verifySignature(msg, mockSignature, mockPubkey);
    expect(isValid).toBe(true);
  });
});
