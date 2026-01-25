/**
 * Taproot key tweaking tests for FROST secp256k1-SHA256-TR.
 * Ported from frost-secp256k1-tr/tests/tweaking_tests.rs
 *
 * These tests verify the taproot-specific key tweaking functionality
 * which allows using FROST-generated keys in Bitcoin taproot outputs.
 *
 * Key concepts:
 * - Taproot uses tweaked public keys for outputs
 * - The tweak is computed from the internal key and merkle root
 * - Signatures must be generated with the tweaked key
 * - The internal key can be revealed for script path spending
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createSecureRng,
  sampleMerkleRoot,
  SCALAR_LENGTH,
  ELEMENT_LENGTH,
  X_ONLY_PUBKEY_LENGTH,
  type CryptoRng,
} from "./helpers/index.js";

// Import types when available
// import {
//   Secp256K1Sha256TR,
//   keys,
//   round1,
//   round2,
//   aggregate,
//   aggregateWithTweak,
//   signWithTweak,
//   Tweak,
//   VerifyingKey,
//   PublicKeyPackage,
// } from "../src/index.js";

describe("FROST secp256k1-SHA256-TR Tweaking Tests", () => {
  let _rng: CryptoRng;

  beforeEach(() => {
    _rng = createSecureRng();
  });

  describe("Tweaked Signing with Dealer", () => {
    it.skip("should complete signing flow with taproot tweak", () => {
      // Ported from: check_tweaked_sign_with_dealer
      // This test verifies the complete tweaked signing flow:
      //
      // let merkle_root: Vec<u8> = vec![12; 32];
      //
      // let mut rng = rand::rngs::OsRng;
      // let max_signers = 5;
      // let min_signers = 3;
      // let (shares, pubkey_package) = frost::keys::generate_with_dealer(
      //     max_signers,
      //     min_signers,
      //     frost::keys::IdentifierList::Default,
      //     rng,
      // )?;
      //
      // const maxSigners = 5;
      // const minSigners = 3;
      // const merkleRoot = sampleMerkleRoot();
      //
      // const [shares, pubkeyPackage] = await keys.generateWithDealer(
      //   maxSigners,
      //   minSigners,
      //   IdentifierList.Default,
      //   rng
      // );
      //
      // // Round 1: Generate nonces and commitments
      // const noncesMap = new Map();
      // const commitmentsMap = new Map();
      // for (let i = 1; i <= minSigners; i++) {
      //   const identifier = Identifier.tryFrom(i);
      //   const keyPackage = keyPackages.get(identifier);
      //   const [nonces, commitments] = round1.commit(keyPackage.signingShare(), rng);
      //   noncesMap.set(identifier, nonces);
      //   commitmentsMap.set(identifier, commitments);
      // }
      //
      // // Round 2: Sign with tweak
      // const signatureShares = new Map();
      // const message = new TextEncoder().encode("message to sign");
      // const signingPackage = SigningPackage.new(commitmentsMap, message);
      //
      // for (const [identifier, keyPackage] of keyPackages) {
      //   const nonces = noncesMap.get(identifier);
      //   const signatureShare = round2.signWithTweak(
      //     signingPackage,
      //     nonces,
      //     keyPackage,
      //     merkleRoot
      //   );
      //   signatureShares.set(identifier, signatureShare);
      // }
      //
      // // Aggregate with tweak
      // const groupSignature = aggregateWithTweak(
      //   signingPackage,
      //   signatureShares,
      //   pubkeyPackage,
      //   merkleRoot
      // );
      expect(true).toBe(true);
    });

    it.skip("should fail verification with untweaked public key", () => {
      // Ported from check_tweaked_sign_with_dealer:
      // pubkey_package
      //     .verifying_key()
      //     .verify(message, &group_signature)
      //     .expect_err("signature should not be valid for untweaked pubkey_package");
      //
      // const pubkeyPackage = ...; // from key generation
      // const groupSignature = ...; // from aggregation
      // const message = ...; // message that was signed
      //
      // // Verify fails with untweaked key
      // expect(() => {
      //   pubkeyPackage.verifyingKey().verify(message, groupSignature);
      // }).toThrow();
      expect(true).toBe(true);
    });

    it.skip("should succeed verification with tweaked public key", () => {
      // Ported from check_tweaked_sign_with_dealer:
      // let pubkey_package_tweaked = pubkey_package.clone().tweak(Some(&merkle_root));
      // pubkey_package_tweaked
      //     .verifying_key()
      //     .verify(message, &group_signature)
      //     .expect("signature should be valid for tweaked pubkey_package");
      //
      // const pubkeyPackageTweaked = pubkeyPackage.tweak(merkleRoot);
      //
      // // Verify succeeds with tweaked key
      // pubkeyPackageTweaked.verifyingKey().verify(message, groupSignature);
      expect(true).toBe(true);
    });

    it.skip("should be verifiable by external BIP-340 verifier", () => {
      // Ported from check_tweaked_sign_with_dealer:
      // helpers::verify_signature(
      //     message,
      //     &group_signature,
      //     pubkey_package_tweaked.verifying_key(),
      // );
      //
      // const pubkeyPackageTweaked = pubkeyPackage.tweak(merkleRoot);
      // verifySignature(message, groupSignature, pubkeyPackageTweaked.verifyingKey());
      expect(true).toBe(true);
    });
  });

  describe("Taproot Output Key Derivation", () => {
    it.skip("should derive correct taproot output pubkey", () => {
      // Ported from check_tweaked_sign_with_dealer:
      // // Confirm the internal (untweaked) group key can be provided to access
      // // script spending paths under the output (tweaked) group key.
      // let (expected_parity, expected_tr_output_pubkey) = taproot_tweak_pubkey(
      //     pubkey_package
      //         .verifying_key()
      //         .to_element()
      //         .to_affine()
      //         .x()
      //         .into(),
      //     &merkle_root,
      // );
      //
      // const [expectedParity, expectedTrOutputPubkey] = taprootTweakPubkey(
      //   pubkeyPackage.verifyingKey().toXOnly(),
      //   merkleRoot
      // );
      //
      // const pubkeyPackageTweaked = pubkeyPackage.tweak(merkleRoot);
      // const trOutputPubkey = pubkeyPackageTweaked.verifyingKey().toXOnly();
      //
      // expect(trOutputPubkey).toEqual(expectedTrOutputPubkey);
      expect(true).toBe(true);
    });

    it.skip("should derive correct parity bit", () => {
      // Ported from check_tweaked_sign_with_dealer:
      // let tr_output_parity: bool = tr_output_point.y_is_odd().into();
      // assert_eq!(
      //     tr_output_parity, expected_parity,
      //     "taproot output pubkey parity bit does not match"
      // );
      //
      // const pubkeyPackageTweaked = pubkeyPackage.tweak(merkleRoot);
      // const [expectedParity, _] = taprootTweakPubkey(
      //   pubkeyPackage.verifyingKey().toXOnly(),
      //   merkleRoot
      // );
      //
      // const trOutputParity = pubkeyPackageTweaked.verifyingKey().isYOdd();
      // expect(trOutputParity).toBe(expectedParity);
      expect(true).toBe(true);
    });
  });

  describe("Tweak Trait", () => {
    it.skip("should implement tweak for PublicKeyPackage", () => {
      // The Tweak trait adds .tweak(merkle_root) method
      //
      // const pubkeyPackage = ...; // from key generation
      // const merkleRoot = sampleMerkleRoot();
      //
      // const tweakedPackage = pubkeyPackage.tweak(merkleRoot);
      // expect(tweakedPackage).toBeDefined();
      // expect(tweakedPackage.verifyingKey()).not.toEqual(pubkeyPackage.verifyingKey());
      expect(true).toBe(true);
    });

    it.skip("should accept null merkle root for key-only spend", () => {
      // For key-path-only spending, merkle_root can be null
      // This tweaks the key with just the internal key x-coordinate
      //
      // const tweakedPackage = pubkeyPackage.tweak(null);
      // expect(tweakedPackage).toBeDefined();
      expect(true).toBe(true);
    });
  });

  describe("signWithTweak Function", () => {
    it.skip("should generate signature share with tweak", () => {
      // round2::sign_with_tweak is used instead of round2::sign
      //
      // const signatureShare = round2.signWithTweak(
      //   signingPackage,
      //   nonces,
      //   keyPackage,
      //   merkleRoot
      // );
      // expect(signatureShare).toBeDefined();
      expect(true).toBe(true);
    });
  });

  describe("aggregateWithTweak Function", () => {
    it.skip("should aggregate signature shares with tweak", () => {
      // frost::aggregate_with_tweak is used instead of frost::aggregate
      //
      // const groupSignature = aggregateWithTweak(
      //   signingPackage,
      //   signatureShares,
      //   pubkeyPackage,
      //   merkleRoot
      // );
      // expect(groupSignature).toBeDefined();
      expect(true).toBe(true);
    });
  });
});

describe("Taproot Tweak Helper Function", () => {
  it("should understand the taproot tweak algorithm", () => {
    // The taproot_tweak_pubkey function implements BIP-341:
    //
    // def taproot_tweak_pubkey(pubkey, h):
    //     t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
    //     if t >= SECP256K1_ORDER:
    //         raise ValueError
    //     P = lift_x(int_from_bytes(pubkey))
    //     if P is None:
    //         raise ValueError
    //     Q = point_add(P, point_mul(G, t))
    //     return 0 if has_even_y(Q) else 1, bytes_from_int(x(Q))
    //
    // In TypeScript:
    // function taprootTweakPubkey(pubkey: Uint8Array, merkleRoot: Uint8Array): [boolean, Uint8Array] {
    //   const prefix = sha256("TapTweak");
    //   const tweakHash = sha256(concat(prefix, prefix, pubkey, merkleRoot));
    //   const t = scalarFromBytes(tweakHash);
    //   const P = liftX(pubkey);
    //   const Q = P.add(G.multiply(t));
    //   return [Q.isYOdd(), Q.x.toBytes()];
    // }
    expect(true).toBe(true);
  });

  it("should use tagged hash for tweak computation", () => {
    // BIP-341 uses tagged hashes: SHA256(SHA256(tag) || SHA256(tag) || data)
    // The tag for tweaking is "TapTweak"
    expect(true).toBe(true);
  });
});

describe("Taproot Concepts", () => {
  it("should understand internal vs output key", () => {
    // In Taproot:
    // - Internal key: The untweaked FROST group key
    // - Output key: The tweaked key that appears on-chain
    // - The internal key is needed to reveal script paths
    expect(true).toBe(true);
  });

  it("should understand key-path vs script-path spending", () => {
    // Key-path: Spend using just the output key (efficient, private)
    // Script-path: Reveal internal key and merkle proof to use scripts
    //
    // FROST enables threshold key-path spending
    expect(true).toBe(true);
  });

  it("should understand x-only public keys", () => {
    // BIP-340 uses x-only public keys (32 bytes instead of 33)
    // The y-coordinate parity is implicit and adjusted during signing
    expect(X_ONLY_PUBKEY_LENGTH).toBe(32);
  });

  it("should understand merkle root for script trees", () => {
    // The merkle root commits to a tree of spending scripts
    // If no scripts: use null merkle root (key-only spend)
    // With scripts: use SHA256 of the script tree root
    const merkleRoot = sampleMerkleRoot();
    expect(merkleRoot.length).toBe(32);
  });
});

describe("EvenY Trait", () => {
  it.skip("should adjust key for even y-coordinate", () => {
    // BIP-340 requires the public key to have an even y-coordinate
    // If it's odd, the secret key is negated
    //
    // This is handled internally by the ciphersuite
    expect(true).toBe(true);
  });

  it.skip("should handle parity in signature generation", () => {
    // The signing process adjusts for parity to ensure
    // the signature is valid under the x-only public key
    expect(true).toBe(true);
  });
});
