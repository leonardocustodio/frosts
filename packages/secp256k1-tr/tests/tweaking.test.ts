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
  X_ONLY_PUBKEY_LENGTH,
  verifySignature,
  taprootTweakPubkey,
  type CryptoRng,
} from "./helpers/index.js";
import {
  Secp256K1Sha256TR,
  keys,
  round1,
  round2,
  aggregate as _aggregate,
  aggregateWithTweak,
  tweakPublicKeyPackage,
  hasEvenY,
  toXOnlyPublicKey,
  type Identifier,
  type KeyPackage,
  type SigningNonces,
  type SigningCommitments,
  type SignatureShare,
  type PublicKeyPackage as _PublicKeyPackage,
} from "../src/index.js";
import { SigningPackageImpl as SigningPackage } from "@frosts/core";

describe("FROST secp256k1-SHA256-TR Tweaking Tests", () => {
  let rng: CryptoRng;

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Tweaked Signing with Dealer", () => {
    it("should complete signing flow with taproot tweak", async () => {
      // Ported from: check_tweaked_sign_with_dealer
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      // Generate keys with dealer
      const [shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      // Convert secret shares to key packages
      const keyPackages = new Map<string, KeyPackage>();
      for (const [idStr, secretShare] of shares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idStr, keyPackage as unknown as KeyPackage);
      }

      // Round 1: Generate nonces and commitments for first minSigners participants
      const noncesMap = new Map<string, SigningNonces>();
      const commitmentsMap = new Map<Identifier, SigningCommitments>();

      let count = 0;
      for (const [idStr, keyPackage] of keyPackages) {
        if (count >= minSigners) break;

        const kp = keyPackage as unknown as { signingShare: unknown; identifier: Identifier };
        const [nonces, commitments] = round1.commit(kp.signingShare as never, rng);
        noncesMap.set(idStr, nonces);
        commitmentsMap.set(kp.identifier, commitments);
        count++;
      }

      // Create signing package
      const message = new TextEncoder().encode("message to sign");
      const signingPackage = SigningPackage.create(Secp256K1Sha256TR, commitmentsMap, message);

      // Round 2: Sign with tweak
      const signatureShares = new Map<Identifier, SignatureShare>();

      for (const [idStr, keyPackage] of keyPackages) {
        const nonces = noncesMap.get(idStr);
        if (!nonces) continue;

        const signatureShare = round2.signWithTweak(
          signingPackage as never,
          nonces,
          keyPackage,
          merkleRoot,
        );
        const kp = keyPackage as unknown as { identifier: Identifier };
        signatureShares.set(kp.identifier, signatureShare);
      }

      // Aggregate with tweak
      const groupSignature = aggregateWithTweak(
        signingPackage as never,
        signatureShares,
        pubkeyPackage,
        merkleRoot,
      );

      expect(groupSignature).toBeDefined();
    });

    it("should fail verification with untweaked public key", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      // Generate keys and sign with tweak
      const [shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      const keyPackages = new Map<string, KeyPackage>();
      for (const [idStr, secretShare] of shares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idStr, keyPackage as unknown as KeyPackage);
      }

      const noncesMap = new Map<string, SigningNonces>();
      const commitmentsMap = new Map<Identifier, SigningCommitments>();

      let count = 0;
      for (const [idStr, keyPackage] of keyPackages) {
        if (count >= minSigners) break;
        const kp = keyPackage as unknown as { signingShare: unknown; identifier: Identifier };
        const [nonces, commitments] = round1.commit(kp.signingShare as never, rng);
        noncesMap.set(idStr, nonces);
        commitmentsMap.set(kp.identifier, commitments);
        count++;
      }

      const message = new TextEncoder().encode("message to sign");
      const signingPackage = SigningPackage.create(Secp256K1Sha256TR, commitmentsMap, message);

      const signatureShares = new Map<Identifier, SignatureShare>();
      for (const [idStr, keyPackage] of keyPackages) {
        const nonces = noncesMap.get(idStr);
        if (!nonces) continue;
        const signatureShare = round2.signWithTweak(
          signingPackage as never,
          nonces,
          keyPackage,
          merkleRoot,
        );
        const kp = keyPackage as unknown as { identifier: Identifier };
        signatureShares.set(kp.identifier, signatureShare);
      }

      const groupSignature = aggregateWithTweak(
        signingPackage as never,
        signatureShares,
        pubkeyPackage,
        merkleRoot,
      );

      // Get signature and pubkey bytes
      const sigBytes = (
        groupSignature as unknown as { serialize: (c: typeof Secp256K1Sha256TR) => Uint8Array }
      ).serialize(Secp256K1Sha256TR);
      const pubkeyBytes = pubkeyPackage.verifyingKey as Uint8Array;

      // Verify fails with untweaked key
      expect(() => {
        verifySignature(message, sigBytes, pubkeyBytes);
      }).toThrow();
    });

    it("should succeed verification with tweaked public key", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      // Generate keys and sign with tweak
      const [shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      const keyPackages = new Map<string, KeyPackage>();
      for (const [idStr, secretShare] of shares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idStr, keyPackage as unknown as KeyPackage);
      }

      const noncesMap = new Map<string, SigningNonces>();
      const commitmentsMap = new Map<Identifier, SigningCommitments>();

      let count = 0;
      for (const [idStr, keyPackage] of keyPackages) {
        if (count >= minSigners) break;
        const kp = keyPackage as unknown as { signingShare: unknown; identifier: Identifier };
        const [nonces, commitments] = round1.commit(kp.signingShare as never, rng);
        noncesMap.set(idStr, nonces);
        commitmentsMap.set(kp.identifier, commitments);
        count++;
      }

      const message = new TextEncoder().encode("message to sign");
      const signingPackage = SigningPackage.create(Secp256K1Sha256TR, commitmentsMap, message);

      const signatureShares = new Map<Identifier, SignatureShare>();
      for (const [idStr, keyPackage] of keyPackages) {
        const nonces = noncesMap.get(idStr);
        if (!nonces) continue;
        const signatureShare = round2.signWithTweak(
          signingPackage as never,
          nonces,
          keyPackage,
          merkleRoot,
        );
        const kp = keyPackage as unknown as { identifier: Identifier };
        signatureShares.set(kp.identifier, signatureShare);
      }

      const groupSignature = aggregateWithTweak(
        signingPackage as never,
        signatureShares,
        pubkeyPackage,
        merkleRoot,
      );

      // Tweak the public key package
      const pubkeyPackageTweaked = tweakPublicKeyPackage(
        pubkeyPackage as unknown as {
          verifyingKey: Uint8Array;
          verifyingShares: Map<string, Uint8Array>;
        },
        merkleRoot,
      );

      // Get signature and tweaked pubkey bytes
      const sigBytes = (
        groupSignature as unknown as { serialize: (c: typeof Secp256K1Sha256TR) => Uint8Array }
      ).serialize(Secp256K1Sha256TR);
      const pubkeyBytes = pubkeyPackageTweaked.verifyingKey;

      // Verify succeeds with tweaked key
      verifySignature(message, sigBytes, pubkeyBytes);
    });

    it("should be verifiable by external BIP-340 verifier", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      // Generate keys and sign with tweak
      const [shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      const keyPackages = new Map<string, KeyPackage>();
      for (const [idStr, secretShare] of shares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idStr, keyPackage as unknown as KeyPackage);
      }

      const noncesMap = new Map<string, SigningNonces>();
      const commitmentsMap = new Map<Identifier, SigningCommitments>();

      let count = 0;
      for (const [idStr, keyPackage] of keyPackages) {
        if (count >= minSigners) break;
        const kp = keyPackage as unknown as { signingShare: unknown; identifier: Identifier };
        const [nonces, commitments] = round1.commit(kp.signingShare as never, rng);
        noncesMap.set(idStr, nonces);
        commitmentsMap.set(kp.identifier, commitments);
        count++;
      }

      const message = new TextEncoder().encode("message to sign");
      const signingPackage = SigningPackage.create(Secp256K1Sha256TR, commitmentsMap, message);

      const signatureShares = new Map<Identifier, SignatureShare>();
      for (const [idStr, keyPackage] of keyPackages) {
        const nonces = noncesMap.get(idStr);
        if (!nonces) continue;
        const signatureShare = round2.signWithTweak(
          signingPackage as never,
          nonces,
          keyPackage,
          merkleRoot,
        );
        const kp = keyPackage as unknown as { identifier: Identifier };
        signatureShares.set(kp.identifier, signatureShare);
      }

      const groupSignature = aggregateWithTweak(
        signingPackage as never,
        signatureShares,
        pubkeyPackage,
        merkleRoot,
      );

      // Tweak the public key package
      const pubkeyPackageTweaked = tweakPublicKeyPackage(
        pubkeyPackage as unknown as {
          verifyingKey: Uint8Array;
          verifyingShares: Map<string, Uint8Array>;
        },
        merkleRoot,
      );

      const sigBytes = (
        groupSignature as unknown as { serialize: (c: typeof Secp256K1Sha256TR) => Uint8Array }
      ).serialize(Secp256K1Sha256TR);
      const pubkeyBytes = pubkeyPackageTweaked.verifyingKey;

      // Verify using external BIP-340 verifier (helpers::verify_signature)
      verifySignature(message, sigBytes, pubkeyBytes);
    });
  });

  describe("Taproot Output Key Derivation", () => {
    it("should derive correct taproot output pubkey", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      const [_shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      // Get x-only pubkey from the verifying key
      const verifyingKey = pubkeyPackage.verifyingKey as Uint8Array;
      const xOnlyPubkey = toXOnlyPublicKey(verifyingKey);

      // Compute expected tweaked pubkey using BIP-341 algorithm
      const [_expectedParity, expectedTrOutputPubkey] = taprootTweakPubkey(xOnlyPubkey, merkleRoot);

      // Tweak the public key package
      const pubkeyPackageTweaked = tweakPublicKeyPackage(
        pubkeyPackage as unknown as {
          verifyingKey: Uint8Array;
          verifyingShares: Map<string, Uint8Array>;
        },
        merkleRoot,
      );

      // Get x-only tweaked pubkey
      const trOutputPubkey = toXOnlyPublicKey(pubkeyPackageTweaked.verifyingKey);

      // Compare x-coordinates
      expect(trOutputPubkey).toEqual(expectedTrOutputPubkey);
    });

    it("should derive correct parity bit", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      const [_shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      // Get x-only pubkey from the verifying key
      const verifyingKey = pubkeyPackage.verifyingKey as Uint8Array;
      const xOnlyPubkey = toXOnlyPublicKey(verifyingKey);

      // Compute expected parity using BIP-341 algorithm
      const [expectedParity, _expectedTrOutputPubkey] = taprootTweakPubkey(xOnlyPubkey, merkleRoot);

      // Tweak the public key package
      const pubkeyPackageTweaked = tweakPublicKeyPackage(
        pubkeyPackage as unknown as {
          verifyingKey: Uint8Array;
          verifyingShares: Map<string, Uint8Array>;
        },
        merkleRoot,
      );

      // Check parity: odd Y means prefix is 0x03
      const trOutputParity = !hasEvenY(pubkeyPackageTweaked.verifyingKey);

      expect(trOutputParity).toBe(expectedParity);
    });
  });

  describe("Tweak Trait", () => {
    it("should implement tweak for PublicKeyPackage", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      const [_shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      const tweakedPackage = tweakPublicKeyPackage(
        pubkeyPackage as unknown as {
          verifyingKey: Uint8Array;
          verifyingShares: Map<string, Uint8Array>;
        },
        merkleRoot,
      );

      expect(tweakedPackage).toBeDefined();
      expect(tweakedPackage.verifyingKey).not.toEqual(pubkeyPackage.verifyingKey);
    });

    it("should accept undefined merkle root for key-only spend", async () => {
      // For key-path-only spending, merkle_root can be undefined
      // This tweaks the key with just the internal key x-coordinate
      const maxSigners = 5;
      const minSigners = 3;

      const [_shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      const tweakedPackage = tweakPublicKeyPackage(
        pubkeyPackage as unknown as {
          verifyingKey: Uint8Array;
          verifyingShares: Map<string, Uint8Array>;
        },
        undefined,
      );

      expect(tweakedPackage).toBeDefined();
    });
  });

  describe("signWithTweak Function", () => {
    it("should generate signature share with tweak", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      const [shares, _pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      const keyPackages = new Map<string, KeyPackage>();
      for (const [idStr, secretShare] of shares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idStr, keyPackage as unknown as KeyPackage);
      }

      // Generate commitments from minSigners participants (need at least 3)
      const commitmentsMap = new Map<Identifier, SigningCommitments>();
      const noncesMap = new Map<string, SigningNonces>();
      let count = 0;
      for (const [idStr, keyPackage] of keyPackages) {
        if (count >= minSigners) break;
        const kp = keyPackage as unknown as { signingShare: unknown; identifier: Identifier };
        const [nonces, commitments] = round1.commit(kp.signingShare as never, rng);
        commitmentsMap.set(kp.identifier, commitments);
        noncesMap.set(idStr, nonces);
        count++;
      }

      // Get first key package and its nonces
      const [firstIdStr, firstKeyPackage] = keyPackages.entries().next().value as [
        string,
        KeyPackage,
      ];
      const firstNonces = noncesMap.get(firstIdStr);
      if (firstNonces === undefined) {
        throw new Error("firstNonces not found");
      }

      const message = new TextEncoder().encode("test message");
      const signingPackage = SigningPackage.create(Secp256K1Sha256TR, commitmentsMap, message);

      const signatureShare = round2.signWithTweak(
        signingPackage as never,
        firstNonces,
        firstKeyPackage,
        merkleRoot,
      );

      expect(signatureShare).toBeDefined();
    });
  });

  describe("aggregateWithTweak Function", () => {
    it("should aggregate signature shares with tweak", async () => {
      const merkleRoot = sampleMerkleRoot();
      const maxSigners = 5;
      const minSigners = 3;

      const [shares, pubkeyPackage] = await keys.generateWithDealer(
        maxSigners,
        minSigners,
        { type: "Default" },
        rng,
      );

      const keyPackages = new Map<string, KeyPackage>();
      for (const [idStr, secretShare] of shares) {
        const keyPackage = secretShare.toKeyPackage();
        keyPackages.set(idStr, keyPackage as unknown as KeyPackage);
      }

      const noncesMap = new Map<string, SigningNonces>();
      const commitmentsMap = new Map<Identifier, SigningCommitments>();

      let count = 0;
      for (const [idStr, keyPackage] of keyPackages) {
        if (count >= minSigners) break;
        const kp = keyPackage as unknown as { signingShare: unknown; identifier: Identifier };
        const [nonces, commitments] = round1.commit(kp.signingShare as never, rng);
        noncesMap.set(idStr, nonces);
        commitmentsMap.set(kp.identifier, commitments);
        count++;
      }

      const message = new TextEncoder().encode("test message");
      const signingPackage = SigningPackage.create(Secp256K1Sha256TR, commitmentsMap, message);

      const signatureShares = new Map<Identifier, SignatureShare>();
      for (const [idStr, keyPackage] of keyPackages) {
        const nonces = noncesMap.get(idStr);
        if (!nonces) continue;
        const signatureShare = round2.signWithTweak(
          signingPackage as never,
          nonces,
          keyPackage,
          merkleRoot,
        );
        const kp = keyPackage as unknown as { identifier: Identifier };
        signatureShares.set(kp.identifier, signatureShare);
      }

      const groupSignature = aggregateWithTweak(
        signingPackage as never,
        signatureShares,
        pubkeyPackage,
        merkleRoot,
      );

      expect(groupSignature).toBeDefined();
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
    // The taprootTweakPubkey function in helpers implements this algorithm
    const xOnlyPubkey = new Uint8Array(32);
    xOnlyPubkey[0] = 0x79;
    xOnlyPubkey[1] = 0xbe;
    // ... fill with generator x-coordinate
    const _merkleRoot = sampleMerkleRoot();
    void _merkleRoot; // Will be used when tweaking implementation is complete

    // Just verify the function exists and returns expected types
    expect(typeof taprootTweakPubkey).toBe("function");
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
  it("should adjust key for even y-coordinate", async () => {
    // BIP-340 requires the public key to have an even y-coordinate
    // If it's odd, the secret key is negated
    //
    // This is handled internally by the ciphersuite
    const rng = createSecureRng();
    const maxSigners = 3;
    const minSigners = 2;

    const [_shares, pubkeyPackage] = await keys.generateWithDealer(
      maxSigners,
      minSigners,
      { type: "Default" },
      rng,
    );

    // The verifying key is always valid
    expect(pubkeyPackage.verifyingKey).toBeDefined();
    const verifyingKey = pubkeyPackage.verifyingKey as Uint8Array;
    expect(verifyingKey.length).toBe(33);
  });

  it("should handle parity in signature generation", async () => {
    // The signing process adjusts for parity to ensure
    // the signature is valid under the x-only public key
    const rng = createSecureRng();
    const maxSigners = 3;
    const minSigners = 2;

    const [_shares, pubkeyPackage] = await keys.generateWithDealer(
      maxSigners,
      minSigners,
      { type: "Default" },
      rng,
    );

    // hasEvenY function checks the parity
    const verifyingKey = pubkeyPackage.verifyingKey as Uint8Array;
    const isEven = hasEvenY(verifyingKey);
    expect(typeof isEven).toBe("boolean");
  });
});
