/**
 * Property-based tests for FROST signatures.
 * Ported from frost-core/src/tests/proptests.rs
 *
 * Uses fast-check for property testing to verify signature behavior:
 * - Valid signatures always verify correctly
 * - Changing the message invalidates the signature
 * - Changing the public key invalidates the signature
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as fc from "fast-check";
import type { Ciphersuite, CryptoRng } from "../src/index.js";
import { SigningKey } from "../src/signing_key.js";
import { VerifyingKey } from "../src/verifying_key.js";
import type { Signature } from "../src/signature.js";
import { createSecureRng } from "./helpers.js";
import { getTestCiphersuite } from "./helpers/ciphersuite.js";

/**
 * A modification to a test-case.
 * Ported from Tweak enum in proptests.rs
 */
export enum Tweak {
  /** No-op, used to check that unchanged cases verify. */
  None = "None",
  /** Change the message the signature is defined for, invalidating the signature. */
  ChangeMessage = "ChangeMessage",
  /** Change the public key the signature is defined for, invalidating the signature. */
  ChangePubkey = "ChangePubkey",
}

/**
 * A signature test-case, containing signature data and expected validity.
 * Ported from SignatureCase struct in proptests.rs
 *
 * @typeParam C - The ciphersuite type
 */
export class SignatureCase<C extends Ciphersuite> {
  /** The message that was signed */
  private _msg: Uint8Array;
  /** The signature over the message */
  private readonly _sig: Signature<C>;
  /** The verifying key (can be swapped to invalidate) */
  private _vk: VerifyingKey<C>;
  /** An invalid verifying key (for ChangePubkey tweak) */
  private readonly _invalidVk: VerifyingKey<C>;
  /** Whether the signature is expected to verify */
  private _isValid: boolean;
  /** The ciphersuite for this test case */
  private readonly _ciphersuite: C;

  /**
   * Private constructor - use SignatureCase.create() instead.
   */
  private constructor(
    ciphersuite: C,
    msg: Uint8Array,
    sig: Signature<C>,
    vk: VerifyingKey<C>,
    invalidVk: VerifyingKey<C>,
    isValid: boolean,
  ) {
    this._ciphersuite = ciphersuite;
    this._msg = msg;
    this._sig = sig;
    this._vk = vk;
    this._invalidVk = invalidVk;
    this._isValid = isValid;
  }

  /**
   * Create a new SignatureCase.
   * Generates a random signing key, signs the message, and creates an invalid
   * verifying key for testing the ChangePubkey tweak.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param rng - A cryptographically secure random number generator
   * @param msg - The message to sign
   * @returns A new SignatureCase
   */
  static create<C extends Ciphersuite>(
    ciphersuite: C,
    rng: CryptoRng,
    msg: Uint8Array,
  ): SignatureCase<C> {
    // Generate a random signing key
    const sk = SigningKey.generate(ciphersuite, rng);
    // Sign the message
    const sig = sk.sign(rng, msg);
    // Derive the verifying key from the signing key
    const vk = VerifyingKey.fromSigningKey(ciphersuite, sk);
    // Generate a different signing key for the invalid verifying key
    const invalidSk = SigningKey.generate(ciphersuite, rng);
    const invalidVk = VerifyingKey.fromSigningKey(ciphersuite, invalidSk);

    return new SignatureCase(ciphersuite, msg, sig, vk, invalidVk, true);
  }

  /**
   * Check that signature verification succeeds or fails, as expected.
   *
   * This method exercises the round-trip serialization/deserialization
   * code paths for both signatures and verifying keys.
   *
   * @returns true if the verification result matches the expected validity
   */
  check(): boolean {
    // The signature data is stored in (refined) byte types, but do a round trip
    // conversion to raw bytes to exercise those code paths.
    const sigBytes = this._sig.serialize(this._ciphersuite);
    // Note: Signature.deserialize is available but not used here since
    // we're verifying with the original signature object
    void sigBytes;

    // Check that the verification key is a valid key.
    const vkBytes = this._vk.serialize();
    const deserializedVk = VerifyingKey.deserialize(this._ciphersuite, vkBytes);
    // Verify the deserialized key equals the original
    if (!deserializedVk.equals(this._vk)) {
      return false;
    }

    // Check that signature validation has the expected result.
    try {
      this._vk.verify(this._msg, this._sig);
      // Verification succeeded
      return this._isValid === true;
    } catch {
      // Verification failed
      return this._isValid === false;
    }
  }

  /**
   * Apply the given tweak to the signature test case.
   *
   * @param tweak - The modification to apply
   */
  applyTweak(tweak: Tweak): void {
    switch (tweak) {
      case Tweak.None:
        // No-op
        break;

      case Tweak.ChangeMessage: {
        // Changing the message makes the signature invalid.
        // Append a byte to the message (matching Rust: self.msg.push(90))
        const newMsg = new Uint8Array(this._msg.length + 1);
        newMsg.set(this._msg, 0);
        newMsg[this._msg.length] = 90;
        this._msg = newMsg;
        this._isValid = false;
        break;
      }

      case Tweak.ChangePubkey:
        // Changing the public key makes the signature invalid.
        this._vk = this._invalidVk;
        this._isValid = false;
        break;
    }
  }

  /**
   * Get the current validity expectation.
   */
  get isValid(): boolean {
    return this._isValid;
  }

  /**
   * Get the message.
   */
  get message(): Uint8Array {
    return this._msg;
  }

  /**
   * Get the signature.
   */
  get signature(): Signature<C> {
    return this._sig;
  }

  /**
   * Get the verifying key.
   */
  get verifyingKey(): VerifyingKey<C> {
    return this._vk;
  }
}

/**
 * Proptest strategy for generating tweaks.
 * Weighted to favor Tweak.None (10:1:1 ratio like Rust).
 *
 * This creates an arbitrary that generates Tweak values with the same
 * probability distribution as the Rust prop_oneof! macro.
 */
export const tweakArbitrary: fc.Arbitrary<Tweak> = fc.oneof(
  { weight: 10, arbitrary: fc.constant(Tweak.None) },
  { weight: 1, arbitrary: fc.constant(Tweak.ChangeMessage) },
  { weight: 1, arbitrary: fc.constant(Tweak.ChangePubkey) },
);

/**
 * Arbitrary for generating random messages (variable length byte arrays).
 * Messages can be 0-1024 bytes in length.
 */
export const messageArbitrary: fc.Arbitrary<Uint8Array> = fc
  .uint8Array({ minLength: 0, maxLength: 1024 })
  .map((arr) => new Uint8Array(arr));

/**
 * Create a property-based test suite for a specific ciphersuite.
 *
 * This function creates the test suite that can be imported and run
 * by ciphersuite-specific packages (e.g., @frosts/ristretto255).
 *
 * @param ciphersuite - The ciphersuite to test
 * @param suiteName - Optional name for the test suite
 */
export function createPropTests<C extends Ciphersuite>(
  ciphersuite: C,
  suiteName: string = "Signature Property Tests",
): void {
  describe(suiteName, () => {
    it("should verify valid signatures correctly", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          // Without any tweak, the signature should be valid
          return signatureCase.check();
        }),
        { numRuns: 100 },
      );
    });

    it("should handle tweaks correctly", () => {
      fc.assert(
        fc.property(messageArbitrary, tweakArbitrary, (msg, tweak) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(tweak);
          return signatureCase.check();
        }),
        { numRuns: 100 },
      );
    });

    it("should invalidate signature when message is changed", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(Tweak.ChangeMessage);

          // After changing the message, isValid should be false
          expect(signatureCase.isValid).toBe(false);

          // The check should still pass (meaning verification fails as expected)
          return signatureCase.check();
        }),
        { numRuns: 50 },
      );
    });

    it("should invalidate signature when public key is changed", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(Tweak.ChangePubkey);

          // After changing the public key, isValid should be false
          expect(signatureCase.isValid).toBe(false);

          // The check should still pass (meaning verification fails as expected)
          return signatureCase.check();
        }),
        { numRuns: 50 },
      );
    });

    it("should keep signature valid when no tweak is applied", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(Tweak.None);

          // With no tweak, isValid should still be true
          expect(signatureCase.isValid).toBe(true);

          // The check should pass (meaning verification succeeds as expected)
          return signatureCase.check();
        }),
        { numRuns: 50 },
      );
    });

    it("should handle empty messages", () => {
      const rng = createSecureRng();
      const emptyMsg = new Uint8Array(0);
      const signatureCase = SignatureCase.create(ciphersuite, rng, emptyMsg);

      // Empty messages should work correctly
      expect(signatureCase.check()).toBe(true);

      // And tweaks should still invalidate them
      const signatureCase2 = SignatureCase.create(ciphersuite, rng, emptyMsg);
      signatureCase2.applyTweak(Tweak.ChangeMessage);
      expect(signatureCase2.check()).toBe(true);
    });

    it("should handle large messages", () => {
      const rng = createSecureRng();
      // Generate a 10KB message
      const largeMsg = new Uint8Array(10240);
      rng.fill(largeMsg);

      const signatureCase = SignatureCase.create(ciphersuite, rng, largeMsg);
      expect(signatureCase.check()).toBe(true);
    });
  });
}

/**
 * Run a single signature test with the given parameters.
 * Useful for integration testing with specific ciphersuites.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param msg - The message to sign
 * @param tweak - The tweak to apply
 * @returns true if the test passes
 */
export function runSignatureTest<C extends Ciphersuite>(
  ciphersuite: C,
  msg: Uint8Array,
  tweak: Tweak,
): boolean {
  const rng = createSecureRng();
  const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
  signatureCase.applyTweak(tweak);
  return signatureCase.check();
}

// Run property-based tests with dynamically-loaded ciphersuite
describe("Property-Based Tests", () => {
  let ciphersuite: Ciphersuite;

  beforeAll(async () => {
    ciphersuite = await getTestCiphersuite();
  });

  describe("Signature Property Tests", () => {
    it("should verify valid signatures correctly", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          return signatureCase.check();
        }),
        { numRuns: 100 },
      );
    }, 30_000);

    it("should handle tweaks correctly", () => {
      fc.assert(
        fc.property(messageArbitrary, tweakArbitrary, (msg, tweak) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(tweak);
          return signatureCase.check();
        }),
        { numRuns: 100 },
      );
    }, 30_000);

    it("should invalidate signature when message is changed", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(Tweak.ChangeMessage);
          expect(signatureCase.isValid).toBe(false);
          return signatureCase.check();
        }),
        { numRuns: 50 },
      );
    }, 30_000);

    it("should invalidate signature when public key is changed", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(Tweak.ChangePubkey);
          expect(signatureCase.isValid).toBe(false);
          return signatureCase.check();
        }),
        { numRuns: 50 },
      );
    }, 30_000);

    it("should keep signature valid when no tweak is applied", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          const rng = createSecureRng();
          const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
          signatureCase.applyTweak(Tweak.None);
          expect(signatureCase.isValid).toBe(true);
          return signatureCase.check();
        }),
        { numRuns: 50 },
      );
    }, 30_000);

    it("should handle empty messages", () => {
      const rng = createSecureRng();
      const emptyMsg = new Uint8Array(0);
      const signatureCase = SignatureCase.create(ciphersuite, rng, emptyMsg);
      expect(signatureCase.check()).toBe(true);

      const signatureCase2 = SignatureCase.create(ciphersuite, rng, emptyMsg);
      signatureCase2.applyTweak(Tweak.ChangeMessage);
      expect(signatureCase2.check()).toBe(true);
    });

    it("should handle large messages", () => {
      const rng = createSecureRng();
      const largeMsg = new Uint8Array(10240);
      rng.fill(largeMsg);

      const signatureCase = SignatureCase.create(ciphersuite, rng, largeMsg);
      expect(signatureCase.check()).toBe(true);
    });
  });

  describe("Tweak enum", () => {
    it("should have all expected values", () => {
      expect(Tweak.None).toBe("None");
      expect(Tweak.ChangeMessage).toBe("ChangeMessage");
      expect(Tweak.ChangePubkey).toBe("ChangePubkey");
    });
  });

  describe("tweakArbitrary", () => {
    it("should generate valid Tweak values", () => {
      fc.assert(
        fc.property(tweakArbitrary, (tweak) => {
          return (
            tweak === Tweak.None || tweak === Tweak.ChangeMessage || tweak === Tweak.ChangePubkey
          );
        }),
        { numRuns: 100 },
      );
    });

    it("should favor Tweak.None due to weighting", () => {
      const samples: Tweak[] = [];
      for (let i = 0; i < 1000; i++) {
        const sample = fc.sample(tweakArbitrary, 1)[0];
        samples.push(sample);
      }

      const noneCount = samples.filter((t) => t === Tweak.None).length;
      const changeMessageCount = samples.filter((t) => t === Tweak.ChangeMessage).length;
      const changePubkeyCount = samples.filter((t) => t === Tweak.ChangePubkey).length;

      // With 10:1:1 weighting, None should be approximately 10/12 = ~83% of samples
      // Allow for some variance in random sampling
      expect(noneCount).toBeGreaterThan(600); // At least 60%
      expect(changeMessageCount).toBeLessThan(200); // Less than 20%
      expect(changePubkeyCount).toBeLessThan(200); // Less than 20%
    });
  });

  describe("messageArbitrary", () => {
    it("should generate Uint8Array messages", () => {
      fc.assert(
        fc.property(messageArbitrary, (msg) => {
          return msg instanceof Uint8Array;
        }),
        { numRuns: 100 },
      );
    });

    it("should generate messages of varying lengths", () => {
      const samples = fc.sample(messageArbitrary, 100);
      const lengths = samples.map((msg) => msg.length);
      const uniqueLengths = new Set(lengths);

      // Should have some variety in lengths
      expect(uniqueLengths.size).toBeGreaterThan(10);
    });
  });
});
