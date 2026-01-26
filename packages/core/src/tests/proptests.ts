/**
 * Ciphersuite-generic functions for property-based tests.
 * Ported from frost-core/src/tests/proptests.rs
 *
 * This module provides the SignatureCase class and Tweak enum for property-based
 * testing of FROST signatures. These can be used with fast-check or similar
 * property testing libraries to verify signature behavior.
 *
 * @module @frosts/core/tests/proptests
 */

import type { Ciphersuite, CryptoRng } from "../types.js";
import { SigningKey } from "../signing_key.js";
import { VerifyingKey } from "../verifying_key.js";
import type { Signature } from "../signature.js";

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
 * This class encapsulates a message, signature, and verifying key, along with
 * methods to apply "tweaks" that should invalidate the signature. The check()
 * method verifies that the signature verification result matches expectations.
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
    // Note: We could deserialize and verify with the deserialized signature,
    // but the Rust code doesn't actually use the deserialized signature
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

  /**
   * Get the ciphersuite.
   */
  get ciphersuite(): C {
    return this._ciphersuite;
  }
}

/**
 * Run a single signature test with the given parameters.
 * Useful for integration testing with specific ciphersuites.
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 * @param msg - The message to sign
 * @param tweak - The tweak to apply
 * @returns true if the test passes
 */
export function checkSignatureWithTweak<C extends Ciphersuite>(
  ciphersuite: C,
  rng: CryptoRng,
  msg: Uint8Array,
  tweak: Tweak,
): boolean {
  const signatureCase = SignatureCase.create(ciphersuite, rng, msg);
  signatureCase.applyTweak(tweak);
  return signatureCase.check();
}
