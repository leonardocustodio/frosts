/**
 * Schnorr signature verifying keys
 * @module
 */

import type { Ciphersuite, Element, Scalar } from "./types";
import type { Signature } from "./signature";
import type { SigningKey } from "./signing_key";
import { FrostError } from "./error";

/**
 * A challenge scalar for Schnorr signature verification.
 * This is the per-message challenge value computed as H2(R || public_key || message).
 * @internal Forward declaration to avoid circular dependency - see types.ts for the actual class.
 */
interface ChallengeLike<C extends Ciphersuite> {
  /** Get the underlying scalar value */
  toScalar(): Scalar<C>;
}

/**
 * A verifiable secret sharing commitment, used for deriving verifying keys.
 * @internal Forward declaration to avoid circular dependency - see keys.ts for the actual class.
 */
interface VerifiableSecretSharingCommitmentLike<C extends Ciphersuite> {
  /** Get the commitment coefficients */
  coefficients(): { value(): Element<C> }[];
}

/**
 * A valid verifying key for Schnorr signatures over a FROST Ciphersuite Group.
 *
 * This class wraps a group element that serves as the public key for signature verification.
 * The element must not be the identity element of the group.
 *
 * @typeParam C - The ciphersuite type that defines the cryptographic parameters
 */
export class VerifyingKey<C extends Ciphersuite> {
  /**
   * The underlying group element (public key).
   */
  private readonly _element: Element<C>;

  /**
   * Reference to the ciphersuite for cryptographic operations.
   */
  private readonly _ciphersuite: C;

  /**
   * Creates a new VerifyingKey from a group element.
   *
   * @param ciphersuite - The ciphersuite to use for cryptographic operations
   * @param element - The group element to use as the verifying key
   * @internal
   */
  private constructor(ciphersuite: C, element: Element<C>) {
    this._ciphersuite = ciphersuite;
    this._element = element;
  }

  /**
   * Create a new VerifyingKey from the given element.
   *
   * This is an internal constructor that does not validate the element.
   * Use deserialize() for safe construction from untrusted input.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param element - The group element
   * @returns A new VerifyingKey
   * @internal
   */
  static create<C extends Ciphersuite>(ciphersuite: C, element: Element<C>): VerifyingKey<C> {
    return new VerifyingKey(ciphersuite, element);
  }

  /**
   * Create a VerifyingKey from a SigningKey.
   *
   * Computes the public key as: verifying_key = generator * signing_key
   *
   * @param ciphersuite - The ciphersuite to use
   * @param signingKey - The signing key to derive the verifying key from
   * @returns The corresponding verifying key
   */
  static fromSigningKey<C extends Ciphersuite>(
    ciphersuite: C,
    signingKey: SigningKey<C>,
  ): VerifyingKey<C> {
    const group = ciphersuite.group;
    const generator = group.generator();
    const scalar = signingKey.toScalar();
    const element = group.scalarMul(generator, scalar) as Element<C>;
    return new VerifyingKey(ciphersuite, element);
  }

  /**
   * Computes the group public key given the group commitment.
   *
   * The verifying key is the first coefficient (constant term) of the
   * verifiable secret sharing commitment polynomial.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param commitment - The verifiable secret sharing commitment
   * @returns The verifying key derived from the commitment
   * @throws {FrostError} If the commitment is empty (IncorrectCommitment)
   * @internal
   */
  static fromCommitment<C extends Ciphersuite>(
    ciphersuite: C,
    commitment: VerifiableSecretSharingCommitmentLike<C>,
  ): VerifyingKey<C> {
    const coefficients = commitment.coefficients();
    if (coefficients.length === 0) {
      throw FrostError.incorrectCommitment();
    }
    const firstCoeff = coefficients[0];
    return new VerifyingKey(ciphersuite, firstCoeff.value());
  }

  /**
   * Deserialize a VerifyingKey from bytes.
   *
   * @param ciphersuite - The ciphersuite to use for deserialization
   * @param bytes - The serialized verifying key bytes
   * @returns The deserialized VerifyingKey
   * @throws {FrostError} If deserialization fails or the element is invalid
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): VerifyingKey<C> {
    const group = ciphersuite.group;
    const element = group.deserialize(bytes) as Element<C>;
    return new VerifyingKey(ciphersuite, element);
  }

  /**
   * Deserialize a VerifyingKey from a hex string.
   *
   * @param ciphersuite - The ciphersuite to use for deserialization
   * @param hex - The hex-encoded verifying key
   * @returns The deserialized VerifyingKey
   * @throws {FrostError} If the hex is invalid or deserialization fails
   */
  static fromHex<C extends Ciphersuite>(ciphersuite: C, hex: string): VerifyingKey<C> {
    const bytes = hexToBytes(hex);
    return VerifyingKey.deserialize(ciphersuite, bytes);
  }

  /**
   * Serialize the VerifyingKey to bytes.
   *
   * @returns The serialized verifying key as a byte array
   * @throws {FrostError} If the element is the identity (should not happen for valid keys)
   */
  serialize(): Uint8Array {
    const group = this._ciphersuite.group;
    return group.serialize(this._element);
  }

  /**
   * Serialize the VerifyingKey to a hex string.
   *
   * @returns The hex-encoded verifying key
   */
  toHex(): string {
    const bytes = this.serialize();
    return bytesToHex(bytes);
  }

  /**
   * Verify a signature with a pre-hashed challenge.
   *
   * This verifies the equation:
   *   h * (z * G - c * A - R) == 0
   *
   * where:
   * - h is the cofactor
   * - z is the signature response
   * - G is the generator
   * - c is the challenge
   * - A is the verifying key (this element)
   * - R is the signature commitment
   *
   * @param challenge - The pre-computed challenge
   * @param signature - The signature to verify
   * @throws {FrostError} If the signature is invalid (InvalidSignature)
   * @internal
   */
  verifyPrehashed(challenge: ChallengeLike<C>, signature: Signature<C>): void {
    const group = this._ciphersuite.group;

    // zB = z * G (generator)
    const generator = group.generator();
    const zB = group.scalarMul(generator, signature.z);

    // cA = c * A (verifying key element)
    const cA = group.scalarMul(this._element, challenge.toScalar());

    // check = (zB - cA - R) * cofactor
    const zBMinusCA = group.sub(zB, cA);
    const zBMinusCAMinusR = group.sub(zBMinusCA, signature.R);
    const cofactor = group.cofactor();
    const check = group.scalarMul(zBMinusCAMinusR, cofactor);

    // Verify check == identity
    const identity = group.identity();
    if (!group.eq(check, identity)) {
      throw FrostError.invalidSignature();
    }
  }

  /**
   * Verify a purported signature over a message made by this verification key.
   *
   * Uses the ciphersuite's verifySignature method if available (for Ciphersuite),
   * otherwise falls back to the default verification implementation.
   *
   * @param message - The message that was signed
   * @param signature - The signature to verify
   * @throws {FrostError} If the signature is invalid
   */
  verify(message: Uint8Array, signature: Signature<C>): void {
    const cs = this._ciphersuite as Ciphersuite;
    if (cs.verifySignature !== undefined) {
      // Interface expects (verifyingKey, message, signature)
      cs.verifySignature(this, message, signature);
      return;
    }
    this.defaultVerify(message, signature);
  }

  /**
   * Default signature verification implementation.
   *
   * Computes the challenge and delegates to verifyPrehashed.
   *
   * @param message - The message that was signed
   * @param signature - The signature to verify
   * @throws {FrostError} If the signature is invalid
   * @internal
   */
  defaultVerify(message: Uint8Array, signature: Signature<C>): void {
    const group = this._ciphersuite.group;

    // Build the preimage for the challenge hash: R || public_key || message
    const rBytes = group.serialize(signature.R);
    const pkBytes = group.serialize(this._element);

    const preimage = new Uint8Array(rBytes.length + pkBytes.length + message.length);
    preimage.set(rBytes, 0);
    preimage.set(pkBytes, rBytes.length);
    preimage.set(message, rBytes.length + pkBytes.length);

    // Compute challenge c = H2(R || public_key || message)
    const c = this._ciphersuite.H2(preimage) as Scalar<C>;

    // Create a challenge object
    const challenge: ChallengeLike<C> = {
      toScalar: () => c,
    };

    this.verifyPrehashed(challenge, signature);
  }

  /**
   * Return the underlying group element.
   *
   * @returns The group element of this verifying key
   */
  toElement(): Element<C> {
    return this._element;
  }

  /**
   * Get the ciphersuite associated with this verifying key.
   *
   * @returns The ciphersuite
   */
  ciphersuite(): C {
    return this._ciphersuite;
  }

  /**
   * Check equality with another VerifyingKey.
   *
   * @param other - The other verifying key to compare
   * @returns true if the verifying keys are equal
   */
  equals(other: VerifyingKey<C>): boolean {
    const group = this._ciphersuite.group;
    return group.eq(this._element, other._element);
  }

  /**
   * Create a copy of this verifying key.
   *
   * @returns A new VerifyingKey with the same element
   */
  clone(): VerifyingKey<C> {
    return new VerifyingKey(this._ciphersuite, this._element);
  }

  /**
   * Returns a debug string representation.
   *
   * @returns A debug string with the hex-encoded key
   */
  toString(): string {
    try {
      return `VerifyingKey(${this.toHex()})`;
    } catch {
      return "VerifyingKey(<invalid>)";
    }
  }

  /**
   * Custom inspect for Node.js console.
   * @returns Debug representation
   */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

/**
 * Convert a hex string to bytes.
 *
 * @param hex - The hex string to convert
 * @returns The byte array
 * @throws {Error} If the hex string is invalid
 * @internal
 */
function hexToBytes(hex: string): Uint8Array {
  // Remove 0x prefix if present
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;

  if (cleanHex.length % 2 !== 0) {
    throw new Error("Invalid hex string: odd length");
  }

  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`Invalid hex character at position ${i * 2}`);
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Convert bytes to a hex string.
 *
 * @param bytes - The byte array to convert
 * @returns The hex string (lowercase)
 * @internal
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
