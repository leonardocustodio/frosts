/**
 * Schnorr signature signing keys
 * @module
 */

import type { Ciphersuite, CryptoRng, Scalar, Element } from "./types";
import { Signature } from "./signature";
import { FrostError } from "./error";

/**
 * A signing key for a Schnorr signature on a FROST Ciphersuite Group.
 *
 * This class wraps a scalar value that serves as the private key for signing operations.
 * The scalar must be non-zero and within the valid range for the ciphersuite's field.
 *
 * @typeParam C - The ciphersuite type that defines the cryptographic parameters
 */
export class SigningKey<C extends Ciphersuite> {
  /**
   * The underlying scalar value (private key material).
   * This is kept private to the module for security.
   */
  private _scalar: Scalar<C>;

  /**
   * Reference to the ciphersuite for cryptographic operations.
   */
  private readonly _ciphersuite: C;

  /**
   * Creates a new SigningKey from a scalar value.
   *
   * @param ciphersuite - The ciphersuite to use for cryptographic operations
   * @param scalar - The scalar value to use as the signing key
   * @throws {FrostError} If the scalar is zero
   */
  private constructor(ciphersuite: C, scalar: Scalar<C>) {
    this._ciphersuite = ciphersuite;
    this._scalar = scalar;
  }

  /**
   * Generate a new signing key using random bytes from the provided RNG.
   *
   * @param ciphersuite - The ciphersuite to use for key generation
   * @param rng - A cryptographically secure random number generator
   * @returns A new SigningKey with a random non-zero scalar
   */
  static generate<C extends Ciphersuite>(ciphersuite: C, rng: CryptoRng): SigningKey<C> {
    const scalar = randomNonzero(ciphersuite, rng);
    return new SigningKey(ciphersuite, scalar);
  }

  /**
   * Creates a SigningKey from a scalar value.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param scalar - The scalar value to use as the signing key
   * @returns A new SigningKey wrapping the scalar
   * @throws {FrostError} If the scalar is zero (MalformedSigningKey)
   */
  static fromScalar<C extends Ciphersuite>(ciphersuite: C, scalar: Scalar<C>): SigningKey<C> {
    const field = ciphersuite.group.field;
    if (field.isZero(scalar)) {
      throw FrostError.malformedSigningKey();
    }
    return new SigningKey(ciphersuite, scalar);
  }

  /**
   * Deserialize a SigningKey from bytes.
   *
   * @param ciphersuite - The ciphersuite to use for deserialization
   * @param bytes - The serialized signing key bytes
   * @returns The deserialized SigningKey
   * @throws {FrostError} If deserialization fails or the scalar is zero
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): SigningKey<C> {
    const field = ciphersuite.group.field;
    const scalar = field.deserialize(bytes) as Scalar<C>;
    return SigningKey.fromScalar(ciphersuite, scalar);
  }

  /**
   * Serialize the SigningKey to bytes.
   *
   * @returns The serialized signing key as a byte array
   */
  serialize(): Uint8Array {
    const field = this._ciphersuite.group.field;
    return field.serialize(this._scalar);
  }

  /**
   * Create a signature for a message using this SigningKey.
   *
   * Uses the ciphersuite's singleSign method if available (for Ciphersuite),
   * otherwise falls back to the default signing implementation.
   *
   * @param rng - A cryptographically secure random number generator
   * @param message - The message to sign
   * @returns The signature over the message
   */
  sign(rng: CryptoRng, message: Uint8Array): Signature<C> {
    const cs = this._ciphersuite as Ciphersuite;
    if (cs.singleSign !== undefined) {
      return cs.singleSign(this, message, rng) as Signature<C>;
    }
    return this.defaultSign(rng, message);
  }

  /**
   * Default signing implementation for standard Schnorr signatures.
   *
   * This implements the standard Schnorr signing algorithm:
   * 1. Generate random nonce k and commitment R = k * G
   * 2. Compute challenge c = H2(R || public_key || message)
   * 3. Compute response z = k + c * private_key
   *
   * @param rng - A cryptographically secure random number generator
   * @param message - The message to sign
   * @returns The signature (R, z)
   * @internal
   */
  defaultSign(rng: CryptoRng, message: Uint8Array): Signature<C> {
    const group = this._ciphersuite.group;
    const field = group.field;

    // Compute public key: verifying_key = G * scalar
    const generator = group.generator();
    const publicElement = group.scalarMul(generator, this._scalar) as Element<C>;
    // Note: publicElement is computed for use in the challenge hash preimage below

    // Generate nonce k (random non-zero scalar) and commitment R = k * G
    const k = randomNonzero(this._ciphersuite, rng);
    const R = group.scalarMul(generator, k) as Element<C>;

    // Generate Schnorr challenge c = H2(R || public_key || message)
    // Build the preimage for the challenge hash
    const rBytes = group.serialize(R);
    const pkBytes = group.serialize(publicElement);

    const preimage = new Uint8Array(rBytes.length + pkBytes.length + message.length);
    preimage.set(rBytes, 0);
    preimage.set(pkBytes, rBytes.length);
    preimage.set(message, rBytes.length + pkBytes.length);

    const c = this._ciphersuite.H2(preimage);

    // Compute z = k + c * scalar
    const cTimesScalar = field.mul(c, this._scalar);
    const z = field.add(k, cTimesScalar);

    return new Signature(R, z);
  }

  /**
   * Return the underlying scalar value.
   *
   * WARNING: This exposes the private key material. Use with caution.
   *
   * @returns The scalar value of this signing key
   */
  toScalar(): Scalar<C> {
    return this._scalar;
  }

  /**
   * Get the ciphersuite associated with this signing key.
   *
   * @returns The ciphersuite
   */
  ciphersuite(): C {
    return this._ciphersuite;
  }

  /**
   * Zeroize the scalar to clear sensitive key material from memory.
   *
   * After calling this method, the signing key should not be used.
   * This provides defense-in-depth for sensitive cryptographic material.
   */
  zeroize(): void {
    const field = this._ciphersuite.group.field;
    this._scalar = field.zero() as Scalar<C>;
  }

  /**
   * Check equality with another SigningKey.
   *
   * @param other - The other signing key to compare
   * @returns true if the signing keys are equal
   */
  equals(other: SigningKey<C>): boolean {
    const field = this._ciphersuite.group.field;
    return field.eq(this._scalar, other._scalar);
  }

  /**
   * Create a copy of this signing key.
   *
   * @returns A new SigningKey with the same scalar value
   */
  clone(): SigningKey<C> {
    return new SigningKey(this._ciphersuite, this._scalar);
  }

  /**
   * Returns a debug string representation.
   * The actual key material is redacted for security.
   *
   * @returns A debug string with redacted content
   */
  toString(): string {
    return "SigningKey(<redacted>)";
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
 * Generates a random nonzero scalar.
 *
 * This function repeatedly generates random scalars until a non-zero value is found.
 * It assumes that the scalar Eq/PartialEq implementation is constant-time.
 *
 * @param ciphersuite - The ciphersuite defining the field
 * @param rng - A cryptographically secure random number generator
 * @returns A random non-zero scalar
 * @internal
 */
export function randomNonzero<C extends Ciphersuite>(ciphersuite: C, rng: CryptoRng): Scalar<C> {
  const field = ciphersuite.group.field;
  while (true) {
    const scalar = field.random(rng) as Scalar<C>;
    if (!field.isZero(scalar)) {
      return scalar;
    }
  }
}
