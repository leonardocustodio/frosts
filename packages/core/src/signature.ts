/**
 * Schnorr signatures over prime order groups (or subgroups)
 * @module
 */

import type { Ciphersuite, Element, Scalar } from "./types";
import { FrostError } from "./error";

/**
 * A Schnorr signature over some prime order group (or subgroup).
 */
export class Signature<C extends Ciphersuite> {
  /**
   * The commitment `R` to the signature nonce.
   * @internal
   */
  readonly R: Element<C>;

  /**
   * The response `z` to the challenge computed from the commitment `R`,
   * the verifying key, and the message.
   * @internal
   */
  readonly z: Scalar<C>;

  /**
   * Create a new Signature.
   * @param R - The commitment to the signature nonce
   * @param z - The response to the challenge
   */
  constructor(R: Element<C>, z: Scalar<C>) {
    this.R = R;
    this.z = z;
  }

  /**
   * Get the commitment `R` to the signature nonce.
   * @returns The R component of the signature
   */
  getR(): Element<C> {
    return this.R;
  }

  /**
   * Get the response `z` to the challenge.
   * @returns The z component of the signature
   */
  getZ(): Scalar<C> {
    return this.z;
  }

  /**
   * Converts default-encoded bytes into a Signature.
   *
   * The default encoding is the serialized R point followed by the serialized z scalar.
   * @internal
   * @param ciphersuite - The ciphersuite to use for deserialization
   * @param bytes - The serialized signature bytes
   * @returns The deserialized Signature
   * @throws {FrostError} If the signature encoding is malformed
   */
  static defaultDeserialize<C extends Ciphersuite>(
    ciphersuite: C,
    bytes: Uint8Array,
  ): Signature<C> {
    const group = ciphersuite.group;
    const field = group.field;

    // To compute the expected length of the encoded point, encode the generator
    // and get its length. Note that we can't use the identity because it can be encoded
    // shorter in some cases (e.g. P-256, which uses SEC1 encoding).
    const generator = group.generator();
    const rSerialization = group.serialize(generator);
    const rBytesLen = rSerialization.length;

    const zero = field.zero();
    const zSerialization = field.serialize(zero);
    const zBytesLen = zSerialization.length;

    if (bytes.length !== rBytesLen + zBytesLen) {
      throw FrostError.malformedSignature();
    }

    const rBytes = bytes.slice(0, rBytesLen);
    const zBytes = bytes.slice(rBytesLen, rBytesLen + zBytesLen);

    const R = group.deserialize(rBytes) as Element<C>;
    const z = field.deserialize(zBytes) as Scalar<C>;

    return new Signature(R, z);
  }

  /**
   * Converts bytes into a Signature using the ciphersuite's deserialization method.
   * @param ciphersuite - The ciphersuite to use for deserialization
   * @param bytes - The serialized signature bytes
   * @returns The deserialized Signature
   * @throws {FrostError} If the signature encoding is malformed
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): Signature<C> {
    // Check if the ciphersuite provides a custom deserialization method
    const ext = ciphersuite as Ciphersuite;
    if (ext.deserializeSignature !== undefined) {
      return ext.deserializeSignature(bytes) as Signature<C>;
    }
    // Fall back to default deserialization
    return Signature.defaultDeserialize(ciphersuite, bytes);
  }

  /**
   * Converts this signature to its default byte serialization.
   *
   * The default encoding is the serialized R point followed by the serialized z scalar.
   * @internal
   * @param ciphersuite - The ciphersuite to use for serialization
   * @returns The serialized signature as bytes
   * @throws {FrostError} If serialization fails (e.g., R is the identity)
   */
  defaultSerialize(ciphersuite: C): Uint8Array {
    const group = ciphersuite.group;
    const field = group.field;

    const rBytes = group.serialize(this.R);
    const zBytes = field.serialize(this.z);

    const bytes = new Uint8Array(rBytes.length + zBytes.length);
    bytes.set(rBytes, 0);
    bytes.set(zBytes, rBytes.length);

    return bytes;
  }

  /**
   * Converts this signature to its byte serialization using the ciphersuite's method.
   * @param ciphersuite - The ciphersuite to use for serialization
   * @returns The serialized signature as bytes
   * @throws {FrostError} If serialization fails
   */
  serialize(ciphersuite: C): Uint8Array {
    // Check if the ciphersuite provides a custom serialization method
    const ext = ciphersuite as Ciphersuite;
    if (ext.serializeSignature !== undefined) {
      return ext.serializeSignature(this);
    }
    // Fall back to default serialization
    return this.defaultSerialize(ciphersuite);
  }

  /**
   * Check equality with another Signature.
   * @param ciphersuite - The ciphersuite to use for comparison
   * @param other - The other Signature to compare with
   * @returns True if the signatures are equal
   */
  equals(ciphersuite: C, other: Signature<C>): boolean {
    const group = ciphersuite.group;
    const field = group.field;
    return group.eq(this.R, other.R) && field.eq(this.z, other.z);
  }

  /**
   * Clone this Signature.
   * @returns A new Signature with the same R and z values
   */
  clone(): Signature<C> {
    return new Signature(this.R, this.z);
  }

  /**
   * Convert to a debug string representation.
   * @param ciphersuite - The ciphersuite to use for serialization
   * @returns A debug string showing R and z as hex
   */
  toString(ciphersuite: C): string {
    const group = ciphersuite.group;
    const field = group.field;

    let rHex: string;
    try {
      const rBytes = group.serialize(this.R);
      rHex = Array.from(rBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch {
      rHex = "<invalid>";
    }

    const zBytes = field.serialize(this.z);
    const zHex = Array.from(zBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    return `Signature { R: ${rHex}, z: ${zHex} }`;
  }
}
