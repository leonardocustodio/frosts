/**
 * FROST participant identifiers
 * @module
 */

import type { Ciphersuite, Scalar } from "./types";
import { FieldError, FrostError } from "./error";

/**
 * A FROST participant identifier.
 *
 * The identifier is a field element in the scalar field that the secret polynomial is defined
 * over, corresponding to some x-coordinate for a polynomial f(x) = y. MUST NOT be zero in the
 * field, as f(0) = the shared secret.
 */
export class Identifier<C extends Ciphersuite> {
  /** The underlying scalar value wrapped for serialization */
  private readonly scalar: Scalar<C>;

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create a new Identifier from a scalar.
   * @internal
   * @param ciphersuite - The ciphersuite to use
   * @param scalar - The scalar value (must not be zero)
   * @throws {FieldError} If the scalar is zero
   */
  private constructor(ciphersuite: C, scalar: Scalar<C>) {
    this.ciphersuite = ciphersuite;
    this.scalar = scalar;
  }

  /**
   * Create a new Identifier from a scalar. For internal use only.
   * @internal
   * @param ciphersuite - The ciphersuite to use
   * @param scalar - The scalar value
   * @returns The new Identifier
   * @throws {FieldError} If the scalar is zero
   */
  static create<C extends Ciphersuite>(ciphersuite: C, scalar: Scalar<C>): Identifier<C> {
    const field = ciphersuite.group.field;
    if (field.eq(scalar, field.zero())) {
      throw FieldError.invalidZeroScalar();
    }
    return new Identifier(ciphersuite, scalar);
  }

  /**
   * Get the inner scalar.
   * @internal
   * @returns The underlying scalar value
   */
  toScalar(): Scalar<C> {
    return this.scalar;
  }

  /**
   * Derive an Identifier from an arbitrary byte string.
   *
   * This feature is not part of the specification and is just a convenient
   * way of creating identifiers.
   *
   * Each possible byte string will map to a uniformly random identifier.
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - The byte string to derive from
   * @returns The derived Identifier
   * @throws {FrostError} If the ciphersuite does not support identifier derivation,
   *         or if the mapped identifier is zero (which is unpredictable, but should happen
   *         with negligible probability).
   */
  static derive<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): Identifier<C> {
    const scalar = ciphersuite.HID?.(bytes);
    if (scalar === null || scalar === undefined) {
      throw FrostError.identifierDerivationNotSupported();
    }
    return Identifier.create(ciphersuite, scalar);
  }

  /**
   * Serialize the identifier using the ciphersuite encoding.
   * @returns The serialized identifier as bytes
   */
  serialize(): Uint8Array {
    const field = this.ciphersuite.group.field;
    return field.serialize(this.scalar);
  }

  /**
   * Deserialize an Identifier from a serialized buffer.
   * @param ciphersuite - The ciphersuite to use for deserialization
   * @param bytes - The serialized bytes
   * @returns The deserialized Identifier
   * @throws {FieldError} If deserialization fails or the scalar is zero
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): Identifier<C> {
    const field = ciphersuite.group.field;
    const scalar = field.deserialize(bytes) as Scalar<C>;
    return Identifier.create(ciphersuite, scalar);
  }

  /**
   * Create an Identifier from a 16-bit unsigned integer.
   *
   * Uses the classic left-to-right double-and-add algorithm that skips the first bit 1
   * (since identifiers are never zero, there is always a bit 1), thus `sum` starts with 1 too.
   * @param ciphersuite - The ciphersuite to use
   * @param n - The unsigned 16-bit integer (must not be zero)
   * @returns The new Identifier
   * @throws {FieldError} If n is zero
   */
  static fromU16<C extends Ciphersuite>(ciphersuite: C, n: number): Identifier<C> {
    if (n === 0) {
      throw FieldError.invalidZeroScalar();
    }
    if (n < 0 || n > 0xffff || !Number.isInteger(n)) {
      throw FieldError.invalidZeroScalar(); // Using closest error for invalid input
    }

    const field = ciphersuite.group.field;
    const one = field.one();

    // Classic left-to-right double-and-add algorithm that skips the first bit 1
    // (since identifiers are never zero, there is always a bit 1), thus `sum` starts with 1 too.
    let sum = field.one();

    // Calculate the number of significant bits
    const bits = 16; // u16 has 16 bits
    const leadingZeros = Math.clz32(n) - 16; // clz32 counts for 32-bit, adjust for 16-bit
    const significantBits = bits - leadingZeros;

    // Iterate from the second most significant bit down to bit 0
    for (let i = significantBits - 2; i >= 0; i--) {
      sum = field.add(sum, sum); // double
      if ((n & (1 << i)) !== 0) {
        sum = field.add(sum, one); // add
      }
    }

    return Identifier.create(ciphersuite, sum);
  }

  /**
   * Check equality with another Identifier.
   * @param other - The other Identifier to compare with
   * @returns True if the identifiers are equal
   */
  equals(other: Identifier<C>): boolean {
    const field = this.ciphersuite.group.field;
    return field.eq(this.scalar, other.scalar);
  }

  /**
   * Compare this Identifier with another for ordering.
   *
   * The comparison is done by serializing both scalars in little-endian order
   * and comparing them lexicographically in big-endian (reversed).
   * @param other - The other Identifier to compare with
   * @returns -1 if this < other, 0 if equal, 1 if this > other
   */
  compare(other: Identifier<C>): -1 | 0 | 1 {
    const field = this.ciphersuite.group.field;
    const serializedSelf = field.littleEndianSerialize(this.scalar);
    const serializedOther = field.littleEndianSerialize(other.scalar);

    // The default comparison uses lexicographic order; so we need the elements in big endian
    // We iterate in reverse to achieve big-endian comparison
    const len = Math.min(serializedSelf.length, serializedOther.length);
    for (let i = len - 1; i >= 0; i--) {
      if (serializedSelf[i] < serializedOther[i]) {
        return -1;
      }
      if (serializedSelf[i] > serializedOther[i]) {
        return 1;
      }
    }

    // If all compared bytes are equal, compare by length
    if (serializedSelf.length < serializedOther.length) {
      return -1;
    }
    if (serializedSelf.length > serializedOther.length) {
      return 1;
    }

    return 0;
  }

  /**
   * Compute a hash code for the Identifier.
   * @returns A numeric hash code
   */
  hashCode(): number {
    const bytes = this.serialize();
    // Simple FNV-1a hash
    let hash = 2166136261;
    for (const byte of bytes) {
      hash ^= byte;
      hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
  }

  /**
   * Convert to a debug string representation.
   * @returns A debug string in the format "Identifier(hex)"
   */
  toString(): string {
    const bytes = this.serialize();
    const hex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return `Identifier(${hex})`;
  }

  /**
   * Clone this Identifier.
   * @returns A new Identifier with the same scalar value
   */
  clone(): Identifier<C> {
    // Scalars are typically immutable, so we can just create a new wrapper
    return new Identifier(this.ciphersuite, this.scalar);
  }
}
