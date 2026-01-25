/**
 * Randomizer for FROST rerandomized signatures.
 *
 * A randomizer is a random scalar which is used to randomize the key.
 * This module provides the Randomizer class with methods for creating,
 * serializing, and managing randomizers.
 *
 * @module randomizer
 */

import type { Ciphersuite, Identifier, Scalar } from "@frost/core";
import {
  FrostError,
  SerializableScalar,
  type SigningCommitments,
  encodeGroupCommitments,
  bytesToHex,
} from "@frost/core";
import type { RandomizedCiphersuite } from "./types.js";

/**
 * A randomizer. A random scalar which is used to randomize the key.
 *
 * @typeParam C - The ciphersuite type
 */
export class Randomizer<C extends Ciphersuite> {
  /** The underlying serializable scalar */
  private readonly scalar: SerializableScalar<C>;

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create a new Randomizer from a SerializableScalar.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param scalar - The serializable scalar value
   * @internal
   */
  private constructor(ciphersuite: C, scalar: SerializableScalar<C>) {
    this.ciphersuite = ciphersuite;
    this.scalar = scalar;
  }

  /**
   * Convert the randomizer to its underlying scalar value.
   *
   * @returns The scalar value
   * @internal
   */
  toScalar(): Scalar<C> {
    return this.scalar.value;
  }

  /**
   * Create a new Randomizer from the given scalar.
   *
   * The scalar MUST be randomly generated. It is not recommended to use this
   * method unless for compatibility reasons with specifications on how the
   * randomizer must be generated. Use `newFromCommitments()` instead.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param scalar - The scalar value (must be randomly generated)
   * @returns A new Randomizer
   */
  static fromScalar<C extends Ciphersuite>(ciphersuite: C, scalar: Scalar<C>): Randomizer<C> {
    return new Randomizer(ciphersuite, new SerializableScalar(ciphersuite, scalar));
  }

  /**
   * Create a new random Randomizer using SigningCommitments for randomness.
   *
   * The SigningCommitments map must be the one being used in the current
   * FROST signing run (built by the Coordinator after receiving from
   * Participants). It is hashed into the randomizer calculation, which binds
   * it to that specific commitments.
   *
   * Returns the Randomizer and the generated randomizer seed. Both can be
   * used to regenerate the Randomizer with `regenerateFromSeedAndCommitments()`.
   *
   * @param ciphersuite - The ciphersuite to use (must support rerandomization)
   * @param rng - A cryptographically secure random number generator
   * @param signingCommitments - Map of identifier to signing commitments
   * @returns A tuple of [Randomizer, randomizer seed bytes]
   * @throws {FrostError} If randomizer generation fails
   */
  static newFromCommitments<C extends RandomizedCiphersuite>(
    ciphersuite: C,
    rng: { fill(array: Uint8Array): void },
    signingCommitments: Map<Identifier<C>, SigningCommitments<C>>,
  ): [Randomizer<C>, Uint8Array] {
    // Generate a dummy scalar to get its encoded size
    const zero = ciphersuite.scalarZero();
    const ns = ciphersuite.serializeScalar(zero).length;

    // Generate random seed
    const randomizerSeed = new Uint8Array(ns);
    rng.fill(randomizerSeed);

    // Regenerate the randomizer from the seed
    const randomizer = Randomizer.regenerateFromSeedAndCommitments(
      ciphersuite,
      randomizerSeed,
      signingCommitments,
    );

    return [randomizer, randomizerSeed];
  }

  /**
   * Regenerates a Randomizer generated with `newFromCommitments()`.
   *
   * This can be used by Participants after receiving the randomizer seed
   * and commitments in Round 2. This is better than the Coordinator simply
   * generating a Randomizer and sending it to Participants, because in this
   * approach the participants don't need to fully trust the Coordinator's
   * random number generator (i.e. even if the randomizer seed was not
   * randomly generated the randomizer will still be).
   *
   * This should be used exclusively with the output of `newFromCommitments()`;
   * it is strongly suggested to not attempt generating the randomizer seed
   * yourself (even if the point of this approach is to hedge against issues
   * in the randomizer seed generation).
   *
   * @param ciphersuite - The ciphersuite to use (must support rerandomization)
   * @param randomizerSeed - The randomizer seed bytes from `newFromCommitments()`
   * @param signingCommitments - Map of identifier to signing commitments
   * @returns The regenerated Randomizer
   * @throws {FrostError} If regeneration fails
   */
  static regenerateFromSeedAndCommitments<C extends RandomizedCiphersuite>(
    ciphersuite: C,
    randomizerSeed: Uint8Array,
    signingCommitments: Map<Identifier<C>, SigningCommitments<C>>,
  ): Randomizer<C> {
    // Encode the group commitments
    const encodedCommitments = encodeGroupCommitments(ciphersuite, signingCommitments);

    // Concatenate seed and encoded commitments
    const input = new Uint8Array(randomizerSeed.length + encodedCommitments.length);
    input.set(randomizerSeed, 0);
    input.set(encodedCommitments, randomizerSeed.length);

    // Hash into randomizer
    const randomizer = ciphersuite.hashRandomizer(input);
    if (randomizer === null) {
      throw FrostError.serializationError();
    }

    return new Randomizer(ciphersuite, new SerializableScalar(ciphersuite, randomizer));
  }

  /**
   * Serialize the randomizer using the ciphersuite encoding.
   *
   * @returns The serialized randomizer bytes
   */
  serialize(): Uint8Array {
    return this.scalar.serialize();
  }

  /**
   * Deserialize a Randomizer from a serialized buffer.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param buf - The bytes to deserialize
   * @returns The deserialized Randomizer
   * @throws {FrostError} If deserialization fails or attempts to deserialize zero
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, buf: Uint8Array): Randomizer<C> {
    const scalar = SerializableScalar.deserialize(ciphersuite, buf);
    return new Randomizer(ciphersuite, scalar);
  }

  /**
   * Returns a string representation of this Randomizer.
   *
   * @returns Debug string with hex-encoded value
   */
  toString(): string {
    return `Randomizer(${bytesToHex(this.scalar.serialize())})`;
  }

  /**
   * Check equality with another Randomizer.
   *
   * @param other - The other Randomizer to compare
   * @returns True if the randomizers are equal
   */
  equals(other: Randomizer<C>): boolean {
    return this.scalar.equals(other.scalar);
  }

  /**
   * Clone this Randomizer.
   *
   * @returns A new Randomizer with the same value
   */
  clone(): Randomizer<C> {
    return new Randomizer(this.ciphersuite, this.scalar.clone());
  }
}
