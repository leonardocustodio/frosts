/**
 * RandomizedParams for FROST rerandomized signatures.
 *
 * This module provides the RandomizedParams class which holds all the
 * parameters needed for a rerandomized FROST signing operation.
 *
 * @module params
 */

import type { Ciphersuite, Element, Identifier } from "@frost/core";
import { VerifyingKey, type SigningCommitments, bytesToHex } from "@frost/core";
import type { RandomizedCiphersuite } from "./types.js";
import { Randomizer } from "./randomizer.js";

/**
 * Randomized parameters for a signing instance of randomized FROST.
 *
 * @typeParam C - The ciphersuite type
 */
export class RandomizedParams<C extends Ciphersuite> {
  /** The randomizer, also called alpha */
  private readonly _randomizer: Randomizer<C>;

  /** The generator multiplied by the randomizer */
  private readonly _randomizerElement: Element<C>;

  /** The randomized group public key. The group public key added to the randomizer element. */
  private readonly _randomizedVerifyingKey: VerifyingKey<C>;

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create new RandomizedParams.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param randomizer - The randomizer
   * @param randomizerElement - The generator multiplied by the randomizer
   * @param randomizedVerifyingKey - The randomized verifying key
   * @internal
   */
  private constructor(
    ciphersuite: C,
    randomizer: Randomizer<C>,
    randomizerElement: Element<C>,
    randomizedVerifyingKey: VerifyingKey<C>,
  ) {
    this.ciphersuite = ciphersuite;
    this._randomizer = randomizer;
    this._randomizerElement = randomizerElement;
    this._randomizedVerifyingKey = randomizedVerifyingKey;
  }

  /**
   * Get the randomizer.
   *
   * @returns The randomizer
   */
  get randomizer(): Randomizer<C> {
    return this._randomizer;
  }

  /**
   * Get the randomizer element (generator * randomizer).
   *
   * @returns The randomizer element
   */
  get randomizerElement(): Element<C> {
    return this._randomizerElement;
  }

  /**
   * Get the randomized verifying key.
   *
   * @returns The randomized verifying key
   */
  get randomizedVerifyingKey(): VerifyingKey<C> {
    return this._randomizedVerifyingKey;
  }

  /**
   * Create a new RandomizedParams for the given VerifyingKey and the given
   * signing commitments.
   *
   * The SigningCommitments map must be the one being used in the current
   * FROST signing run (built by the Coordinator after receiving from
   * Participants). It is hashed into the randomizer calculation, which binds
   * it to that specific commitments.
   *
   * Returns the generated RandomizedParams and a randomizer seed. Both can
   * be used to regenerate the RandomizedParams with
   * `regenerateFromSeedAndCommitments()`.
   *
   * @param ciphersuite - The ciphersuite to use (must support rerandomization)
   * @param groupVerifyingKey - The group's verifying key
   * @param signingCommitments - Map of identifier to signing commitments
   * @param rng - A cryptographically secure random number generator
   * @returns A tuple of [RandomizedParams, randomizer seed bytes]
   * @throws {FrostError} If parameter generation fails
   */
  static newFromCommitments<C extends RandomizedCiphersuite>(
    ciphersuite: C,
    groupVerifyingKey: VerifyingKey<C>,
    signingCommitments: Map<Identifier<C>, SigningCommitments<C>>,
    rng: { fill(array: Uint8Array): void },
  ): [RandomizedParams<C>, Uint8Array] {
    const [randomizer, randomizerSeed] = Randomizer.newFromCommitments(
      ciphersuite,
      rng,
      signingCommitments,
    );
    return [
      RandomizedParams.fromRandomizer(ciphersuite, groupVerifyingKey, randomizer),
      randomizerSeed,
    ];
  }

  /**
   * Regenerate a RandomizedParams with the given VerifyingKey from the given
   * signing commitments.
   *
   * Regenerates a RandomizedParams generated with `newFromCommitments()`.
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
   * @param groupVerifyingKey - The group's verifying key
   * @param randomizerSeed - The randomizer seed bytes from `newFromCommitments()`
   * @param signingCommitments - Map of identifier to signing commitments
   * @returns The regenerated RandomizedParams
   * @throws {FrostError} If regeneration fails
   */
  static regenerateFromSeedAndCommitments<C extends RandomizedCiphersuite>(
    ciphersuite: C,
    groupVerifyingKey: VerifyingKey<C>,
    randomizerSeed: Uint8Array,
    signingCommitments: Map<Identifier<C>, SigningCommitments<C>>,
  ): RandomizedParams<C> {
    const randomizer = Randomizer.regenerateFromSeedAndCommitments(
      ciphersuite,
      randomizerSeed,
      signingCommitments,
    );
    return RandomizedParams.fromRandomizer(ciphersuite, groupVerifyingKey, randomizer);
  }

  /**
   * Create a new RandomizedParams for the given VerifyingKey and the given
   * randomizer.
   *
   * The randomizer MUST be generated uniformly at random! Use
   * `newFromCommitments()` which generates a fresh randomizer, unless your
   * application requires generating a randomizer outside.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param groupVerifyingKey - The group's verifying key
   * @param randomizer - The randomizer (must be uniformly random)
   * @returns The new RandomizedParams
   */
  static fromRandomizer<C extends Ciphersuite>(
    ciphersuite: C,
    groupVerifyingKey: VerifyingKey<C>,
    randomizer: Randomizer<C>,
  ): RandomizedParams<C> {
    // randomizerElement = generator * randomizer
    const randomizerElement = ciphersuite.scalarBaseMult(randomizer.toScalar());

    // randomizedVerifyingKey = verifyingKey + randomizerElement
    const verifyingKeyElement = groupVerifyingKey.toElement();
    const randomizedVerifyingKeyElement = ciphersuite.elementAdd(
      verifyingKeyElement,
      randomizerElement,
    );
    const randomizedVerifyingKey = VerifyingKey.create(ciphersuite, randomizedVerifyingKeyElement);

    return new RandomizedParams(ciphersuite, randomizer, randomizerElement, randomizedVerifyingKey);
  }

  /**
   * Returns a string representation of this RandomizedParams.
   *
   * @returns Debug string with all fields
   */
  toString(): string {
    let randomizerElementHex: string;
    try {
      const bytes = this.ciphersuite.serializeElement(this._randomizerElement);
      randomizerElementHex = bytesToHex(bytes);
    } catch {
      randomizerElementHex = "<invalid>";
    }

    return `RandomizedParams { randomizer: ${this._randomizer.toString()}, randomizerElement: ${randomizerElementHex}, randomizedVerifyingKey: ${this._randomizedVerifyingKey.toString()} }`;
  }

  /**
   * Check equality with another RandomizedParams.
   *
   * @param other - The other RandomizedParams to compare
   * @returns True if the params are equal
   */
  equals(other: RandomizedParams<C>): boolean {
    return (
      this._randomizer.equals(other._randomizer) &&
      this.ciphersuite.elementsEqual(this._randomizerElement, other._randomizerElement) &&
      this._randomizedVerifyingKey.equals(other._randomizedVerifyingKey)
    );
  }

  /**
   * Clone this RandomizedParams.
   *
   * @returns A new RandomizedParams with the same values
   */
  clone(): RandomizedParams<C> {
    return new RandomizedParams(
      this.ciphersuite,
      this._randomizer.clone(),
      this._randomizerElement,
      this._randomizedVerifyingKey.clone(),
    );
  }
}
