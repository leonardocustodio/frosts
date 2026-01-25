/**
 * FROST Round 1 functionality and types
 *
 * This module implements the first round of the FROST signing protocol,
 * where participants generate nonces and commitments.
 *
 * @module round1
 */

import type { Ciphersuite } from "./ciphersuite";
import type { SigningShare } from "./keys";
import type { Identifier } from "./identifier";
import type { BindingFactor } from "./types";
import type { RandomSource } from "./random";

/**
 * A scalar that is a signing nonce.
 *
 * Nonces are secret values generated during Round 1 that must be kept private
 * and used exactly once for a signing operation.
 */
export class Nonce<C extends Ciphersuite> {
  /** The underlying scalar value */
  private scalar: C["Scalar"];

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create a Nonce from a scalar value.
   * @internal
   */
  private constructor(ciphersuite: C, scalar: C["Scalar"]) {
    this.ciphersuite = ciphersuite;
    this.scalar = scalar;
  }

  /**
   * Generates a new uniformly random signing nonce by sourcing fresh randomness and combining
   * with the secret signing share, to hedge against a bad RNG.
   *
   * Each participant generates signing nonces before performing a signing operation.
   *
   * An implementation of `nonce_generate(secret)` from the [spec].
   *
   * [spec]: https://datatracker.ietf.org/doc/html/rfc9591#name-nonce-generation
   *
   * @param ciphersuite - The ciphersuite to use
   * @param secret - The participant's signing share
   * @param rng - A cryptographically secure random number generator
   * @returns A new signing nonce
   */
  static generate<C extends Ciphersuite>(
    ciphersuite: C,
    secret: SigningShare<C>,
    rng: RandomSource,
  ): Nonce<C> {
    const randomBytes = new Uint8Array(32);
    rng.fill(randomBytes);

    return Nonce.nonceGenerateFromRandomBytes(ciphersuite, secret, randomBytes);
  }

  /**
   * Create a nonce from a scalar.
   * @internal
   */
  static fromScalar<C extends Ciphersuite>(ciphersuite: C, scalar: C["Scalar"]): Nonce<C> {
    return new Nonce(ciphersuite, scalar);
  }

  /**
   * Convert a nonce into a scalar.
   * @internal
   */
  toScalar(): C["Scalar"] {
    return this.scalar;
  }

  /**
   * Generates a nonce from the given random bytes.
   * This function allows testing and MUST NOT be made public.
   * @internal
   */
  static nonceGenerateFromRandomBytes<C extends Ciphersuite>(
    ciphersuite: C,
    secret: SigningShare<C>,
    randomBytes: Uint8Array,
  ): Nonce<C> {
    const secretEnc = secret.serialize();

    // Concatenate random_bytes and secret_enc
    const input = new Uint8Array(randomBytes.length + secretEnc.length);
    input.set(randomBytes, 0);
    input.set(secretEnc, randomBytes.length);

    const scalar = ciphersuite.H3(input);
    return new Nonce(ciphersuite, scalar);
  }

  /**
   * Deserialize a Nonce from bytes.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - The serialized nonce bytes
   * @returns The deserialized nonce
   * @throws Error if deserialization fails
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): Nonce<C> {
    const scalar = ciphersuite.deserializeScalar(bytes);
    return new Nonce(ciphersuite, scalar);
  }

  /**
   * Serialize the Nonce to bytes.
   *
   * @returns The serialized nonce bytes
   */
  serialize(): Uint8Array {
    return this.ciphersuite.serializeScalar(this.scalar);
  }

  /**
   * Zeroize the nonce by overwriting the scalar with zero.
   *
   * This should be called when the nonce is no longer needed to prevent
   * secret data from remaining in memory.
   */
  zeroize(): void {
    this.scalar = this.ciphersuite.scalarZero();
  }
}

/**
 * A group element that is a commitment to a signing nonce share.
 *
 * NonceCommitments are the public counterparts to Nonces and can be safely shared
 * with other participants and the coordinator.
 */
export class NonceCommitment<C extends Ciphersuite> {
  /** The underlying group element */
  private readonly element: C["Element"];

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create a NonceCommitment from a group element.
   * @internal
   */
  private constructor(ciphersuite: C, element: C["Element"]) {
    this.ciphersuite = ciphersuite;
    this.element = element;
  }

  /**
   * Create a new NonceCommitment from an Element.
   * @internal
   */
  static fromElement<C extends Ciphersuite>(
    ciphersuite: C,
    element: C["Element"],
  ): NonceCommitment<C> {
    return new NonceCommitment(ciphersuite, element);
  }

  /**
   * Get the inner Element of the NonceCommitment.
   * @internal
   */
  toElement(): C["Element"] {
    return this.element;
  }

  /**
   * Create a NonceCommitment from a Nonce.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param nonce - The nonce to create a commitment from
   * @returns The commitment to the nonce
   */
  static fromNonce<C extends Ciphersuite>(ciphersuite: C, nonce: Nonce<C>): NonceCommitment<C> {
    const element = ciphersuite.scalarBaseMult(nonce.toScalar());
    return new NonceCommitment(ciphersuite, element);
  }

  /**
   * Deserialize a NonceCommitment from bytes.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - The serialized commitment bytes
   * @returns The deserialized commitment
   * @throws Error if deserialization fails
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): NonceCommitment<C> {
    const element = ciphersuite.deserializeElement(bytes);
    return new NonceCommitment(ciphersuite, element);
  }

  /**
   * Serialize the NonceCommitment to bytes.
   *
   * @returns The serialized commitment bytes
   * @throws Error if the element is the identity
   */
  serialize(): Uint8Array {
    return this.ciphersuite.serializeElement(this.element);
  }

  /**
   * Check equality with another NonceCommitment.
   *
   * @param other - The other commitment to compare with
   * @returns true if the commitments are equal
   */
  equals(other: NonceCommitment<C>): boolean {
    return this.ciphersuite.elementsEqual(this.element, other.element);
  }

  /**
   * Returns a string representation of this NonceCommitment.
   */
  toString(): string {
    try {
      const bytes = this.serialize();
      return `NonceCommitment(${bytesToHex(bytes)})`;
    } catch {
      return "NonceCommitment(<invalid>)";
    }
  }
}

/**
 * Comprised of hiding and binding nonces.
 *
 * Note that SigningNonces must be used *only once* for a signing operation;
 * re-using nonces will result in leakage of a signer's long-lived signing key.
 */
export class SigningNonces<C extends Ciphersuite> {
  /** The hiding Nonce */
  readonly hiding: Nonce<C>;

  /** The binding Nonce */
  readonly binding: Nonce<C>;

  /**
   * The commitments to the nonces. This is precomputed to improve
   * sign() performance, since it needs to check if the commitments
   * to the participant's nonces are included in the commitments sent
   * by the Coordinator, and this prevents having to recompute them.
   */
  readonly commitments: SigningCommitments<C>;

  /** The ciphersuite instance */
  readonly ciphersuite: C;

  /**
   * Create SigningNonces from hiding and binding nonces.
   * @internal
   */
  private constructor(
    ciphersuite: C,
    hiding: Nonce<C>,
    binding: Nonce<C>,
    commitments: SigningCommitments<C>,
  ) {
    this.ciphersuite = ciphersuite;
    this.hiding = hiding;
    this.binding = binding;
    this.commitments = commitments;
  }

  /**
   * Generates a new signing nonce.
   *
   * Each participant generates signing nonces before performing a signing operation.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param secret - The participant's signing share
   * @param rng - A cryptographically secure random number generator
   * @returns New signing nonces
   */
  static generate<C extends Ciphersuite>(
    ciphersuite: C,
    secret: SigningShare<C>,
    rng: RandomSource,
  ): SigningNonces<C> {
    const hiding = Nonce.generate(ciphersuite, secret, rng);
    const binding = Nonce.generate(ciphersuite, secret, rng);

    return SigningNonces.fromNonces(ciphersuite, hiding, binding);
  }

  /**
   * Generates a new SigningNonces from a pair of Nonces.
   *
   * # Security
   *
   * SigningNonces MUST NOT be repeated in different FROST signings.
   * Thus, if you're using this method (because e.g. you're writing it
   * to disk between rounds), be careful so that does not happen.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param hiding - The hiding nonce
   * @param binding - The binding nonce
   * @returns New signing nonces
   */
  static fromNonces<C extends Ciphersuite>(
    ciphersuite: C,
    hiding: Nonce<C>,
    binding: Nonce<C>,
  ): SigningNonces<C> {
    const hidingCommitment = NonceCommitment.fromNonce(ciphersuite, hiding);
    const bindingCommitment = NonceCommitment.fromNonce(ciphersuite, binding);
    const commitments = new SigningCommitments(ciphersuite, hidingCommitment, bindingCommitment);

    return new SigningNonces(ciphersuite, hiding, binding, commitments);
  }

  /**
   * Zeroize the nonces by overwriting with zeros.
   *
   * This should be called when the nonces are no longer needed to prevent
   * secret data from remaining in memory.
   */
  zeroize(): void {
    this.hiding.zeroize();
    this.binding.zeroize();
  }

  /**
   * Returns a string representation of this SigningNonces (redacted for security).
   */
  toString(): string {
    return "SigningNonces { hiding: <redacted>, binding: <redacted> }";
  }
}

/**
 * Published by each participant in the first round of the signing protocol.
 *
 * This step can be batched if desired by the implementation. Each
 * SigningCommitment can be used for exactly *one* signature.
 */
export class SigningCommitments<C extends Ciphersuite> {
  /** Commitment to the hiding Nonce */
  readonly hiding: NonceCommitment<C>;

  /** Commitment to the binding Nonce */
  readonly binding: NonceCommitment<C>;

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create new SigningCommitments.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param hiding - Commitment to the hiding nonce
   * @param binding - Commitment to the binding nonce
   */
  constructor(ciphersuite: C, hiding: NonceCommitment<C>, binding: NonceCommitment<C>) {
    this.ciphersuite = ciphersuite;
    this.hiding = hiding;
    this.binding = binding;
  }

  /**
   * Create SigningCommitments from SigningNonces.
   *
   * @param nonces - The signing nonces
   * @returns The commitments to those nonces
   */
  static fromNonces<C extends Ciphersuite>(nonces: SigningNonces<C>): SigningCommitments<C> {
    return nonces.commitments;
  }

  /**
   * Computes the [commitment share] from these round one signing commitments.
   *
   * [commitment share]: https://datatracker.ietf.org/doc/html/rfc9591#name-signature-share-aggregation
   *
   * @param bindingFactor - The binding factor rho for this participant
   * @returns The group commitment share
   * @internal
   */
  toGroupCommitmentShare(bindingFactor: BindingFactor<C>): GroupCommitmentShare<C> {
    // hiding + (binding * rho)
    const scaledBinding = this.ciphersuite.elementMul(
      this.binding.toElement(),
      bindingFactor.toScalar(),
    );
    const result = this.ciphersuite.elementAdd(this.hiding.toElement(), scaledBinding);
    return GroupCommitmentShare.fromElement(this.ciphersuite, result);
  }

  /**
   * Check equality with another SigningCommitments.
   *
   * @param other - The other commitments to compare with
   * @returns true if the commitments are equal
   */
  equals(other: SigningCommitments<C>): boolean {
    return this.hiding.equals(other.hiding) && this.binding.equals(other.binding);
  }

  /**
   * Serialize the SigningCommitments to bytes.
   *
   * @returns The serialized bytes (hiding commitment || binding commitment)
   */
  serialize(): Uint8Array {
    const hidingBytes = this.hiding.serialize();
    const bindingBytes = this.binding.serialize();
    const result = new Uint8Array(hidingBytes.length + bindingBytes.length);
    result.set(hidingBytes, 0);
    result.set(bindingBytes, hidingBytes.length);
    return result;
  }

  /**
   * Deserialize SigningCommitments from bytes.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - The serialized bytes
   * @returns The deserialized commitments
   */
  static deserialize<C extends Ciphersuite>(
    ciphersuite: C,
    bytes: Uint8Array,
  ): SigningCommitments<C> {
    const elementSize = ciphersuite.elementSize();
    if (bytes.length !== elementSize * 2) {
      throw new Error(
        `Invalid SigningCommitments length: expected ${elementSize * 2}, got ${bytes.length}`,
      );
    }
    const hidingBytes = bytes.slice(0, elementSize);
    const bindingBytes = bytes.slice(elementSize);
    const hiding = NonceCommitment.deserialize(ciphersuite, hidingBytes);
    const binding = NonceCommitment.deserialize(ciphersuite, bindingBytes);
    return new SigningCommitments(ciphersuite, hiding, binding);
  }

  /**
   * Returns a string representation of this SigningCommitments.
   */
  toString(): string {
    return `SigningCommitments { hiding: ${this.hiding.toString()}, binding: ${this.binding.toString()} }`;
  }
}

/**
 * One signer's share of the group commitment, derived from their individual signing commitments
 * and the binding factor _rho_.
 */
export class GroupCommitmentShare<C extends Ciphersuite> {
  /** The underlying group element */
  private readonly element: C["Element"];

  /** The ciphersuite instance */
  readonly ciphersuite: C;

  /**
   * Create a GroupCommitmentShare from a group element.
   * @internal
   */
  private constructor(ciphersuite: C, element: C["Element"]) {
    this.ciphersuite = ciphersuite;
    this.element = element;
  }

  /**
   * Create from an element.
   * @internal
   */
  static fromElement<C extends Ciphersuite>(
    ciphersuite: C,
    element: C["Element"],
  ): GroupCommitmentShare<C> {
    return new GroupCommitmentShare(ciphersuite, element);
  }

  /**
   * Return the underlying element.
   * @internal
   */
  toElement(): C["Element"] {
    return this.element;
  }
}

/**
 * Encode the list of group signing commitments.
 *
 * Implements [`encode_group_commitment_list()`] from the spec.
 *
 * `signingCommitments` must contain the sorted map of participants
 * identifiers to the signing commitments they issued.
 *
 * Returns a byte string containing the serialized representation of the
 * commitment list.
 *
 * [`encode_group_commitment_list()`]: https://datatracker.ietf.org/doc/html/rfc9591#name-list-operations
 *
 * @param ciphersuite - The ciphersuite to use
 * @param signingCommitments - Map of identifier to signing commitments (must be sorted by identifier)
 * @returns The encoded commitment list
 * @internal
 */
export function encodeGroupCommitments<C extends Ciphersuite>(
  ciphersuite: C,
  signingCommitments: Map<Identifier<C>, SigningCommitments<C>>,
): Uint8Array {
  // Mark ciphersuite as used for type consistency
  void ciphersuite;

  const chunks: Uint8Array[] = [];

  // Sort by identifier - compare() no longer needs ciphersuite
  const sortedEntries = [...signingCommitments.entries()].sort((a, b) => a[0].compare(b[0]));

  for (const [identifier, commitment] of sortedEntries) {
    // serialize() no longer needs ciphersuite parameter
    chunks.push(identifier.serialize());
    // Use the SigningCommitments' ciphersuite for element serialization
    chunks.push(commitment.hiding.serialize());
    chunks.push(commitment.binding.serialize());
  }

  // Concatenate all chunks
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}

/**
 * Done once by each participant, to generate _their_ nonces and commitments
 * that are then used during signing.
 *
 * This is only needed if pre-processing is needed (for 1-round FROST). For
 * regular 2-round FROST, use `commit`.
 *
 * When performing signing using two rounds, numNonces would equal 1, to
 * perform the first round. Batching entails generating more than one
 * nonce/commitment pair at a time. Nonces should be stored in secret storage
 * for later use, whereas the commitments are published.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param numNonces - The number of nonce pairs to generate
 * @param secret - The participant's signing share
 * @param rng - A cryptographically secure random number generator
 * @returns A tuple of [signing nonces, signing commitments]
 */
export function preprocess<C extends Ciphersuite>(
  ciphersuite: C,
  numNonces: number,
  secret: SigningShare<C>,
  rng: RandomSource,
): [SigningNonces<C>[], SigningCommitments<C>[]] {
  const signingNonces: SigningNonces<C>[] = [];
  const signingCommitments: SigningCommitments<C>[] = [];

  for (let i = 0; i < numNonces; i++) {
    const nonces = SigningNonces.generate(ciphersuite, secret, rng);
    signingCommitments.push(SigningCommitments.fromNonces(nonces));
    signingNonces.push(nonces);
  }

  return [signingNonces, signingCommitments];
}

/**
 * Performed once by each participant selected for the signing operation.
 *
 * Implements `commit` from the spec.
 *
 * Generates the signing nonces and commitments to be used in the signing operation.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9591#name-round-one-commitment
 *
 * @param ciphersuite - The ciphersuite to use
 * @param secret - The participant's signing share
 * @param rng - A cryptographically secure random number generator
 * @returns A tuple of [signing nonces, signing commitments]
 */
export function commit<C extends Ciphersuite>(
  ciphersuite: C,
  secret: SigningShare<C>,
  rng: RandomSource,
): [SigningNonces<C>, SigningCommitments<C>] {
  const [nonces, commitments] = preprocess(ciphersuite, 1, secret, rng);
  return [nonces[0], commitments[0]];
}

// Helper function to convert bytes to hex string
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
