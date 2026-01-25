/**
 * Core FROST types
 *
 * This module defines the core types used throughout the FROST implementation.
 * It is the canonical source for the Ciphersuite interface and related types.
 *
 * @module types
 */

import type { SigningCommitments } from "./round1";

// Forward declaration for Identifier to avoid circular dependency
// The actual Identifier class is in ./identifier.ts
// Note: The actual Identifier class requires ciphersuite for most operations
interface IdentifierLike<C extends Ciphersuite> {
  toScalar(): C["Scalar"];
  clone(): IdentifierLike<C>;
}

/**
 * A cryptographically secure random number generator interface.
 */
export interface CryptoRng {
  /**
   * Fill the provided buffer with random bytes.
   */
  fill(buffer: Uint8Array): void;

  /**
   * Generate a random 32-bit unsigned integer.
   */
  nextU32(): number;

  /**
   * Generate a random 64-bit unsigned integer as a BigInt.
   */
  nextU64(): bigint;
}

/**
 * A prime order finite field GF(q) over which all scalar values for our prime order group can be
 * multiplied are defined.
 *
 * @typeParam S - The scalar type for this field
 * @typeParam Ser - The serialization type (fixed-length byte array)
 */
export interface Field<S = unknown, Ser extends Uint8Array = Uint8Array> {
  /**
   * Returns the zero element of the field, the additive identity.
   */
  zero(): S;

  /**
   * Returns the one element of the field, the multiplicative identity.
   */
  one(): S;

  /**
   * Computes the multiplicative inverse of an element of the scalar field, failing if the
   * element is zero.
   */
  invert(scalar: S): S;

  /**
   * Generate a random scalar from the entire space [0, l-1]
   */
  random(rng: CryptoRng): S;

  /**
   * Serialize a scalar to bytes.
   */
  serialize(scalar: S): Ser;

  /**
   * Serialize a scalar to bytes in little-endian order.
   */
  littleEndianSerialize(scalar: S): Ser;

  /**
   * Deserialize a scalar from bytes.
   */
  deserialize(buf: Ser | Uint8Array): S;

  /**
   * Add two scalars.
   */
  add(a: S, b: S): S;

  /**
   * Subtract two scalars.
   */
  sub(a: S, b: S): S;

  /**
   * Multiply two scalars.
   */
  mul(a: S, b: S): S;

  /**
   * Negate a scalar.
   */
  negate(scalar: S): S;

  /**
   * Check if two scalars are equal (constant-time).
   */
  eq(a: S, b: S): boolean;

  /**
   * Check if a scalar is zero.
   */
  isZero(scalar: S): boolean;
}

/**
 * A prime-order group (or subgroup) that provides everything we need to create and verify Schnorr
 * signatures.
 *
 * @typeParam F - The field type for scalars
 * @typeParam E - The element type for this group
 * @typeParam Ser - The serialization type (fixed-length byte array, little-endian)
 */
export interface Group<
  F extends Field = Field,
  E = unknown,
  Ser extends Uint8Array = Uint8Array,
> {
  /**
   * The field instance for this group.
   */
  readonly field: F;

  /**
   * The cofactor of the group.
   */
  cofactor(): ScalarOf<F>;

  /**
   * The identity element of the group.
   */
  identity(): E;

  /**
   * The generator element of the group.
   */
  generator(): E;

  /**
   * Serialize an element to bytes.
   */
  serialize(element: E): Ser;

  /**
   * Deserialize an element from bytes.
   */
  deserialize(buf: Ser | Uint8Array): E;

  /**
   * Add two group elements.
   */
  add(a: E, b: E): E;

  /**
   * Subtract two group elements.
   */
  sub(a: E, b: E): E;

  /**
   * Multiply a group element by a scalar.
   */
  scalarMul(element: E, scalar: ScalarOf<F>): E;

  /**
   * Scalar base multiplication (generator * scalar).
   */
  scalarBaseMul(scalar: ScalarOf<F>): E;

  /**
   * Negate a group element.
   */
  negate(element: E): E;

  /**
   * Check if two elements are equal.
   */
  eq(a: E, b: E): boolean;

  /**
   * Check if an element is the identity.
   */
  isIdentity(element: E): boolean;
}

/**
 * Helper type to extract the scalar type from a Field.
 */
export type ScalarOf<F> = F extends Field<infer S> ? S : never;

/**
 * Helper type to extract the element type from a Group.
 */
export type ElementOf<G> = G extends Group<Field, infer E> ? E : never;

/**
 * A FROST ciphersuite specifies the underlying prime-order group details and cryptographic hash
 * function.
 *
 * This is the unified Ciphersuite interface that combines both hierarchical access (via `group`)
 * and flattened methods for convenience.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9591#name-ciphersuites
 */
export interface Ciphersuite {
  /**
   * The ciphersuite ID string. It should be equal to the contextString in
   * the spec. For new ciphersuites, this should be a string that identifies
   * the ciphersuite; it's recommended to use a similar format to the
   * ciphersuites in the FROST spec, e.g. "FROST-RISTRETTO255-SHA512-v1".
   */
  readonly ID: string;

  /**
   * The prime order group (or subgroup) that this ciphersuite operates over.
   * Provides access to Field and Group operations in a hierarchical manner.
   */
  readonly group: Group;

  /** The scalar type for this ciphersuite */
  Scalar: unknown;

  /** The element type for this ciphersuite */
  Element: unknown;

  /** The verifying key type */
  VerifyingKey: unknown;

  /** The signing key type */
  SigningKey: unknown;

  // Field operations (flattened for convenience)

  /**
   * Returns the zero element of the field, the additive identity.
   */
  scalarZero(): this["Scalar"];

  /**
   * Returns the one element of the field, the multiplicative identity.
   */
  scalarOne(): this["Scalar"];

  /**
   * Computes the multiplicative inverse of an element of the scalar field.
   * @throws Error if the element is zero
   */
  scalarInvert(scalar: this["Scalar"]): this["Scalar"];

  /**
   * Generate a random scalar from the entire space [0, l-1]
   */
  scalarRandom(rng: { fill(array: Uint8Array): void }): this["Scalar"];

  /**
   * Serialize a scalar to bytes.
   */
  serializeScalar(scalar: this["Scalar"]): Uint8Array;

  /**
   * Deserialize a scalar from bytes.
   * @throws Error if the bytes are not a valid scalar encoding
   */
  deserializeScalar(bytes: Uint8Array): this["Scalar"];

  /**
   * Add two scalars.
   */
  scalarAdd(a: this["Scalar"], b: this["Scalar"]): this["Scalar"];

  /**
   * Subtract two scalars.
   */
  scalarSub(a: this["Scalar"], b: this["Scalar"]): this["Scalar"];

  /**
   * Multiply two scalars.
   */
  scalarMul(a: this["Scalar"], b: this["Scalar"]): this["Scalar"];

  /**
   * Check if two scalars are equal.
   */
  scalarsEqual(a: this["Scalar"], b: this["Scalar"]): boolean;

  // Group operations (flattened for convenience)

  /**
   * Returns the size in bytes of a serialized element.
   */
  elementSize(): number;

  /**
   * Returns the size in bytes of a serialized scalar.
   */
  scalarSize(): number;

  /**
   * The order of the quotient group when the prime order subgroup divides the order of the
   * full curve group. For prime order curves, this should return 1.
   */
  cofactor(): this["Scalar"];

  /**
   * Additive identity of the prime order group.
   */
  identity(): this["Element"];

  /**
   * The fixed generator element of the prime order group.
   */
  generator(): this["Element"];

  /**
   * Serialize an element to bytes.
   * @throws Error if the element is the identity
   */
  serializeElement(element: this["Element"]): Uint8Array;

  /**
   * Deserialize an element from bytes.
   * @throws Error if the bytes are not a valid element encoding or represent the identity
   */
  deserializeElement(bytes: Uint8Array): this["Element"];

  /**
   * Add two group elements.
   */
  elementAdd(a: this["Element"], b: this["Element"]): this["Element"];

  /**
   * Subtract two group elements.
   */
  elementSub(a: this["Element"], b: this["Element"]): this["Element"];

  /**
   * Multiply a group element by a scalar.
   */
  elementMul(element: this["Element"], scalar: this["Scalar"]): this["Element"];

  /**
   * Scalar multiplication with the generator (g * scalar).
   */
  scalarBaseMult(scalar: this["Scalar"]): this["Element"];

  /**
   * Check if two elements are equal.
   */
  elementsEqual(a: this["Element"], b: this["Element"]): boolean;

  /**
   * Check if an element is the identity.
   */
  isIdentity(element: this["Element"]): boolean;

  // Hash functions

  /**
   * H1 for a FROST ciphersuite.
   *
   * Maps arbitrary inputs to Scalar elements of the prime-order group scalar field.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#name-cryptographic-hash-function
   */
  H1(m: Uint8Array): this["Scalar"];

  /**
   * H2 for a FROST ciphersuite.
   *
   * Maps arbitrary inputs to Scalar elements of the prime-order group scalar field.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#name-cryptographic-hash-function
   */
  H2(m: Uint8Array): this["Scalar"];

  /**
   * H3 for a FROST ciphersuite.
   *
   * Maps arbitrary inputs to Scalar elements of the prime-order group scalar field.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#name-cryptographic-hash-function
   */
  H3(m: Uint8Array): this["Scalar"];

  /**
   * H4 for a FROST ciphersuite.
   *
   * Usually an alias for the ciphersuite hash function H with domain separation applied.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#name-cryptographic-hash-function
   */
  H4(m: Uint8Array): Uint8Array;

  /**
   * H5 for a FROST ciphersuite.
   *
   * Usually an alias for the ciphersuite hash function H with domain separation applied.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#name-cryptographic-hash-function
   */
  H5(m: Uint8Array): Uint8Array;

  /**
   * Hash function for a FROST ciphersuite, used for the DKG.
   *
   * The DKG is not part of the specification, thus this is optional.
   * Returns null if DKG is not supported by the Ciphersuite.
   *
   * Maps arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
   */
  HDKG?(m: Uint8Array): this["Scalar"] | null;

  /**
   * Hash function for a FROST ciphersuite, used for deriving identifiers from strings.
   *
   * This feature is not part of the specification and is just a convenient
   * way of creating identifiers. Returns null if this is not supported.
   *
   * Maps arbitrary inputs to non-zero Scalar elements of the prime-order group scalar field.
   */
  HID?(m: Uint8Array): this["Scalar"] | null;

  // Optional extension methods for single-signer operations

  /**
   * Optional. Single-signer Schnorr signing.
   * If provided, allows for optimized single-party signing without the full FROST protocol.
   */
  singleSign?(
    signingKey: this["SigningKey"],
    message: Uint8Array,
    rng: { fill(array: Uint8Array): void },
  ): unknown;

  /**
   * Optional. Verify a Schnorr signature.
   * If provided, allows for direct signature verification without going through FROST.
   */
  verifySignature?(
    verifyingKey: this["VerifyingKey"],
    message: Uint8Array,
    signature: unknown,
  ): boolean;

  /**
   * Optional. Serialize a signature to bytes.
   * If provided, allows for custom signature serialization.
   */
  serializeSignature?(signature: unknown): Uint8Array;

  /**
   * Optional. Deserialize a signature from bytes.
   * If provided, allows for custom signature deserialization.
   */
  deserializeSignature?(bytes: Uint8Array): unknown;

  // Optional customization methods

  /**
   * Optional. Generates the challenge as is required for Schnorr signatures.
   * Called by round2.sign() and aggregate().
   */
  challenge(
    R: this["Element"],
    verifyingKey: this["VerifyingKey"],
    message: Uint8Array,
  ): Challenge<this>;

  /**
   * Optional. Pre-process round2.sign() inputs.
   * Returns the same values or modified versions.
   */
  preSign?<C extends Ciphersuite>(
    signingPackage: SigningPackage<C>,
    signerNonces: SigningNoncesLike<C>,
    keyPackage: KeyPackageLike<C>,
  ): {
    signingPackage: SigningPackage<C>;
    signerNonces: SigningNoncesLike<C>;
    keyPackage: KeyPackageLike<C>;
  };

  /**
   * Optional. Pre-process compute_group_commitment() inputs in round2.sign().
   */
  preCommitmentSign?<C extends Ciphersuite>(
    signingPackage: SigningPackage<C>,
    signingNonces: SigningNoncesLike<C>,
    bindingFactorList: BindingFactorList<C>,
  ): {
    signingPackage: SigningPackage<C>;
    signerNonces: SigningNoncesLike<C>;
  };

  /**
   * Optional. Compute the signature share for a particular signer.
   * Called by round2.sign().
   */
  computeSignatureShare?<C extends Ciphersuite>(
    groupCommitment: GroupCommitment<C>,
    signerNonces: SigningNoncesLike<C>,
    bindingFactor: BindingFactor<C>,
    lambdaI: this["Scalar"],
    keyPackage: KeyPackageLike<C>,
    challenge: Challenge<C>,
  ): SignatureShareLike<C>;

  /**
   * Optional. Verify a signing share.
   * Called by aggregate() if cheater detection is enabled.
   */
  verifyShare?<C extends Ciphersuite>(
    groupCommitment: GroupCommitment<C>,
    signatureShare: SignatureShareLike<C>,
    identifier: IdentifierLike<C>,
    groupCommitmentShare: GroupCommitmentShareLike<C>,
    verifyingShare: VerifyingShareLike<C>,
    lambdaI: this["Scalar"],
    challenge: Challenge<C>,
  ): void;

  // Computation helpers

  /**
   * Compute binding factors for all participants.
   */
  computeBindingFactorList<C extends Ciphersuite>(
    signingPackage: SigningPackage<C>,
    verifyingKey: this["VerifyingKey"],
    additionalPrefix: Uint8Array,
  ): BindingFactorList<C>;

  /**
   * Compute the group commitment from all signing commitments.
   */
  computeGroupCommitment<C extends Ciphersuite>(
    signingPackage: SigningPackage<C>,
    bindingFactorList: BindingFactorList<C>,
  ): GroupCommitment<C>;

  /**
   * Compute the Lagrange coefficient for a participant.
   */
  deriveInterpolatingValue<C extends Ciphersuite>(
    signerId: IdentifierLike<C>,
    signingPackage: SigningPackage<C>,
  ): this["Scalar"];
}

/**
 * Type alias for the scalar type of a ciphersuite (for use with generic C extends Ciphersuite).
 */
export type Scalar<C extends Ciphersuite> = C["Scalar"];

/**
 * Type alias for the element type of a ciphersuite (for use with generic C extends Ciphersuite).
 */
export type Element<C extends Ciphersuite> = C["Element"];

// Forward declarations for types used in Ciphersuite methods to avoid circular imports
interface SigningNoncesLike<C extends Ciphersuite> {
  readonly hiding: { toScalar(): C["Scalar"] };
  readonly binding: { toScalar(): C["Scalar"] };
  readonly commitments: SigningCommitmentsLike<C>;
}

interface SigningCommitmentsLike<C extends Ciphersuite> {
  readonly hiding: { toElement(): C["Element"] };
  readonly binding: { toElement(): C["Element"] };
  equals(other: SigningCommitmentsLike<C>): boolean;
}

interface KeyPackageLike<C extends Ciphersuite> {
  readonly identifier: IdentifierLike<C>;
  readonly signingShare: { toScalar(): C["Scalar"] };
  readonly verifyingShare: { toElement(): C["Element"] };
  readonly verifyingKey: C["Element"];
  readonly minSigners: number;
}

interface SignatureShareLike<C extends Ciphersuite> {
  toScalar(): C["Scalar"];
}

interface GroupCommitmentShareLike<C extends Ciphersuite> {
  toElement(): C["Element"];
}

interface VerifyingShareLike<C extends Ciphersuite> {
  toElement(): C["Element"];
}

// Re-export Identifier type alias for use in this module
// Note: IdentifierLike is used in Ciphersuite interface methods
export type { IdentifierLike };

/**
 * A type refinement for the scalar field element representing the per-message _[challenge]_.
 *
 * [challenge]: https://datatracker.ietf.org/doc/html/rfc9591#name-signature-challenge-computa
 */
export class Challenge<C extends Ciphersuite> {
  /** The underlying scalar value */
  private readonly scalar: C["Scalar"];

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create a Challenge from a scalar.
   * @internal
   */
  private constructor(ciphersuite: C, scalar: C["Scalar"]) {
    this.ciphersuite = ciphersuite;
    this.scalar = scalar;
  }

  /**
   * Creates a challenge from a scalar.
   * @internal
   */
  static fromScalar<C extends Ciphersuite>(ciphersuite: C, scalar: C["Scalar"]): Challenge<C> {
    return new Challenge(ciphersuite, scalar);
  }

  /**
   * Return the underlying scalar.
   * @internal
   */
  toScalar(): C["Scalar"] {
    return this.scalar;
  }

  /**
   * Returns a string representation of this Challenge.
   */
  toString(): string {
    const bytes = this.ciphersuite.serializeScalar(this.scalar);
    return `Challenge(${bytesToHex(bytes)})`;
  }
}

/**
 * The binding factor, also known as _rho_ (rho)
 *
 * Ensures each signature share is strongly bound to a signing set, specific set
 * of commitments, and a specific message.
 *
 * @see https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md
 */
export class BindingFactor<C extends Ciphersuite> {
  /** The underlying scalar value */
  private readonly scalar: C["Scalar"];

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create a BindingFactor from a scalar.
   * @internal
   */
  private constructor(ciphersuite: C, scalar: C["Scalar"]) {
    this.ciphersuite = ciphersuite;
    this.scalar = scalar;
  }

  /**
   * Creates a binding factor from a scalar.
   * @internal
   */
  static fromScalar<C extends Ciphersuite>(ciphersuite: C, scalar: C["Scalar"]): BindingFactor<C> {
    return new BindingFactor(ciphersuite, scalar);
  }

  /**
   * Return the underlying scalar.
   * @internal
   */
  toScalar(): C["Scalar"] {
    return this.scalar;
  }

  /**
   * Serializes BindingFactor to bytes.
   */
  serialize(): Uint8Array {
    return this.ciphersuite.serializeScalar(this.scalar);
  }

  /**
   * Returns a string representation of this BindingFactor.
   */
  toString(): string {
    return `BindingFactor(${bytesToHex(this.serialize())})`;
  }
}

/**
 * A list of binding factors and their associated identifiers.
 */
export class BindingFactorList<C extends Ciphersuite> {
  /** The map of identifiers to binding factors */
  private readonly factors: Map<string, BindingFactor<C>>;

  /** The ciphersuite instance */
  readonly ciphersuite: C;

  /**
   * Create a new BindingFactorList.
   * @internal
   */
  constructor(ciphersuite: C, factors: Map<string, BindingFactor<C>>) {
    this.ciphersuite = ciphersuite;
    this.factors = factors;
  }

  /**
   * Create from a map with Identifier keys (converts to string keys internally).
   * @internal
   */
  static fromIdentifierMap<C extends Ciphersuite>(
    ciphersuite: C,
    factors: Map<IdentifierLike<C>, BindingFactor<C>>,
    serializeFn: (id: IdentifierLike<C>) => Uint8Array,
  ): BindingFactorList<C> {
    const stringMap = new Map<string, BindingFactor<C>>();
    for (const [id, factor] of factors) {
      stringMap.set(bytesToHex(serializeFn(id)), factor);
    }
    return new BindingFactorList(ciphersuite, stringMap);
  }

  /**
   * Get the BindingFactor for the given identifier key, or undefined if not found.
   */
  getByKey(key: string): BindingFactor<C> | undefined {
    return this.factors.get(key);
  }

  /**
   * Get the BindingFactor for the given identifier using serialized bytes, or undefined if not found.
   */
  getByBytes(bytes: Uint8Array): BindingFactor<C> | undefined {
    return this.factors.get(bytesToHex(bytes));
  }
}

/**
 * Generated by the coordinator of the signing operation and distributed to
 * each signing party.
 *
 * Note: This is an abstract type definition. The concrete implementation
 * should be provided by each ciphersuite.
 */
export interface SigningPackage<C extends Ciphersuite> {
  /**
   * The set of commitments participants published in the first round of the protocol.
   * The map is keyed by some identifier type that depends on the implementation.
   */
  readonly signingCommitments: Map<unknown, SigningCommitments<C>>;

  /**
   * Message which each participant will sign.
   *
   * Each signer should perform protocol-specific verification on the message.
   */
  readonly message: Uint8Array;
}

/**
 * The product of all signers' individual commitments, published as part of the
 * final signature.
 */
export class GroupCommitment<C extends Ciphersuite> {
  /** The underlying group element */
  private readonly element: C["Element"];

  /** The ciphersuite instance */
  readonly ciphersuite: C;

  /**
   * Create a GroupCommitment from a group element.
   * @internal
   */
  private constructor(ciphersuite: C, element: C["Element"]) {
    this.ciphersuite = ciphersuite;
    this.element = element;
  }

  /**
   * Create a GroupCommitment from an element.
   * @internal
   */
  static fromElement<C extends Ciphersuite>(
    ciphersuite: C,
    element: C["Element"],
  ): GroupCommitment<C> {
    return new GroupCommitment(ciphersuite, element);
  }

  /**
   * Return the underlying element.
   * @internal
   */
  toElement(): C["Element"] {
    return this.element;
  }
}

// Note: The canonical Signature class is defined in signature.ts

// Helper function to convert bytes to hex string
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
