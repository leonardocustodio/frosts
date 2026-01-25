/**
 * FROST keys, keygen, key shares
 *
 * This module provides types and functions for FROST key generation
 * and management, including trusted dealer key generation and
 * Shamir secret sharing.
 *
 * @module keys
 */

import type { Ciphersuite } from "./ciphersuite";
import type { Identifier } from "./identifier";
import type { RandomSource } from "./random";
import { FrostError } from "./error";

// Re-export submodules
export * from "./keys/dkg";
export * from "./keys/repairable";
export * from "./keys/refresh";

/**
 * Compute the Lagrange coefficient for a participant.
 *
 * Implements `derive_interpolating_value` from the spec.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param signerIds - Array of participant identifiers in the signing set
 * @param xCoord - The x-coordinate for the coefficient (or undefined for x=0)
 * @param signerId - The participant's own identifier
 * @returns The Lagrange coefficient
 * @throws {FrostError} If the identifier is duplicated or not found
 * @internal
 */
export function computeLagrangeCoefficient<C extends Ciphersuite>(
  ciphersuite: C,
  signerIds: Identifier<C>[],
  xCoord: Identifier<C> | undefined,
  signerId: Identifier<C>,
): C["Scalar"] {
  let numerator = ciphersuite.scalarOne();
  let denominator = ciphersuite.scalarOne();

  const xI = signerId.toScalar();
  const x = xCoord !== undefined ? xCoord.toScalar() : ciphersuite.scalarZero();

  for (const id of signerIds) {
    const xJ = id.toScalar();

    if (ciphersuite.scalarsEqual(xJ, xI)) {
      continue;
    }

    // numerator *= x - xJ
    const xMinusXj = ciphersuite.scalarSub(x, xJ);
    numerator = ciphersuite.scalarMul(numerator, xMinusXj);

    // denominator *= xI - xJ
    const xIMinusXj = ciphersuite.scalarSub(xI, xJ);
    if (ciphersuite.scalarsEqual(xIMinusXj, ciphersuite.scalarZero())) {
      throw FrostError.duplicatedIdentifier<C>();
    }
    denominator = ciphersuite.scalarMul(denominator, xIMinusXj);
  }

  const denominatorInverse = ciphersuite.scalarInvert(denominator);
  return ciphersuite.scalarMul(numerator, denominatorInverse);
}

/**
 * Sum the commitments from all participants in a distributed key generation
 * run into a single group commitment.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param commitments - Array of commitment references from each participant
 * @returns The combined VerifiableSecretSharingCommitment
 * @throws {FrostError} If the number of commitments is incorrect
 */
export function sumCommitments<C extends Ciphersuite>(
  ciphersuite: C,
  commitments: VerifiableSecretSharingCommitment<C>[],
): VerifiableSecretSharingCommitment<C> {
  if (commitments.length === 0) {
    throw FrostError.incorrectNumberOfCommitments<C>();
  }

  const firstCommitment = commitments[0];
  const numCoefficients = firstCommitment.coefficients().length;

  // Initialize with identity elements
  const groupCommitment: CoefficientCommitment<C>[] = [];
  for (let i = 0; i < numCoefficients; i++) {
    groupCommitment.push(new CoefficientCommitment(ciphersuite, ciphersuite.identity()));
  }

  // Sum all commitments
  for (const commitment of commitments) {
    const coeffs = commitment.coefficients();
    if (coeffs.length !== numCoefficients) {
      throw FrostError.incorrectNumberOfCommitments<C>();
    }
    for (let i = 0; i < numCoefficients; i++) {
      const currentValue = groupCommitment[i].value();
      const addValue = coeffs[i].value();
      groupCommitment[i] = new CoefficientCommitment(
        ciphersuite,
        ciphersuite.elementAdd(currentValue, addValue),
      );
    }
  }

  return new VerifiableSecretSharingCommitment(ciphersuite, groupCommitment);
}

/**
 * Return a vector of randomly generated polynomial coefficients (Scalars).
 *
 * @param ciphersuite - The ciphersuite to use
 * @param size - Number of coefficients to generate
 * @param rng - Random number generator
 * @returns Array of random scalars
 */
export function generateCoefficients<C extends Ciphersuite>(
  ciphersuite: C,
  size: number,
  rng: RandomSource,
): C["Scalar"][] {
  const coefficients: C["Scalar"][] = [];
  for (let i = 0; i < size; i++) {
    coefficients.push(ciphersuite.scalarRandom(rng));
  }
  return coefficients;
}

/**
 * Return a list of default identifiers (1 to maxSigners, inclusive).
 *
 * @param ciphersuite - The ciphersuite to use
 * @param maxSigners - Maximum number of signers
 * @returns Array of identifiers
 */
export async function defaultIdentifiers<C extends Ciphersuite>(
  ciphersuite: C,
  maxSigners: number,
): Promise<Identifier<C>[]> {
  // Import dynamically to avoid circular dependency
  const { Identifier: Id } = (await import("./identifier")) as {
    Identifier: { fromU16: <T extends Ciphersuite>(cs: T, n: number) => Identifier<T> };
  };
  const identifiers: Identifier<C>[] = [];
  for (let i = 1; i <= maxSigners; i++) {
    identifiers.push(Id.fromU16(ciphersuite, i));
  }
  return identifiers;
}

/**
 * A secret scalar value representing a signer's share of the group secret.
 */
export class SigningShare<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  private readonly scalar: C["Scalar"];

  /**
   * Create a new SigningShare from a scalar.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param scalar - The scalar value
   */
  constructor(ciphersuite: C, scalar: C["Scalar"]) {
    this.ciphersuite = ciphersuite;
    this.scalar = scalar;
  }

  /**
   * Get the inner scalar value.
   *
   * @returns The scalar value
   */
  toScalar(): C["Scalar"] {
    return this.scalar;
  }

  /**
   * Deserialize from bytes.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - Serialized bytes
   * @returns The deserialized SigningShare
   * @throws {FrostError} If deserialization fails
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): SigningShare<C> {
    const scalar = ciphersuite.deserializeScalar(bytes);
    return new SigningShare(ciphersuite, scalar);
  }

  /**
   * Serialize to bytes.
   *
   * @returns Serialized bytes
   */
  serialize(): Uint8Array {
    return this.ciphersuite.serializeScalar(this.scalar);
  }

  /**
   * Computes the signing share from a list of coefficients.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param coefficients - Polynomial coefficients
   * @param peer - The identifier of the peer
   * @returns The computed signing share
   */
  static fromCoefficients<C extends Ciphersuite>(
    ciphersuite: C,
    coefficients: C["Scalar"][],
    peer: Identifier<C>,
  ): SigningShare<C> {
    const value = evaluatePolynomial(ciphersuite, peer, coefficients);
    return new SigningShare(ciphersuite, value);
  }

  /**
   * Create a default (zero) SigningShare.
   *
   * @param ciphersuite - The ciphersuite to use
   * @returns A zero SigningShare
   */
  static default<C extends Ciphersuite>(ciphersuite: C): SigningShare<C> {
    return new SigningShare(ciphersuite, ciphersuite.scalarZero());
  }

  /**
   * Check equality with another SigningShare.
   *
   * @param other - The other SigningShare
   * @returns True if equal
   */
  equals(other: SigningShare<C>): boolean {
    return this.ciphersuite.scalarsEqual(this.scalar, other.scalar);
  }

  /**
   * Convert to a VerifyingShare.
   *
   * @returns The corresponding VerifyingShare
   */
  toVerifyingShare(): VerifyingShare<C> {
    const element = this.ciphersuite.scalarBaseMult(this.scalar);
    return new VerifyingShare(this.ciphersuite, element);
  }
}

/**
 * A public group element that represents a single signer's public verification share.
 */
export class VerifyingShare<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  private readonly element: C["Element"];

  /**
   * Create a new VerifyingShare from an element.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param element - The group element
   */
  constructor(ciphersuite: C, element: C["Element"]) {
    this.ciphersuite = ciphersuite;
    this.element = element;
  }

  /**
   * Get the inner element value.
   *
   * @returns The element value
   */
  toElement(): C["Element"] {
    return this.element;
  }

  /**
   * Deserialize from bytes.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - Serialized bytes
   * @returns The deserialized VerifyingShare
   * @throws {FrostError} If deserialization fails
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): VerifyingShare<C> {
    const element = ciphersuite.deserializeElement(bytes);
    return new VerifyingShare(ciphersuite, element);
  }

  /**
   * Serialize to bytes.
   *
   * @returns Serialized bytes
   * @throws {FrostError} If serialization fails
   */
  serialize(): Uint8Array {
    return this.ciphersuite.serializeElement(this.element);
  }

  /**
   * Computes a verifying share for a peer given the group commitment.
   *
   * DKG Round 2, Step 4:
   * Any participant can compute the public verification share of any
   * other participant by calculating Y_i = product of phi_{jk}^{i^k mod q}.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param identifier - The participant identifier
   * @param commitment - The verifiable secret sharing commitment
   * @returns The computed VerifyingShare
   */
  static fromCommitment<C extends Ciphersuite>(
    ciphersuite: C,
    identifier: Identifier<C>,
    commitment: VerifiableSecretSharingCommitment<C>,
  ): VerifyingShare<C> {
    const element = evaluateVss(ciphersuite, identifier, commitment);
    return new VerifyingShare(ciphersuite, element);
  }

  /**
   * Check equality with another VerifyingShare.
   *
   * @param other - The other VerifyingShare
   * @returns True if equal
   */
  equals(other: VerifyingShare<C>): boolean {
    return this.ciphersuite.elementsEqual(this.element, other.element);
  }
}

/**
 * A Group::Element newtype that is a commitment to one coefficient of our secret polynomial.
 *
 * This is a (public) commitment to one coefficient of a secret polynomial used for performing
 * verifiable secret sharing for a Shamir secret share.
 */
export class CoefficientCommitment<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  private readonly element: C["Element"];

  /**
   * Create a new CoefficientCommitment.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param value - The group element value
   */
  constructor(ciphersuite: C, value: C["Element"]) {
    this.ciphersuite = ciphersuite;
    this.element = value;
  }

  /**
   * Deserialize from bytes.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - Serialized bytes
   * @returns The deserialized CoefficientCommitment
   * @throws {FrostError} If deserialization fails
   */
  static deserialize<C extends Ciphersuite>(
    ciphersuite: C,
    bytes: Uint8Array,
  ): CoefficientCommitment<C> {
    const element = ciphersuite.deserializeElement(bytes);
    return new CoefficientCommitment(ciphersuite, element);
  }

  /**
   * Serialize to bytes.
   *
   * @returns Serialized bytes
   * @throws {FrostError} If serialization fails
   */
  serialize(): Uint8Array {
    return this.ciphersuite.serializeElement(this.element);
  }

  /**
   * Returns inner element value.
   *
   * @returns The element value
   */
  value(): C["Element"] {
    return this.element;
  }

  /**
   * Check equality with another CoefficientCommitment.
   *
   * @param other - The other CoefficientCommitment
   * @returns True if equal
   */
  equals(other: CoefficientCommitment<C>): boolean {
    return this.ciphersuite.elementsEqual(this.element, other.element);
  }
}

/**
 * Contains the commitments to the coefficients for our secret polynomial _f_,
 * used to generate participants' key shares.
 *
 * VerifiableSecretSharingCommitment contains a set of commitments to the coefficients
 * (which themselves are scalars) for a secret polynomial f, where f is used to
 * generate each ith participant's key share f(i). Participants use this set of
 * commitments to perform verifiable secret sharing.
 *
 * Note that participants MUST be assured that they have the *same*
 * VerifiableSecretSharingCommitment, either by performing pairwise comparison, or by using
 * some agreed-upon public location for publication, where each participant can
 * ensure that they received the correct (and same) value.
 */
export class VerifiableSecretSharingCommitment<C extends Ciphersuite> {
  readonly ciphersuite: C;
  /** The coefficient commitments */
  readonly commitmentCoefficients: CoefficientCommitment<C>[];

  /**
   * Create a new VerifiableSecretSharingCommitment.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param coefficients - Array of coefficient commitments
   */
  constructor(ciphersuite: C, coefficients: CoefficientCommitment<C>[]) {
    this.ciphersuite = ciphersuite;
    this.commitmentCoefficients = coefficients;
  }

  /**
   * Returns serialized coefficient commitments.
   *
   * @returns Array of serialized commitments
   * @throws {FrostError} If serialization fails
   */
  serialize(): Uint8Array[] {
    return this.commitmentCoefficients.map((cc) => cc.serialize());
  }

  /**
   * Serialize the whole commitment vector as a single byte vector.
   *
   * @returns Concatenated serialized commitments
   * @throws {FrostError} If serialization fails
   */
  serializeWhole(): Uint8Array {
    const parts = this.serialize();
    const totalLength = parts.reduce((acc, p) => acc + p.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  /**
   * Returns VerifiableSecretSharingCommitment from an iterator of serialized
   * CoefficientCommitments (e.g. an array of Uint8Array).
   *
   * @param ciphersuite - The ciphersuite to use
   * @param serializedCommitments - Array of serialized commitments
   * @returns The deserialized VerifiableSecretSharingCommitment
   * @throws {FrostError} If deserialization fails
   */
  static deserialize<C extends Ciphersuite>(
    ciphersuite: C,
    serializedCommitments: Uint8Array[],
  ): VerifiableSecretSharingCommitment<C> {
    const coefficients = serializedCommitments.map((bytes) =>
      CoefficientCommitment.deserialize(ciphersuite, bytes),
    );
    return new VerifiableSecretSharingCommitment(ciphersuite, coefficients);
  }

  /**
   * Deserialize a whole commitment vector from a single byte vector.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - Concatenated serialized commitments
   * @returns The deserialized VerifiableSecretSharingCommitment
   * @throws {FrostError} If deserialization fails
   */
  static deserializeWhole<C extends Ciphersuite>(
    ciphersuite: C,
    bytes: Uint8Array,
  ): VerifiableSecretSharingCommitment<C> {
    // Get size from the element size
    const len = ciphersuite.elementSize();

    if (bytes.length % len !== 0) {
      throw FrostError.invalidCoefficient<C>();
    }

    const serializedCommitments: Uint8Array[] = [];
    for (let i = 0; i < bytes.length; i += len) {
      serializedCommitments.push(bytes.slice(i, i + len));
    }

    return VerifiableSecretSharingCommitment.deserialize(ciphersuite, serializedCommitments);
  }

  /**
   * Get the VerifyingKey matching this commitment vector (which is the first
   * element in the vector).
   *
   * @returns The verifying key element
   * @throws {FrostError} If the commitment vector is empty
   */
  verifyingKey(): C["Element"] {
    if (this.commitmentCoefficients.length === 0) {
      throw FrostError.missingCommitment<C>();
    }
    return this.commitmentCoefficients[0].value();
  }

  /**
   * Returns the coefficient commitments.
   *
   * @returns Array of coefficient commitments
   */
  coefficients(): CoefficientCommitment<C>[] {
    return this.commitmentCoefficients;
  }

  /**
   * Return the threshold (minSigners) associated with this commitment.
   *
   * @returns The minimum number of signers
   */
  minSigners(): number {
    return this.commitmentCoefficients.length;
  }

  /**
   * Check equality with another VerifiableSecretSharingCommitment.
   *
   * @param other - The other commitment
   * @returns True if equal
   */
  equals(other: VerifiableSecretSharingCommitment<C>): boolean {
    if (this.commitmentCoefficients.length !== other.commitmentCoefficients.length) {
      return false;
    }
    for (let i = 0; i < this.commitmentCoefficients.length; i++) {
      if (!this.commitmentCoefficients[i].equals(other.commitmentCoefficients[i])) {
        return false;
      }
    }
    return true;
  }
}

/**
 * A secret share generated by performing a (t-out-of-n) secret sharing scheme,
 * generated by a dealer performing `generateWithDealer`.
 *
 * `n` is the total number of shares and `t` is the threshold required to reconstruct the secret;
 * in this case we use Shamir's secret sharing.
 *
 * As a solution to the secret polynomial _f_ (a 'point'), the `identifier` is the x-coordinate, and the
 * `value` is the y-coordinate.
 *
 * To derive a FROST keypair, the receiver of the SecretShare *must* call
 * `toKeyPackage()`, which under the hood also performs validation.
 */
export class SecretShare<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  /** The participant identifier of this SecretShare */
  readonly identifier: Identifier<C>;
  /** Secret Key (signing share) */
  readonly signingShare: SigningShare<C>;
  /** The commitments to be distributed among signers */
  readonly commitment: VerifiableSecretSharingCommitment<C>;

  /**
   * Create a new SecretShare instance.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param identifier - The participant identifier
   * @param signingShare - The signing share
   * @param commitment - The VSS commitment
   */
  constructor(
    ciphersuite: C,
    identifier: Identifier<C>,
    signingShare: SigningShare<C>,
    commitment: VerifiableSecretSharingCommitment<C>,
  ) {
    this.ciphersuite = ciphersuite;
    this.identifier = identifier;
    this.signingShare = signingShare;
    this.commitment = commitment;
  }

  /**
   * Verifies that a secret share is consistent with a verifiable secret sharing commitment,
   * and returns the derived group info for the participant (their public verification share,
   * and the group public key) if successful.
   *
   * This ensures that this participant's share has been generated using the same
   * mechanism as all other signing participants. Note that participants *MUST*
   * ensure that they have the same view as all other participants of the
   * commitment!
   *
   * An implementation of `vss_verify()` from the spec.
   * This also implements `derive_group_info()` from the spec (which is very similar),
   * but only for this participant.
   *
   * @returns A tuple of [VerifyingShare, verifying key element]
   * @throws {FrostError} If verification fails
   */
  verify(): [VerifyingShare<C>, C["Element"]] {
    const fResult = this.ciphersuite.scalarBaseMult(this.signingShare.toScalar());
    const result = evaluateVss(this.ciphersuite, this.identifier, this.commitment);

    if (!this.ciphersuite.elementsEqual(fResult, result)) {
      throw FrostError.invalidSecretShare<C>();
    }

    return [new VerifyingShare(this.ciphersuite, result), this.commitment.verifyingKey()];
  }

  /**
   * Convert this SecretShare to a KeyPackage after verification.
   *
   * @returns The KeyPackage
   * @throws {FrostError} If verification fails
   */
  toKeyPackage(): KeyPackage<C> {
    const [verifyingShare, verifyingKey] = this.verify();
    return new KeyPackage(
      this.ciphersuite,
      this.identifier,
      this.signingShare,
      verifyingShare,
      verifyingKey,
      this.commitment.minSigners(),
    );
  }

  /**
   * Check equality with another SecretShare.
   *
   * @param other - The other SecretShare
   * @returns True if equal
   */
  equals(other: SecretShare<C>): boolean {
    return (
      this.identifier.equals(other.identifier) &&
      this.signingShare.equals(other.signingShare) &&
      this.commitment.equals(other.commitment)
    );
  }
}

/**
 * The identifier list to use when generating key shares.
 */
export type IdentifierList<C extends Ciphersuite> =
  | { type: "Default" }
  | { type: "Custom"; identifiers: Identifier<C>[] };

/**
 * Allows all participants' keys to be generated using a central, trusted dealer.
 *
 * Under the hood, this performs verifiable secret sharing, which itself uses
 * Shamir secret sharing, from which each share becomes a participant's secret
 * key. The output from this function is a set of shares along with one single
 * commitment that participants use to verify the integrity of the share.
 *
 * Implements `trusted_dealer_keygen` from the spec.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers (threshold)
 * @param identifiers - Identifier list configuration
 * @param rng - Random number generator
 * @returns A tuple of [Map of SecretShares by identifier string, PublicKeyPackage]
 * @throws {FrostError} If parameters are invalid
 */
export async function generateWithDealer<C extends Ciphersuite>(
  ciphersuite: C,
  maxSigners: number,
  minSigners: number,
  identifiers: IdentifierList<C>,
  rng: RandomSource,
): Promise<[Map<string, SecretShare<C>>, PublicKeyPackage<C>]> {
  // Generate a random signing key
  const scalar = randomNonzeroScalar(ciphersuite, rng);
  return splitFromScalar(ciphersuite, scalar, maxSigners, minSigners, identifiers, rng);
}

/**
 * Generate a random nonzero scalar.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 * @returns A random nonzero scalar
 */
function randomNonzeroScalar<C extends Ciphersuite>(
  ciphersuite: C,
  rng: RandomSource,
): C["Scalar"] {
  let scalar: C["Scalar"];
  do {
    scalar = ciphersuite.scalarRandom(rng);
  } while (ciphersuite.scalarsEqual(scalar, ciphersuite.scalarZero()));
  return scalar;
}

/**
 * Splits an existing key into FROST shares.
 *
 * This is identical to `generateWithDealer` but receives an existing key
 * instead of generating a fresh one. This is useful in scenarios where
 * the key needs to be generated externally or must be derived from e.g. a
 * seed phrase.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param secretScalar - The secret scalar to split
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers (threshold)
 * @param identifiers - Identifier list configuration
 * @param rng - Random number generator
 * @returns A tuple of [Map of SecretShares by identifier string, PublicKeyPackage]
 * @throws {FrostError} If parameters are invalid
 */
export async function splitFromScalar<C extends Ciphersuite>(
  ciphersuite: C,
  secretScalar: C["Scalar"],
  maxSigners: number,
  minSigners: number,
  identifiers: IdentifierList<C>,
  rng: RandomSource,
): Promise<[Map<string, SecretShare<C>>, PublicKeyPackage<C>]> {
  validateNumOfSigners(minSigners, maxSigners);

  let identifierList: Identifier<C>[];
  if (identifiers.type === "Custom") {
    if (identifiers.identifiers.length !== maxSigners) {
      throw FrostError.incorrectNumberOfIdentifiers<C>();
    }
    identifierList = identifiers.identifiers;
  } else {
    identifierList = await defaultIdentifiers(ciphersuite, maxSigners);
  }

  const verifyingKey = ciphersuite.scalarBaseMult(secretScalar);

  const coefficients = generateCoefficients(ciphersuite, minSigners - 1, rng);

  const secretShares = generateSecretShares(
    ciphersuite,
    secretScalar,
    maxSigners,
    minSigners,
    coefficients,
    identifierList,
  );

  const verifyingShares = new Map<string, VerifyingShare<C>>();
  const secretSharesById = new Map<string, SecretShare<C>>();

  for (const secretShare of secretShares) {
    const signerPublic = secretShare.signingShare.toVerifyingShare();
    const idKey = identifierToString(secretShare.identifier);
    verifyingShares.set(idKey, signerPublic);
    secretSharesById.set(idKey, secretShare);
  }

  const publicKeyPackage = new PublicKeyPackage(
    ciphersuite,
    verifyingShares,
    verifyingKey,
    minSigners,
  );

  return [secretSharesById, publicKeyPackage];
}

/**
 * Evaluate the polynomial with the given coefficients (constant term first)
 * at the point x=identifier using Horner's method.
 *
 * Implements `polynomial_evaluate` from the spec.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The x-coordinate
 * @param coefficients - Polynomial coefficients (constant term first)
 * @returns The polynomial value at the given point
 */
export function evaluatePolynomial<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  coefficients: C["Scalar"][],
): C["Scalar"] {
  let value = ciphersuite.scalarZero();

  const ell = identifier.toScalar();

  // Horner's method: start from the highest degree coefficient
  for (let i = coefficients.length - 1; i >= 1; i--) {
    value = ciphersuite.scalarAdd(value, coefficients[i]);
    value = ciphersuite.scalarMul(value, ell);
  }

  // Add the constant term
  if (coefficients.length > 0) {
    value = ciphersuite.scalarAdd(value, coefficients[0]);
  }

  return value;
}

/**
 * Evaluates the right-hand side of the VSS verification equation.
 *
 * Computes the product of phi^{i^k mod q}_{lk} (multiplicative notation)
 * using `identifier` as `i` and the `commitment` as the commitment vector phi_l.
 *
 * This is also used in Round 2, Step 4 of the DKG.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The participant identifier
 * @param commitment - The VSS commitment
 * @returns The evaluated group element
 */
export function evaluateVss<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  commitment: VerifiableSecretSharingCommitment<C>,
): C["Element"] {
  const i = identifier.toScalar();

  let iToTheK = ciphersuite.scalarOne();
  let sumSoFar = ciphersuite.identity();

  for (const commK of commitment.coefficients()) {
    // sumSoFar += commK.value() * iToTheK
    const term = ciphersuite.elementMul(commK.value(), iToTheK);
    sumSoFar = ciphersuite.elementAdd(sumSoFar, term);
    // iToTheK *= i
    iToTheK = ciphersuite.scalarMul(i, iToTheK);
  }

  return sumSoFar;
}

/**
 * A FROST keypair, which can be generated either by a trusted dealer or using a DKG.
 *
 * When using a central dealer, SecretShares are distributed to participants,
 * who then perform verification, before deriving KeyPackages, which they
 * store to later use during signing.
 */
export class KeyPackage<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  /** Denotes the participant identifier each secret share key package is owned by */
  readonly identifier: Identifier<C>;
  /** This participant's signing share. This is secret. */
  readonly signingShare: SigningShare<C>;
  /** This participant's public key */
  readonly verifyingShare: VerifyingShare<C>;
  /** The public verifying key that represents the entire group */
  readonly verifyingKey: C["Element"];
  /** The minimum number of signers */
  readonly minSigners: number;

  /**
   * Create a new KeyPackage instance.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param identifier - Participant identifier
   * @param signingShare - The signing share
   * @param verifyingShare - The verifying share
   * @param verifyingKey - The group verifying key element
   * @param minSigners - Minimum number of signers
   */
  constructor(
    ciphersuite: C,
    identifier: Identifier<C>,
    signingShare: SigningShare<C>,
    verifyingShare: VerifyingShare<C>,
    verifyingKey: C["Element"],
    minSigners: number,
  ) {
    this.ciphersuite = ciphersuite;
    this.identifier = identifier;
    this.signingShare = signingShare;
    this.verifyingShare = verifyingShare;
    this.verifyingKey = verifyingKey;
    this.minSigners = minSigners;
  }

  /**
   * Check equality with another KeyPackage.
   *
   * @param other - The other KeyPackage
   * @returns True if equal
   */
  equals(other: KeyPackage<C>): boolean {
    return (
      this.identifier.equals(other.identifier) &&
      this.signingShare.equals(other.signingShare) &&
      this.verifyingShare.equals(other.verifyingShare) &&
      this.ciphersuite.elementsEqual(this.verifyingKey, other.verifyingKey) &&
      this.minSigners === other.minSigners
    );
  }
}

/**
 * Public data that contains all the signers' verifying shares as well as the
 * group verifying key.
 *
 * Used for verification purposes before publishing a signature.
 */
export class PublicKeyPackage<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  /** The verifying shares for all participants. Used to validate signature shares they generate. */
  readonly verifyingShares: Map<string, VerifyingShare<C>>;
  /** The joint public key for the entire group */
  readonly verifyingKey: C["Element"];
  /** The minimum number of signers (threshold) required for the group. Can be undefined for legacy packages. */
  readonly minSigners: number | undefined;

  /**
   * Create a new PublicKeyPackage instance.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param verifyingShares - Map of identifier string to verifying share
   * @param verifyingKey - The group verifying key element
   * @param minSigners - Minimum number of signers (threshold)
   */
  constructor(
    ciphersuite: C,
    verifyingShares: Map<string, VerifyingShare<C>>,
    verifyingKey: C["Element"],
    minSigners?: number,
  ) {
    this.ciphersuite = ciphersuite;
    this.verifyingShares = verifyingShares;
    this.verifyingKey = verifyingKey;
    this.minSigners = minSigners;
  }

  /**
   * Computes the public key package given a list of participant identifiers
   * and a VerifiableSecretSharingCommitment. This is useful in scenarios
   * where the commitments are published somewhere and it's desirable to
   * recreate the public key package from them.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param identifiers - Set of participant identifier strings
   * @param commitment - The VSS commitment
   * @returns The computed PublicKeyPackage
   * @throws {FrostError} If computation fails
   */
  static async fromCommitment<C extends Ciphersuite>(
    ciphersuite: C,
    identifiers: Set<string>,
    commitment: VerifiableSecretSharingCommitment<C>,
  ): Promise<PublicKeyPackage<C>> {
    // Import dynamically to avoid circular dependency
    const { Identifier: Id } = (await import("./identifier")) as {
      Identifier: {
        deserialize: <T extends Ciphersuite>(cs: T, bytes: Uint8Array) => Identifier<T>;
      };
    };

    const verifyingShares = new Map<string, VerifyingShare<C>>();

    for (const idStr of identifiers) {
      const idBytes = hexToBytes(idStr);
      const id = Id.deserialize(ciphersuite, idBytes);
      const share = VerifyingShare.fromCommitment(ciphersuite, id, commitment);
      verifyingShares.set(idStr, share);
    }

    const verifyingKey = commitment.verifyingKey();

    return new PublicKeyPackage(
      ciphersuite,
      verifyingShares,
      verifyingKey,
      commitment.minSigners(),
    );
  }

  /**
   * Computes the public key package given a map of participant identifiers
   * and their VerifiableSecretSharingCommitment from a distributed key
   * generation process.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param commitments - Map of identifier string to VSS commitment
   * @returns The computed PublicKeyPackage
   * @throws {FrostError} If computation fails
   */
  static async fromDkgCommitments<C extends Ciphersuite>(
    ciphersuite: C,
    commitments: Map<string, VerifiableSecretSharingCommitment<C>>,
  ): Promise<PublicKeyPackage<C>> {
    const identifiers = new Set(commitments.keys());
    const commitmentArray = Array.from(commitments.values());
    const groupCommitment = sumCommitments(ciphersuite, commitmentArray);
    return PublicKeyPackage.fromCommitment(ciphersuite, identifiers, groupCommitment);
  }

  /**
   * Return the maximum number of signers.
   *
   * @returns The maximum number of signers
   */
  maxSigners(): number {
    return this.verifyingShares.size;
  }

  /**
   * Check equality with another PublicKeyPackage.
   *
   * @param other - The other PublicKeyPackage
   * @returns True if equal
   */
  equals(other: PublicKeyPackage<C>): boolean {
    if (!this.ciphersuite.elementsEqual(this.verifyingKey, other.verifyingKey)) {
      return false;
    }
    if (this.minSigners !== other.minSigners) {
      return false;
    }
    if (this.verifyingShares.size !== other.verifyingShares.size) {
      return false;
    }
    for (const [key, share] of this.verifyingShares) {
      const otherShare = other.verifyingShares.get(key);
      if (otherShare === undefined || !share.equals(otherShare)) {
        return false;
      }
    }
    return true;
  }
}

/**
 * Validates the number of signers.
 *
 * @param minSigners - Minimum number of signers
 * @param maxSigners - Maximum number of signers
 * @throws {FrostError} If validation fails
 */
export function validateNumOfSigners(minSigners: number, maxSigners: number): void {
  if (minSigners < 2) {
    throw FrostError.invalidMinSigners();
  }
  if (maxSigners < 2) {
    throw FrostError.invalidMaxSigners();
  }
  if (minSigners > maxSigners) {
    throw FrostError.invalidMinSigners();
  }
}

/**
 * Generate a secret polynomial to use in secret sharing, for the given
 * secret value. Also validates the given parameters.
 *
 * Returns the full vector of coefficients in little-endian order (including the
 * given secret, which is the first element) and a VerifiableSecretSharingCommitment
 * which contains commitments to those coefficients.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param secret - The secret scalar
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers
 * @param coefficients - Pre-generated coefficients (excluding the secret)
 * @returns A tuple of [coefficients, VerifiableSecretSharingCommitment]
 * @throws {FrostError} If parameters are invalid
 */
export function generateSecretPolynomial<C extends Ciphersuite>(
  ciphersuite: C,
  secret: C["Scalar"],
  maxSigners: number,
  minSigners: number,
  coefficients: C["Scalar"][],
): [C["Scalar"][], VerifiableSecretSharingCommitment<C>] {
  validateNumOfSigners(minSigners, maxSigners);

  if (coefficients.length !== minSigners - 1) {
    throw FrostError.invalidCoefficients<C>();
  }

  // Prepend the secret, which is the 0th coefficient
  const allCoefficients = [secret, ...coefficients];

  // Create the vector of commitments
  const commitments = allCoefficients.map((c) => {
    const element = ciphersuite.scalarBaseMult(c);
    return new CoefficientCommitment(ciphersuite, element);
  });

  const commitment = new VerifiableSecretSharingCommitment(ciphersuite, commitments);

  return [allCoefficients, commitment];
}

/**
 * Creates secret shares for a given secret using the given coefficients.
 *
 * This function accepts a secret from which shares are generated,
 * and a list of threshold-1 coefficients. While in FROST this secret
 * and coefficients should always be generated randomly, we allow them
 * to be specified for this internal function for testability.
 *
 * Implements `secret_share_shard` from the spec.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param secret - The secret scalar
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers
 * @param coefficients - Pre-generated coefficients (excluding the secret)
 * @param identifiers - Array of participant identifiers
 * @returns Array of SecretShares
 * @throws {FrostError} If parameters are invalid
 */
export function generateSecretShares<C extends Ciphersuite>(
  ciphersuite: C,
  secret: C["Scalar"],
  maxSigners: number,
  minSigners: number,
  coefficients: C["Scalar"][],
  identifiers: Identifier<C>[],
): SecretShare<C>[] {
  const [allCoefficients, commitment] = generateSecretPolynomial(
    ciphersuite,
    secret,
    maxSigners,
    minSigners,
    coefficients,
  );

  // Check for duplicates
  const identifierSet = new Set(identifiers.map((id) => identifierToString(id)));
  if (identifierSet.size !== identifiers.length) {
    throw FrostError.duplicatedIdentifier<C>();
  }

  const secretShares: SecretShare<C>[] = [];

  for (const id of identifiers) {
    const signingShare = SigningShare.fromCoefficients(ciphersuite, allCoefficients, id);

    secretShares.push(new SecretShare(ciphersuite, id, signingShare, commitment));
  }

  return secretShares;
}

/**
 * Recompute the secret from at least `minSigners` secret shares (inside
 * KeyPackages) using Lagrange interpolation.
 *
 * This can be used if for some reason the original key must be restored; e.g.
 * if threshold signing is not required anymore.
 *
 * This is NOT required to sign with FROST; the point of FROST is being
 * able to generate signatures only using the shares, without having to
 * reconstruct the original key.
 *
 * The caller is responsible for providing at least `minSigners` packages;
 * if less than that is provided, a different key will be returned.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param keyPackages - Array of key packages
 * @returns The reconstructed secret scalar
 * @throws {FrostError} If reconstruction fails
 */
export function reconstruct<C extends Ciphersuite>(
  ciphersuite: C,
  keyPackages: KeyPackage<C>[],
): C["Scalar"] {
  if (keyPackages.length === 0) {
    throw FrostError.incorrectNumberOfShares<C>();
  }

  // Get the minimum minSigners value from all packages
  const minSigners = Math.min(...keyPackages.map((k) => k.minSigners));

  if (keyPackages.length < minSigners) {
    throw FrostError.incorrectNumberOfShares<C>();
  }

  let secret = ciphersuite.scalarZero();

  // Collect identifiers and check for duplicates
  const identifierSet = new Set<string>();
  const identifiers: Identifier<C>[] = [];

  for (const kp of keyPackages) {
    const idStr = identifierToString(kp.identifier);
    if (identifierSet.has(idStr)) {
      throw FrostError.duplicatedIdentifier<C>();
    }
    identifierSet.add(idStr);
    identifiers.push(kp.identifier);
  }

  // Compute the Lagrange coefficients and sum up the shares
  for (const keyPackage of keyPackages) {
    const lagrangeCoefficient = computeLagrangeCoefficient(
      ciphersuite,
      identifiers,
      undefined,
      keyPackage.identifier,
    );

    // Compute y = f(0) via polynomial interpolation
    const term = ciphersuite.scalarMul(lagrangeCoefficient, keyPackage.signingShare.toScalar());
    secret = ciphersuite.scalarAdd(secret, term);
  }

  return secret;
}

/**
 * Convert an identifier to a hex string key.
 *
 * @param identifier - The identifier
 * @returns Hex string representation
 */
export function identifierToString<C extends Ciphersuite>(identifier: Identifier<C>): string {
  return bytesToHex(identifier.serialize());
}

// Note: serialize() no longer needs a ciphersuite parameter as the Identifier stores it internally

/**
 * Convert a hex string to bytes.
 *
 * @param hex - The hex string
 * @returns The byte array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to a hex string.
 *
 * @param bytes - The byte array
 * @returns The hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// DKG type aliases for convenience (re-exported from dkg.ts namespaces)
import type { round1, round2 } from "./keys/dkg";

/** Type alias for DKG Round 1 Package */
export type Round1Package<C extends Ciphersuite> = round1.Package<C>;
/** Type alias for DKG Round 2 Package */
export type Round2Package<C extends Ciphersuite> = round2.Package<C>;
/** Type alias for DKG Round 1 Secret Package */
export type Round1SecretPackage<C extends Ciphersuite> = round1.SecretPackage<C>;
/** Type alias for DKG Round 2 Secret Package */
export type Round2SecretPackage<C extends Ciphersuite> = round2.SecretPackage<C>;
/** Type alias for DKG Secret Package (Round 1) - legacy alias */
export type SecretPackage<C extends Ciphersuite> = round1.SecretPackage<C>;
