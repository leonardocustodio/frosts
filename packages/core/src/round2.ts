/**
 * FROST Round 2 functionality and types, for signature share generation
 *
 * This module implements the second round of the FROST signing protocol,
 * where participants compute their signature shares.
 *
 * @module round2
 */

import type { Ciphersuite } from "./ciphersuite";
import type { KeyPackage, VerifyingShare } from "./keys";
import type { Identifier } from "./identifier";
import type {
  Challenge,
  BindingFactor,
  SigningPackage,
  GroupCommitment,
  BindingFactorList,
} from "./types";
import type { SigningNonces, GroupCommitmentShare } from "./round1";

/**
 * A participant's signature share, which the coordinator will aggregate with all other signer's
 * shares into the joint signature.
 */
export class SignatureShare<C extends Ciphersuite> {
  /** This participant's signature over the message */
  private readonly share: C["Scalar"];

  /** The ciphersuite instance */
  private readonly ciphersuite: C;

  /**
   * Create a SignatureShare from a scalar.
   * @internal
   */
  private constructor(ciphersuite: C, share: C["Scalar"]) {
    this.ciphersuite = ciphersuite;
    this.share = share;
  }

  /**
   * Create a new SignatureShare from a scalar.
   * @internal
   */
  static fromScalar<C extends Ciphersuite>(ciphersuite: C, scalar: C["Scalar"]): SignatureShare<C> {
    return new SignatureShare(ciphersuite, scalar);
  }

  /**
   * Convert to the underlying scalar value.
   * @internal
   */
  toScalar(): C["Scalar"] {
    return this.share;
  }

  /**
   * Deserialize a SignatureShare from bytes.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param bytes - The serialized share bytes
   * @returns The deserialized signature share
   * @throws Error if deserialization fails
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): SignatureShare<C> {
    const scalar = ciphersuite.deserializeScalar(bytes);
    return new SignatureShare(ciphersuite, scalar);
  }

  /**
   * Serialize the SignatureShare to bytes.
   *
   * @returns The serialized share bytes
   */
  serialize(): Uint8Array {
    return this.ciphersuite.serializeScalar(this.share);
  }

  /**
   * Tests if a signature share issued by a participant is valid before
   * aggregating it into a final joint signature to publish.
   *
   * This is the final step of `verify_signature_share` from the spec.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#name-signature-share-aggregation
   *
   * @param identifier - The participant's identifier
   * @param groupCommitmentShare - The participant's group commitment share
   * @param verifyingShare - The participant's verifying share (public key share)
   * @param lambdaI - The Lagrange coefficient for this participant
   * @param challenge - The signature challenge
   * @throws Error if the signature share is invalid
   * @internal
   */
  verify(
    identifier: Identifier<C>,
    groupCommitmentShare: GroupCommitmentShare<C>,
    verifyingShare: VerifyingShare<C>,
    lambdaI: C["Scalar"],
    challenge: Challenge<C>,
  ): void {
    // g^z_i == R_i + Y_i * c * lambda_i
    // where R_i is the group commitment share and Y_i is the verifying share
    const lhs = this.ciphersuite.scalarBaseMult(this.share);

    // challenge.0 * lambda_i
    const challengeLambda = this.ciphersuite.scalarMul(challenge.toScalar(), lambdaI);

    // verifying_share * challenge * lambda_i
    const scaledVerifyingShare = this.ciphersuite.elementMul(
      verifyingShare.toElement(),
      challengeLambda,
    );

    // R_i + (Y_i * c * lambda_i)
    const rhs = this.ciphersuite.elementAdd(groupCommitmentShare.toElement(), scaledVerifyingShare);

    if (!this.ciphersuite.elementsEqual(lhs, rhs)) {
      throw new InvalidSignatureShareError([identifier]);
    }
  }

  /**
   * Returns a string representation of this SignatureShare.
   */
  toString(): string {
    return `SignatureShare(${bytesToHex(this.serialize())})`;
  }

  /**
   * Check equality with another SignatureShare.
   *
   * @param other - The other SignatureShare to compare
   * @returns true if the shares are equal
   */
  equals(other: SignatureShare<C>): boolean {
    return this.ciphersuite.scalarsEqual(this.share, other.share);
  }

  /**
   * Clone this SignatureShare.
   *
   * @returns A new SignatureShare with the same value
   */
  clone(): SignatureShare<C> {
    return new SignatureShare(this.ciphersuite, this.share);
  }
}

/**
 * Error thrown when a signature share is invalid.
 */
export class InvalidSignatureShareError<C extends Ciphersuite> extends Error {
  /** The identifiers of the culprits who provided invalid shares */
  readonly culprits: Identifier<C>[];

  constructor(culprits: Identifier<C>[]) {
    super(
      `Invalid signature share from participants: ${culprits.map((c) => c.toString()).join(", ")}`,
    );
    this.name = "InvalidSignatureShareError";
    this.culprits = culprits;
  }
}

/**
 * Compute the signature share for a signing operation.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param signerNonces - The signer's nonces generated in round 1
 * @param bindingFactor - The binding factor for this signer
 * @param lambdaI - The Lagrange coefficient for this signer
 * @param keyPackage - The signer's key package
 * @param challenge - The per-message challenge
 * @returns The computed signature share
 * @internal
 */
export function computeSignatureShare<C extends Ciphersuite>(
  ciphersuite: C,
  signerNonces: SigningNonces<C>,
  bindingFactor: BindingFactor<C>,
  lambdaI: C["Scalar"],
  keyPackage: KeyPackage<C>,
  challenge: Challenge<C>,
): SignatureShare<C> {
  // z_share = hiding + (binding * rho) + (lambda_i * signing_share * c)
  //
  // where:
  //   hiding = signer_nonces.hiding
  //   binding = signer_nonces.binding
  //   rho = binding_factor
  //   lambda_i = Lagrange coefficient
  //   signing_share = key_package.signing_share
  //   c = challenge

  // binding * rho
  const bindingTimesRho = ciphersuite.scalarMul(
    signerNonces.binding.toScalar(),
    bindingFactor.toScalar(),
  );

  // lambda_i * signing_share
  const lambdaTimesShare = ciphersuite.scalarMul(lambdaI, keyPackage.signingShare.toScalar());

  // lambda_i * signing_share * c
  const lambdaShareChallenge = ciphersuite.scalarMul(lambdaTimesShare, challenge.toScalar());

  // hiding + (binding * rho)
  const hidingPlusBinding = ciphersuite.scalarAdd(signerNonces.hiding.toScalar(), bindingTimesRho);

  // hiding + (binding * rho) + (lambda_i * signing_share * c)
  const zShare = ciphersuite.scalarAdd(hidingPlusBinding, lambdaShareChallenge);

  return SignatureShare.fromScalar(ciphersuite, zShare);
}

/**
 * Performed once by each participant selected for the signing operation.
 *
 * Implements `sign` from the spec.
 *
 * Receives the message to be signed and a set of signing commitments and a set
 * of randomizing commitments to be used in that signing operation, including
 * that for this participant.
 *
 * Assumes the participant has already determined which nonce corresponds with
 * the commitment that was assigned by the coordinator in the SigningPackage.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9591#name-round-two-signature-share-g
 *
 * @param ciphersuite - The ciphersuite to use
 * @param signingPackage - The signing package from the coordinator
 * @param signerNonces - The signer's nonces generated in round 1
 * @param keyPackage - The signer's key package containing their secret share
 * @returns The signature share
 * @throws Error if the number of commitments is insufficient
 * @throws Error if the signer's commitment is not found in the signing package
 * @throws Error if the signer's commitment doesn't match
 */
export function sign<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signerNonces: SigningNonces<C>,
  keyPackage: KeyPackage<C>,
): SignatureShare<C> {
  // Validate we have enough commitments
  if (signingPackage.signingCommitments.size < keyPackage.minSigners) {
    throw new IncorrectNumberOfCommitmentsError(
      signingPackage.signingCommitments.size,
      keyPackage.minSigners,
    );
  }

  // Validate the signer's commitment is present in the signing package
  const commitment = signingPackage.signingCommitments.get(keyPackage.identifier);
  if (commitment === undefined) {
    throw new MissingCommitmentError(keyPackage.identifier);
  }

  // Validate if the signer's commitment matches what was generated in round 1
  if (!signerNonces.commitments.equals(commitment)) {
    throw new IncorrectCommitmentError();
  }

  // Apply any ciphersuite-specific pre-processing
  const preSignResult = ciphersuite.preSign?.(signingPackage, signerNonces, keyPackage);
  const processedSigningPackage = preSignResult?.signingPackage ?? signingPackage;
  const processedSignerNonces = preSignResult?.signerNonces ?? signerNonces;
  const processedKeyPackage = preSignResult?.keyPackage ?? keyPackage;

  // Compute binding factors
  // Encodes the signing commitment list produced in round one as part of generating
  // BindingFactor, the binding factor.
  const bindingFactorList = computeBindingFactorList(
    ciphersuite,
    processedSigningPackage,
    processedKeyPackage.verifyingKey,
    new Uint8Array(0),
  );

  const bindingFactor = bindingFactorList.get(processedKeyPackage.identifier);
  if (bindingFactor === undefined) {
    throw new UnknownIdentifierError(processedKeyPackage.identifier as Identifier<C>);
  }

  // Apply any ciphersuite-specific pre-commitment processing
  const preCommitResult = ciphersuite.preCommitmentSign?.(
    processedSigningPackage,
    processedSignerNonces,
    bindingFactorList,
  );
  const finalSigningPackage = preCommitResult?.signingPackage ?? processedSigningPackage;
  const finalSignerNonces = preCommitResult?.signerNonces ?? processedSignerNonces;

  // Compute the group commitment from signing commitments produced in round one
  const groupCommitment = computeGroupCommitment(
    ciphersuite,
    finalSigningPackage,
    bindingFactorList,
  );

  // Compute Lagrange coefficient
  const lambdaI = deriveInterpolatingValue(
    ciphersuite,
    processedKeyPackage.identifier as Identifier<C>,
    finalSigningPackage,
  );

  // Compute the per-message challenge
  const challenge = ciphersuite.challenge(
    groupCommitment.toElement(),
    processedKeyPackage.verifyingKey,
    finalSigningPackage.message,
  );

  // Compute the Schnorr signature share
  const signatureShare =
    ciphersuite.computeSignatureShare?.(
      groupCommitment,
      finalSignerNonces,
      bindingFactor,
      lambdaI,
      processedKeyPackage,
      challenge,
    ) ??
    computeSignatureShare(
      ciphersuite,
      finalSignerNonces as SigningNonces<C>,
      bindingFactor,
      lambdaI,
      processedKeyPackage as KeyPackage<C>,
      challenge,
    );

  return signatureShare as SignatureShare<C>;
}

/**
 * Error thrown when the number of commitments is incorrect.
 */
export class IncorrectNumberOfCommitmentsError extends Error {
  readonly actual: number;
  readonly expected: number;

  constructor(actual: number, expected: number) {
    super(`Incorrect number of commitments: got ${actual}, need at least ${expected}`);
    this.name = "IncorrectNumberOfCommitmentsError";
    this.actual = actual;
    this.expected = expected;
  }
}

/**
 * Error thrown when a participant's commitment is missing from the signing package.
 */
export class MissingCommitmentError<C extends Ciphersuite> extends Error {
  readonly identifier: Identifier<C>;

  constructor(identifier: Identifier<C>) {
    super(`Missing commitment for participant ${identifier.toString()}`);
    this.name = "MissingCommitmentError";
    this.identifier = identifier;
  }
}

/**
 * Error thrown when a participant's commitment doesn't match their nonces.
 */
export class IncorrectCommitmentError extends Error {
  constructor() {
    super("Signer's commitment doesn't match the generated nonces");
    this.name = "IncorrectCommitmentError";
  }
}

/**
 * Error thrown when an identifier is not found.
 */
export class UnknownIdentifierError<C extends Ciphersuite> extends Error {
  readonly identifier: Identifier<C>;

  constructor(identifier: Identifier<C>) {
    super(`Unknown identifier: ${identifier.toString()}`);
    this.name = "UnknownIdentifierError";
    this.identifier = identifier;
  }
}

// The following are internal helper types and functions that are referenced by the sign function.
// In a complete implementation, these would be imported from other modules.

/**
 * Compute binding factors for all participants.
 * @internal
 */
function computeBindingFactorList<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  verifyingKey: C["VerifyingKey"],
  additionalPrefix: Uint8Array,
): BindingFactorList<C> {
  // This is a placeholder - actual implementation would be in a separate module
  // and imported here. The full implementation computes:
  // 1. Serialize verifying key
  // 2. Hash message with H4
  // 3. Hash commitment list with H5
  // 4. For each participant, compute H1(prefix || identifier)
  return ciphersuite.computeBindingFactorList(signingPackage, verifyingKey, additionalPrefix);
}

/**
 * Compute the group commitment from all signing commitments.
 * @internal
 */
function computeGroupCommitment<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  bindingFactorList: BindingFactorList<C>,
): GroupCommitment<C> {
  // This is a placeholder - actual implementation would be in a separate module
  return ciphersuite.computeGroupCommitment(signingPackage, bindingFactorList);
}

/**
 * Compute the Lagrange coefficient for a participant.
 * @internal
 */
function deriveInterpolatingValue<C extends Ciphersuite>(
  ciphersuite: C,
  signerId: Identifier<C>,
  signingPackage: SigningPackage<C>,
): C["Scalar"] {
  // This is a placeholder - actual implementation would be in a separate module
  return ciphersuite.deriveInterpolatingValue(signerId, signingPackage);
}

// Helper function to convert bytes to hex string
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
