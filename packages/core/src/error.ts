/**
 * FROST Error types
 * @module
 */

import type { Ciphersuite, IdentifierLike } from "./types";

/**
 * An error related to a scalar Field.
 */
export enum FieldErrorType {
  /** The encoding of a group scalar was malformed. */
  MalformedScalar = "MalformedScalar",
  /** This scalar MUST NOT be zero. */
  InvalidZeroScalar = "InvalidZeroScalar",
}

/**
 * An error related to a scalar Field.
 */
export class FieldError extends Error {
  public readonly type: FieldErrorType;

  constructor(type: FieldErrorType) {
    const messages: Record<FieldErrorType, string> = {
      [FieldErrorType.MalformedScalar]: "Malformed scalar encoding.",
      [FieldErrorType.InvalidZeroScalar]: "Invalid for this scalar to be zero.",
    };
    super(messages[type]);
    this.name = "FieldError";
    this.type = type;
  }

  /** Create a MalformedScalar error */
  static malformedScalar(): FieldError {
    return new FieldError(FieldErrorType.MalformedScalar);
  }

  /** Create an InvalidZeroScalar error */
  static invalidZeroScalar(): FieldError {
    return new FieldError(FieldErrorType.InvalidZeroScalar);
  }
}

/**
 * An error related to a Group (usually an elliptic curve or constructed from one) or one of its Elements.
 */
export enum GroupErrorType {
  /** The encoding of a group element was malformed. */
  MalformedElement = "MalformedElement",
  /** This element MUST NOT be the identity. */
  InvalidIdentityElement = "InvalidIdentityElement",
  /** This element MUST have (large) prime order. */
  InvalidNonPrimeOrderElement = "InvalidNonPrimeOrderElement",
}

/**
 * An error related to a Group (usually an elliptic curve or constructed from one) or one of its Elements.
 */
export class GroupError extends Error {
  public readonly type: GroupErrorType;

  constructor(type: GroupErrorType) {
    const messages: Record<GroupErrorType, string> = {
      [GroupErrorType.MalformedElement]: "Malformed group element encoding.",
      [GroupErrorType.InvalidIdentityElement]: "Invalid for this element to be the identity.",
      [GroupErrorType.InvalidNonPrimeOrderElement]:
        "Invalid for this element to not have large prime order.",
    };
    super(messages[type]);
    this.name = "GroupError";
    this.type = type;
  }

  /** Create a MalformedElement error */
  static malformedElement(): GroupError {
    return new GroupError(GroupErrorType.MalformedElement);
  }

  /** Create an InvalidIdentityElement error */
  static invalidIdentityElement(): GroupError {
    return new GroupError(GroupErrorType.InvalidIdentityElement);
  }

  /** Create an InvalidNonPrimeOrderElement error */
  static invalidNonPrimeOrderElement(): GroupError {
    return new GroupError(GroupErrorType.InvalidNonPrimeOrderElement);
  }
}

/**
 * Error types for FROST operations.
 */
export enum FrostErrorType {
  /** min_signers is invalid */
  InvalidMinSigners = "InvalidMinSigners",
  /** max_signers is invalid */
  InvalidMaxSigners = "InvalidMaxSigners",
  /** coefficients must have min_signers-1 elements */
  InvalidCoefficients = "InvalidCoefficients",
  /** This identifier is unserializable. */
  MalformedIdentifier = "MalformedIdentifier",
  /** This identifier is duplicated. */
  DuplicatedIdentifier = "DuplicatedIdentifier",
  /** This identifier does not belong to a participant in the signing process. */
  UnknownIdentifier = "UnknownIdentifier",
  /** Incorrect number of identifiers. */
  IncorrectNumberOfIdentifiers = "IncorrectNumberOfIdentifiers",
  /** The encoding of a signing key was malformed. */
  MalformedSigningKey = "MalformedSigningKey",
  /** The encoding of a verifying key was malformed. */
  MalformedVerifyingKey = "MalformedVerifyingKey",
  /** The encoding of a signature was malformed. */
  MalformedSignature = "MalformedSignature",
  /** Signature verification failed. */
  InvalidSignature = "InvalidSignature",
  /** Duplicated shares provided */
  DuplicatedShares = "DuplicatedShares",
  /** Incorrect number of shares. */
  IncorrectNumberOfShares = "IncorrectNumberOfShares",
  /** Commitment equals the identity */
  IdentityCommitment = "IdentityCommitment",
  /** The participant's commitment is missing from the Signing Package */
  MissingCommitment = "MissingCommitment",
  /** The participant's commitment is incorrect */
  IncorrectCommitment = "IncorrectCommitment",
  /** Incorrect number of commitments. */
  IncorrectNumberOfCommitments = "IncorrectNumberOfCommitments",
  /** Signature share verification failed. */
  InvalidSignatureShare = "InvalidSignatureShare",
  /** Secret share verification failed. */
  InvalidSecretShare = "InvalidSecretShare",
  /** Round 1 package not found for Round 2 participant. */
  PackageNotFound = "PackageNotFound",
  /** Incorrect number of packages. */
  IncorrectNumberOfPackages = "IncorrectNumberOfPackages",
  /** The incorrect package was specified. */
  IncorrectPackage = "IncorrectPackage",
  /** The ciphersuite does not support DKG. */
  DKGNotSupported = "DKGNotSupported",
  /** The proof of knowledge is not valid. */
  InvalidProofOfKnowledge = "InvalidProofOfKnowledge",
  /** Error in scalar Field. */
  FieldError = "FieldError",
  /** Error in elliptic curve Group. */
  GroupError = "GroupError",
  /** Error in coefficient commitment deserialization. */
  InvalidCoefficient = "InvalidCoefficient",
  /** The ciphersuite does not support deriving identifiers from strings. */
  IdentifierDerivationNotSupported = "IdentifierDerivationNotSupported",
  /** Error serializing value. */
  SerializationError = "SerializationError",
  /** Error deserializing value. */
  DeserializationError = "DeserializationError",
}

/**
 * Error messages for each FROST error type.
 */
const FROST_ERROR_MESSAGES: Record<FrostErrorType, string> = {
  [FrostErrorType.InvalidMinSigners]:
    "min_signers must be at least 2 and not larger than max_signers",
  [FrostErrorType.InvalidMaxSigners]: "max_signers must be at least 2",
  [FrostErrorType.InvalidCoefficients]: "coefficients must have min_signers-1 elements",
  [FrostErrorType.MalformedIdentifier]: "Malformed identifier is unserializable.",
  [FrostErrorType.DuplicatedIdentifier]: "Duplicated identifier.",
  [FrostErrorType.UnknownIdentifier]: "Unknown identifier.",
  [FrostErrorType.IncorrectNumberOfIdentifiers]: "Incorrect number of identifiers.",
  [FrostErrorType.MalformedSigningKey]: "Malformed signing key encoding.",
  [FrostErrorType.MalformedVerifyingKey]: "Malformed verifying key encoding.",
  [FrostErrorType.MalformedSignature]: "Malformed signature encoding.",
  [FrostErrorType.InvalidSignature]: "Invalid signature.",
  [FrostErrorType.DuplicatedShares]: "Duplicated shares provided.",
  [FrostErrorType.IncorrectNumberOfShares]: "Incorrect number of shares.",
  [FrostErrorType.IdentityCommitment]: "Commitment equals the identity.",
  [FrostErrorType.MissingCommitment]:
    "The Signing Package must contain the participant's Commitment.",
  [FrostErrorType.IncorrectCommitment]: "The participant's commitment is incorrect.",
  [FrostErrorType.IncorrectNumberOfCommitments]: "Incorrect number of commitments.",
  [FrostErrorType.InvalidSignatureShare]: "Invalid signature share.",
  [FrostErrorType.InvalidSecretShare]: "Invalid secret share.",
  [FrostErrorType.PackageNotFound]: "Round 1 package not found for Round 2 participant.",
  [FrostErrorType.IncorrectNumberOfPackages]: "Incorrect number of packages.",
  [FrostErrorType.IncorrectPackage]: "The incorrect package was specified.",
  [FrostErrorType.DKGNotSupported]: "The ciphersuite does not support DKG.",
  [FrostErrorType.InvalidProofOfKnowledge]: "The proof of knowledge is not valid.",
  [FrostErrorType.FieldError]: "Error in scalar Field.",
  [FrostErrorType.GroupError]: "Error in elliptic curve Group.",
  [FrostErrorType.InvalidCoefficient]: "Invalid coefficient",
  [FrostErrorType.IdentifierDerivationNotSupported]:
    "The ciphersuite does not support deriving identifiers from strings.",
  [FrostErrorType.SerializationError]: "Error serializing value.",
  [FrostErrorType.DeserializationError]: "Error deserializing value.",
};

/**
 * An error related to FROST.
 *
 * @typeParam C - The ciphersuite type
 */
export class FrostError<C extends Ciphersuite> extends Error {
  public readonly type: FrostErrorType;

  /**
   * The identifier of signers whose share validation failed.
   * Only populated for InvalidSignatureShare errors.
   */
  public readonly culpritIdentifiers: IdentifierLike<C>[];

  /**
   * The identifier of the signer whose secret share or proof of knowledge validation failed.
   * Only populated for InvalidSecretShare and InvalidProofOfKnowledge errors.
   */
  public readonly culpritIdentifier: IdentifierLike<C> | null;

  /**
   * The underlying FieldError, if this error wraps one.
   */
  public readonly fieldError: FieldError | null;

  /**
   * The underlying GroupError, if this error wraps one.
   */
  public readonly groupError: GroupError | null;

  private constructor(
    type: FrostErrorType,
    options?: {
      culprits?: IdentifierLike<C>[];
      culprit?: IdentifierLike<C> | null;
      fieldError?: FieldError;
      groupError?: GroupError;
    },
  ) {
    super(FROST_ERROR_MESSAGES[type]);
    this.name = "FrostError";
    this.type = type;
    this.culpritIdentifiers = options?.culprits ?? [];
    this.culpritIdentifier = options?.culprit ?? null;
    this.fieldError = options?.fieldError ?? null;
    this.groupError = options?.groupError ?? null;
  }

  /**
   * Return the identifiers of the participants that caused the error.
   * Returns an empty array if not applicable for the error.
   *
   * This can be used to penalize participants that do not follow the
   * protocol correctly, e.g. removing them from further signings.
   */
  culprits(): IdentifierLike<C>[] {
    switch (this.type) {
      case FrostErrorType.InvalidSignatureShare:
        return [...this.culpritIdentifiers];
      case FrostErrorType.InvalidProofOfKnowledge:
        return this.culpritIdentifier !== null ? [this.culpritIdentifier] : [];
      case FrostErrorType.InvalidSecretShare:
        return this.culpritIdentifier !== null ? [this.culpritIdentifier] : [];
      case FrostErrorType.InvalidMinSigners:
      case FrostErrorType.InvalidMaxSigners:
      case FrostErrorType.InvalidCoefficients:
      case FrostErrorType.MalformedIdentifier:
      case FrostErrorType.DuplicatedIdentifier:
      case FrostErrorType.UnknownIdentifier:
      case FrostErrorType.IncorrectNumberOfIdentifiers:
      case FrostErrorType.MalformedSigningKey:
      case FrostErrorType.MalformedVerifyingKey:
      case FrostErrorType.MalformedSignature:
      case FrostErrorType.InvalidSignature:
      case FrostErrorType.DuplicatedShares:
      case FrostErrorType.IncorrectNumberOfShares:
      case FrostErrorType.IdentityCommitment:
      case FrostErrorType.MissingCommitment:
      case FrostErrorType.IncorrectCommitment:
      case FrostErrorType.IncorrectNumberOfCommitments:
      case FrostErrorType.PackageNotFound:
      case FrostErrorType.IncorrectNumberOfPackages:
      case FrostErrorType.IncorrectPackage:
      case FrostErrorType.DKGNotSupported:
      case FrostErrorType.FieldError:
      case FrostErrorType.GroupError:
      case FrostErrorType.InvalidCoefficient:
      case FrostErrorType.IdentifierDerivationNotSupported:
      case FrostErrorType.SerializationError:
      case FrostErrorType.DeserializationError:
        return [];
    }
  }

  // Static factory methods for each error type

  /** Create an InvalidMinSigners error */
  static invalidMinSigners<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidMinSigners);
  }

  /** Create an InvalidMaxSigners error */
  static invalidMaxSigners<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidMaxSigners);
  }

  /** Create an InvalidCoefficients error */
  static invalidCoefficients<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidCoefficients);
  }

  /** Create a MalformedIdentifier error */
  static malformedIdentifier<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.MalformedIdentifier);
  }

  /** Create a DuplicatedIdentifier error */
  static duplicatedIdentifier<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.DuplicatedIdentifier);
  }

  /** Create an UnknownIdentifier error */
  static unknownIdentifier<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.UnknownIdentifier);
  }

  /** Create an IncorrectNumberOfIdentifiers error */
  static incorrectNumberOfIdentifiers<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IncorrectNumberOfIdentifiers);
  }

  /** Create a MalformedSigningKey error */
  static malformedSigningKey<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.MalformedSigningKey);
  }

  /** Create a MalformedVerifyingKey error */
  static malformedVerifyingKey<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.MalformedVerifyingKey);
  }

  /** Create a MalformedSignature error */
  static malformedSignature<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.MalformedSignature);
  }

  /** Create an InvalidSignature error */
  static invalidSignature<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidSignature);
  }

  /** Create a DuplicatedShares error */
  static duplicatedShares<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.DuplicatedShares);
  }

  /** Create an IncorrectNumberOfShares error */
  static incorrectNumberOfShares<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IncorrectNumberOfShares);
  }

  /** Create an IdentityCommitment error */
  static identityCommitment<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IdentityCommitment);
  }

  /** Create a MissingCommitment error */
  static missingCommitment<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.MissingCommitment);
  }

  /** Create an IncorrectCommitment error */
  static incorrectCommitment<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IncorrectCommitment);
  }

  /** Create an IncorrectNumberOfCommitments error */
  static incorrectNumberOfCommitments<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IncorrectNumberOfCommitments);
  }

  /**
   * Create an InvalidSignatureShare error
   * @param culprits - The identifiers of the signers whose share validation failed
   */
  static invalidSignatureShare<C extends Ciphersuite>(
    culprits: IdentifierLike<C>[],
  ): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidSignatureShare, { culprits });
  }

  /**
   * Create an InvalidSecretShare error
   * @param culprit - The identifier of the signer whose secret share validation failed, if known
   */
  static invalidSecretShare<C extends Ciphersuite>(
    culprit?: IdentifierLike<C> | null,
  ): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidSecretShare, {
      culprit: culprit ?? null,
    });
  }

  /** Create a PackageNotFound error */
  static packageNotFound<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.PackageNotFound);
  }

  /** Create an IncorrectNumberOfPackages error */
  static incorrectNumberOfPackages<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IncorrectNumberOfPackages);
  }

  /** Create an IncorrectPackage error */
  static incorrectPackage<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IncorrectPackage);
  }

  /** Create a DKGNotSupported error */
  static dkgNotSupported<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.DKGNotSupported);
  }

  /**
   * Create an InvalidProofOfKnowledge error
   * @param culprit - The identifier of the signer whose proof of knowledge validation failed
   */
  static invalidProofOfKnowledge<C extends Ciphersuite>(culprit: IdentifierLike<C>): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidProofOfKnowledge, { culprit });
  }

  /**
   * Create a FrostError from a FieldError
   * @param error - The underlying FieldError
   */
  static fromFieldError<C extends Ciphersuite>(error: FieldError): FrostError<C> {
    return new FrostError(FrostErrorType.FieldError, { fieldError: error });
  }

  /**
   * Create a FrostError from a GroupError
   * @param error - The underlying GroupError
   */
  static fromGroupError<C extends Ciphersuite>(error: GroupError): FrostError<C> {
    return new FrostError(FrostErrorType.GroupError, { groupError: error });
  }

  /** Create an InvalidCoefficient error */
  static invalidCoefficient<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.InvalidCoefficient);
  }

  /** Create an IdentifierDerivationNotSupported error */
  static identifierDerivationNotSupported<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.IdentifierDerivationNotSupported);
  }

  /** Create a SerializationError */
  static serializationError<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.SerializationError);
  }

  /** Create a DeserializationError */
  static deserializationError<C extends Ciphersuite>(): FrostError<C> {
    return new FrostError(FrostErrorType.DeserializationError);
  }
}

// Re-export for convenience
export { FrostError as Error };
