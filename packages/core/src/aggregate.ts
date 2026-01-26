/**
 * FROST signature aggregation
 *
 * This module implements the signature aggregation functionality for the FROST protocol.
 * It takes individual signature shares from participants and combines them into
 * a complete Schnorr signature.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9591#name-signature-share-aggregation
 * @module aggregate
 */

import type { Ciphersuite, SigningPackage, BindingFactorList, GroupCommitment } from "./types";
import type { Identifier } from "./identifier";
import type { PublicKeyPackage, VerifyingShare } from "./keys";
import { type SignatureShare, InvalidSignatureShareError } from "./round2";
import { Signature } from "./signature";
import { VerifyingKey } from "./verifying_key";
import type { Challenge } from "./types";
import { FrostError } from "./error";

/**
 * The type of cheater detection to use.
 */
export enum CheaterDetection {
  /**
   * Disable cheater detection. Fast in case there are invalid shares.
   */
  Disabled = "disabled",

  /**
   * Detect the first cheater and stop. Performance will depend on where
   * the cheater's share is in the list.
   */
  FirstCheater = "first-cheater",

  /**
   * Detect all cheaters. Slower since all shares must be verified.
   * Performance will be proportional on the size of participants.
   */
  AllCheaters = "all-cheaters",
}

/**
 * Aggregates the signature shares to produce a final signature that
 * can be verified with the group public key.
 *
 * `signature_shares` maps the identifier of each participant to the
 * SignatureShare they sent. These identifiers must come from whatever
 * key generation method was used; typically from the SecretShare
 * identifier from Keygen and must represent the same set of participants
 * that are specified in the SigningPackage.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param signingPackage - The signing package containing commitments and message
 * @param signatureShares - Map of participant identifiers to their signature shares
 * @param pubkeys - The public key package with verifying shares
 * @returns The aggregated FROST signature
 * @throws {FrostError} If aggregation fails
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9591#name-signature-share-aggregation
 */
export function aggregate<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  pubkeys: PublicKeyPackage<C>,
): Signature<C> {
  return aggregateCustom(
    ciphersuite,
    signingPackage,
    signatureShares,
    pubkeys,
    CheaterDetection.FirstCheater,
  );
}

/**
 * Like `aggregate()`, but allow specifying a specific cheater detection
 * strategy. If you are disabling cheater detection, then the identifiers
 * in `signatureShares` do not need to correspond to the senders (i.e.
 * you don't need to authenticate the origin of the shares).
 *
 * @param ciphersuite - The ciphersuite to use
 * @param signingPackage - The signing package containing commitments and message
 * @param signatureShares - Map of participant identifiers to their signature shares
 * @param pubkeys - The public key package with verifying shares
 * @param cheaterDetection - The cheater detection strategy to use
 * @returns The aggregated FROST signature
 * @throws {FrostError} If aggregation fails
 * @throws {InvalidSignatureShareError} If cheater detection finds invalid shares
 */
export function aggregateCustom<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  pubkeys: PublicKeyPackage<C>,
  cheaterDetection: CheaterDetection,
): Signature<C> {
  // Check if signing_package.signing_commitments and signature_shares have
  // the same set of identifiers, and if they are all in pubkeys.verifying_shares.
  if (signingPackage.signingCommitments.size !== signatureShares.size) {
    throw FrostError.unknownIdentifier<C>();
  }

  // Validate all identifiers match
  for (const [identifier] of signingPackage.signingCommitments) {
    const idKey = serializeIdentifier(identifier as Identifier<C>);
    const hasSignatureShare = hasIdentifierInMap(signatureShares, identifier as Identifier<C>);

    if (!hasSignatureShare) {
      throw FrostError.unknownIdentifier<C>();
    }

    if (cheaterDetection !== CheaterDetection.Disabled) {
      if (!pubkeys.verifyingShares.has(idKey)) {
        throw FrostError.unknownIdentifier<C>();
      }
    }
  }

  // Get the verifying key from pubkeys
  const verifyingKey = VerifyingKey.create(ciphersuite, pubkeys.verifyingKey);

  // Encodes the signing commitment list produced in round one as part of generating
  // BindingFactor, the binding factor.
  const bindingFactorList = ciphersuite.computeBindingFactorList(
    signingPackage,
    verifyingKey.toElement(),
    new Uint8Array(0),
  );

  // Compute the group commitment from signing commitments produced in round one.
  const groupCommitment = ciphersuite.computeGroupCommitment(signingPackage, bindingFactorList);

  // The aggregation of the signature shares by summing them up, resulting in
  // a plain Schnorr signature.
  //
  // Implements `aggregate` from the spec.
  //
  // https://datatracker.ietf.org/doc/html/rfc9591#name-signature-share-aggregation
  let z = ciphersuite.scalarZero();

  for (const signatureShare of signatureShares.values()) {
    z = ciphersuite.scalarAdd(z, signatureShare.toScalar());
  }

  const signature = new Signature<C>(groupCommitment.toElement(), z);

  // Verify the aggregate signature
  let verificationResult: Error | null = null;
  try {
    verifyingKey.verify(signingPackage.message, signature);
  } catch (e) {
    verificationResult = e as Error;
  }

  // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
  // This approach is more efficient since we don't need to verify all shares
  // if the aggregate signature is valid (which should be the common case).
  switch (cheaterDetection) {
    case CheaterDetection.Disabled:
      if (verificationResult !== null) {
        throw verificationResult;
      }
      break;

    case CheaterDetection.FirstCheater:
    case CheaterDetection.AllCheaters:
      if (verificationResult !== null) {
        detectCheater(
          ciphersuite,
          groupCommitment,
          pubkeys,
          signingPackage,
          signatureShares,
          bindingFactorList,
          cheaterDetection,
        );
      }
      break;
  }

  return signature;
}

/**
 * Optional cheater detection feature.
 * Each share is verified to find the cheater.
 * @internal
 */
function detectCheater<C extends Ciphersuite>(
  ciphersuite: C,
  groupCommitment: GroupCommitment<C>,
  pubkeys: PublicKeyPackage<C>,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  bindingFactorList: BindingFactorList<C>,
  cheaterDetection: CheaterDetection,
): void {
  // Compute the per-message challenge.
  const verifyingKey = VerifyingKey.create(ciphersuite, pubkeys.verifyingKey);
  const challenge = ciphersuite.challenge(
    groupCommitment.toElement(),
    verifyingKey.toElement(),
    signingPackage.message,
  ) as ReturnType<C["challenge"]>;

  const allCulprits: Identifier<C>[] = [];

  // Verify the signature shares.
  for (const [identifier, signatureShare] of signatureShares) {
    const idKey = serializeIdentifier(identifier);

    // Look up the public key for this signer
    const verifyingShare = pubkeys.verifyingShares.get(idKey);
    if (verifyingShare === undefined) {
      throw FrostError.unknownIdentifier<C>();
    }

    try {
      verifySignatureSharePrecomputed(
        ciphersuite,
        identifier,
        signingPackage,
        bindingFactorList,
        groupCommitment,
        signatureShare,
        verifyingShare,
        challenge,
        verifyingKey.toElement(),
      );
    } catch (e) {
      if (e instanceof InvalidSignatureShareError) {
        allCulprits.push(...(e.culprits as Identifier<C>[]));
        if (cheaterDetection === CheaterDetection.FirstCheater) {
          break;
        }
      } else {
        throw e;
      }
    }
  }

  if (allCulprits.length > 0) {
    throw new InvalidSignatureShareError(allCulprits);
  }

  // We should never reach here; but we throw an error to be safe.
  throw FrostError.invalidSignature<C>();
}

/**
 * Similar to verifySignatureShare() but using a precomputed
 * binding_factor_list and challenge.
 * @internal
 */
function verifySignatureSharePrecomputed<C extends Ciphersuite>(
  ciphersuite: C,
  signatureShareIdentifier: Identifier<C>,
  signingPackage: SigningPackage<C>,
  bindingFactorList: BindingFactorList<C>,
  groupCommitment: GroupCommitment<C>,
  signatureShare: SignatureShare<C>,
  verifyingShare: VerifyingShare<C>,
  challenge: Challenge<C>,
  groupVerifyingKey?: C["Element"],
): void {
  // Compute the Lagrange coefficient for this participant
  const lambdaI = ciphersuite.deriveInterpolatingValue(signatureShareIdentifier, signingPackage);

  // Get the binding factor for this participant
  const bindingFactor = bindingFactorList.get(signatureShareIdentifier);
  if (bindingFactor === undefined) {
    throw FrostError.unknownIdentifier<C>();
  }

  // Get the signing commitment for this participant
  const signingCommitment = signingPackage.signingCommitments.get(signatureShareIdentifier);
  if (signingCommitment === undefined) {
    throw FrostError.unknownIdentifier<C>();
  }

  // Compute R_share = hiding + binding * rho
  const bindingTimesRho = ciphersuite.elementMul(
    signingCommitment.binding.toElement(),
    bindingFactor.toScalar(),
  );
  const rShareElement = ciphersuite.elementAdd(
    signingCommitment.hiding.toElement(),
    bindingTimesRho,
  );

  // Create a GroupCommitmentShare-like object
  const groupCommitmentShare = {
    toElement: () => rShareElement,
  };

  // Verify the signature share
  // If ciphersuite provides custom verification, use it
  if (ciphersuite.verifyShare !== undefined) {
    ciphersuite.verifyShare(
      groupCommitment,
      signatureShare,
      signatureShareIdentifier,
      groupCommitmentShare,
      verifyingShare,
      lambdaI,
      challenge,
      groupVerifyingKey,
    );
    return;
  }

  // Default verification: g^z_i == R_i + Y_i * c * lambda_i
  signatureShare.verify(
    signatureShareIdentifier,
    groupCommitmentShare as Parameters<typeof signatureShare.verify>[1],
    verifyingShare,
    lambdaI,
    challenge,
  );
}

/**
 * Verify a signature share for the given participant.
 *
 * This is not required for regular FROST usage but might be useful in certain
 * situations where it is desired to verify each individual signature share
 * before aggregating the signature.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The participant's identifier
 * @param verifyingShare - The participant's verifying share
 * @param signatureShare - The signature share to verify
 * @param signingPackage - The signing package
 * @param verifyingKey - The group verifying key
 * @throws {InvalidSignatureShareError} If the signature share is invalid
 */
export function verifySignatureShare<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  verifyingShare: VerifyingShare<C>,
  signatureShare: SignatureShare<C>,
  signingPackage: SigningPackage<C>,
  verifyingKey: VerifyingKey<C>,
): void {
  // Create "dummy" containers to reuse the verification logic
  const signatureShares = new Map<Identifier<C>, SignatureShare<C>>();
  signatureShares.set(identifier, signatureShare);

  const idKey = serializeIdentifier(identifier);
  const verifyingShares = new Map<string, VerifyingShare<C>>();
  verifyingShares.set(idKey, verifyingShare);

  // Compute binding factors
  const bindingFactorList = ciphersuite.computeBindingFactorList(
    signingPackage,
    verifyingKey.toElement(),
    new Uint8Array(0),
  );

  // Compute the group commitment
  const groupCommitment = ciphersuite.computeGroupCommitment(signingPackage, bindingFactorList);

  // Compute the per-message challenge
  const challenge: Challenge<C> = ciphersuite.challenge(
    groupCommitment.toElement(),
    verifyingKey.toElement(),
    signingPackage.message,
  );

  // Verify the signature share
  verifySignatureSharePrecomputed(
    ciphersuite,
    identifier,
    signingPackage,
    bindingFactorList,
    groupCommitment,
    signatureShare,
    verifyingShare,
    challenge,
    verifyingKey.toElement(),
  );
}

// Helper function to serialize an identifier to a hex string key
function serializeIdentifier<C extends Ciphersuite>(identifier: Identifier<C>): string {
  const bytes = identifier.serialize();
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Helper function to check if a Map contains an identifier
function hasIdentifierInMap<C extends Ciphersuite, V>(
  map: Map<Identifier<C>, V>,
  identifier: Identifier<C>,
): boolean {
  const idKey = serializeIdentifier(identifier);
  for (const [key] of map) {
    if (serializeIdentifier(key) === idKey) {
      return true;
    }
  }
  return false;
}
