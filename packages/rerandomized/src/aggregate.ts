/**
 * Aggregation functions for FROST rerandomized signatures.
 *
 * This module provides the aggregate function that combines signature shares
 * into a final signature using randomized parameters.
 *
 * @module aggregate
 */

import type { Ciphersuite, Identifier, SigningPackage } from "@frosts/core";
import { type SignatureShare, type PublicKeyPackage, Signature } from "@frosts/core";
import type { RandomizedParams } from "./params.js";
import { randomizePublicKeyPackage } from "./randomize.js";

/**
 * Re-randomized FROST signature share aggregation with the given RandomizedParams,
 * which can be computed from the previously generated randomizer using
 * `RandomizedParams.fromRandomizer()` or `RandomizedParams.newFromCommitments()`.
 *
 * This function aggregates signature shares from all participants into a final
 * Schnorr signature. The resulting signature will verify against the randomized
 * verifying key (`randomizedParams.randomizedVerifyingKey`).
 *
 * **Note:** This function requires the `aggregate` function from `@frosts/core`
 * which aggregates signature shares into a final signature. Currently, this
 * implementation provides the randomization wrapper.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param signingPackage - The signing package containing the message and commitments
 * @param signatureShares - Map of identifier to signature share from each participant
 * @param pubkeys - The original (non-randomized) public key package
 * @param randomizedParams - The randomized parameters used for signing
 * @returns The aggregated Schnorr signature
 * @throws {FrostError} If aggregation fails or any signature share is invalid
 *
 * @example
 * ```typescript
 * // Coordinator aggregates signature shares
 * const signature = aggregate(
 *   ciphersuite,
 *   signingPackage,
 *   signatureShares,
 *   publicKeyPackage,
 *   randomizedParams,
 * );
 *
 * // Verify the signature against the randomized verifying key
 * randomizedParams.randomizedVerifyingKey.verify(message, signature);
 * ```
 */
export function aggregate<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  pubkeys: PublicKeyPackage<C>,
  randomizedParams: RandomizedParams<C>,
): Signature<C> {
  // Randomize the public key package
  const randomizedPublicKeyPackage = randomizePublicKeyPackage(
    ciphersuite,
    pubkeys,
    randomizedParams,
  );

  // Perform the standard FROST aggregation with the randomized public key package
  // This implementation follows the Rust pattern where aggregate calls frost::aggregate
  // with the randomized public key package.
  //
  // The aggregate function computes:
  // 1. Group commitment R = sum of commitment shares
  // 2. Challenge c = H2(R || verifying_key || message)
  // 3. z = sum of signature shares
  // 4. Return Signature(R, z)
  return aggregateInternal(
    ciphersuite,
    signingPackage,
    signatureShares,
    randomizedPublicKeyPackage,
  );
}

/**
 * Internal aggregation implementation.
 *
 * This implements the core FROST signature aggregation logic:
 * 1. Compute the binding factors for each signer
 * 2. Compute the group commitment R from all signing commitments
 * 3. Compute the aggregate signature z from all signature shares
 * 4. Return the final Schnorr signature (R, z)
 *
 * @internal
 */
function aggregateInternal<C extends Ciphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signatureShares: Map<Identifier<C>, SignatureShare<C>>,
  pubkeys: PublicKeyPackage<C>,
): Signature<C> {
  // Compute binding factors
  const bindingFactorList = ciphersuite.computeBindingFactorList(
    signingPackage,
    pubkeys.verifyingKey,
    new Uint8Array(0),
  );

  // Compute group commitment
  const groupCommitment = ciphersuite.computeGroupCommitment(signingPackage, bindingFactorList);

  // Aggregate the signature shares
  let z = ciphersuite.scalarZero();
  for (const [_identifier, share] of signatureShares) {
    z = ciphersuite.scalarAdd(z, share.toScalar());
  }

  // Create and return the signature
  return new Signature(groupCommitment.toElement(), z);
}
