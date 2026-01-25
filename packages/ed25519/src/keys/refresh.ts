/**
 * Refresh Shares module for FROST(Ed25519, SHA-512).
 *
 * Refreshing shares has two purposes:
 *
 * - Mitigate against share compromise.
 * - Remove participants from a group.
 *
 * Refer to the FROST book (https://frost.zfnd.org/frost.html#refreshing-shares)
 * for important details.
 *
 * This module supports refreshing shares using a Trusted Dealer or DKG. You
 * probably want to use the same approach as the original share generation.
 *
 * For the Trusted Dealer approach, the trusted dealer should call
 * {@link computeRefreshingShares} and send the returned refreshing shares to
 * the participants. Each participant should then call {@link refreshShare}.
 *
 * For the DKG approach, the flow is very similar to DKG itself. Each participant
 * calls {@link refreshDkgPart1}, keeps the returned secret package and sends the
 * returned package to other participants. Then each participant calls
 * {@link refreshDkgPart2} and sends the returned packages to the other
 * participants. Finally each participant calls {@link refreshDkgShares}.
 *
 * @module keys/refresh
 */

import type { Ed25519Sha512Impl } from "../index.js";
import type { Identifier, RandomSource } from "@frost/core";
import {
  computeRefreshingShares as coreComputeRefreshingShares,
  refreshShare as coreRefreshShare,
  refreshDkgPart1 as coreRefreshDkgPart1,
  refreshDkgPart2 as coreRefreshDkgPart2,
  refreshDkgShares as coreRefreshDkgShares,
} from "@frost/core";
import type { KeyPackage, PublicKeyPackage, SecretShare } from "./index.js";
import type { round1, round2 } from "./dkg.js";

// Re-use the ciphersuite type
type E = Ed25519Sha512Impl;

/**
 * Compute refreshing shares for the Trusted Dealer refresh procedure.
 *
 * - `pubKeyPackage`: the current public key package. Note: if a pre-3.0.0
 *   generated package is used, you will need to manually set the `minSigners`
 *   field with the threshold that was used in the original share generation.
 *   (You can't change the threshold when refreshing shares.)
 * - `identifiers`: The identifiers of all participants that want to refresh
 *   their shares. Must be a subset of the identifiers in `pubKeyPackage`. If
 *   not all identifiers are passed, the refresh procedure will effectively
 *   remove the missing participants. The length must be equal to or greater
 *   than the threshold of the group.
 *
 * It returns a tuple of [refreshing shares, refreshed PublicKeyPackage].
 * The refreshing shares must be sent to the participants in the same order
 * as `identifiers`.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param oldPubKeyPackage - The current public key package
 * @param identifiers - Array of participant identifiers to refresh
 * @param rng - Random number generator
 * @returns A tuple of [SecretShare[], PublicKeyPackage]
 * @throws {FrostError} If parameters are invalid
 */
export function computeRefreshingShares(
  ciphersuite: E,
  oldPubKeyPackage: PublicKeyPackage,
  identifiers: Identifier<E>[],
  rng: RandomSource,
): [SecretShare[], PublicKeyPackage] {
  return coreComputeRefreshingShares(ciphersuite, oldPubKeyPackage, identifiers, rng);
}

/**
 * Refresh a share in the Trusted Dealer refresh procedure.
 *
 * Must be called by each participant refreshing the shares, with the
 * `refreshingShare` received from the trusted dealer and the
 * `currentKeyPackage` of the participant.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param zeroShare - The refreshing share received from the dealer
 * @param currentShare - The participant's current key package
 * @returns The refreshed KeyPackage
 * @throws {FrostError} If refresh fails
 */
export function refreshShare(
  ciphersuite: E,
  zeroShare: SecretShare,
  currentShare: KeyPackage,
): KeyPackage {
  return coreRefreshShare(ciphersuite, zeroShare, currentShare);
}

/**
 * Part 1 of refresh share with DKG.
 *
 * - `identifier`: The identifier of the participant that wants to refresh
 *   their share.
 * - `maxSigners`: the number of participants that are refreshing their
 *   shares. It can be smaller than the original value, but still equal to or
 *   greater than `minSigners`.
 * - `minSigners`: the threshold needed to sign. It must be equal to the
 *   original value for the group (i.e. the refresh process can't reduce
 *   the threshold).
 *
 * It returns the SecretPackage that must be kept in memory by the participant
 * for the other steps, and the Package that must be sent to each other
 * participant in the refresh run.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param identifier - The participant's identifier
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers (threshold)
 * @param rng - Random number generator
 * @returns A tuple of [round1.SecretPackage, round1.Package]
 * @throws {FrostError} If parameters are invalid
 */
export function refreshDkgPart1(
  ciphersuite: E,
  identifier: Identifier<E>,
  maxSigners: number,
  minSigners: number,
  rng: RandomSource,
): [round1.SecretPackage, round1.Package] {
  return coreRefreshDkgPart1(ciphersuite, identifier, maxSigners, minSigners, rng);
}

/**
 * Performs the second part of the refresh procedure for the
 * participant holding the given SecretPackage, given the received
 * round1::Packages received from the other participants.
 *
 * `round1Packages` maps the identifier of each other participant to the
 * Package they sent to the current participant (the owner of
 * `secretPackage`). These identifiers must come from whatever mapping the
 * participant has between communication channels and participants, i.e. they
 * must have assurance that the Package came from the participant
 * with that identifier.
 *
 * It returns the SecretPackage that must be kept in memory by the
 * participant for the final step, and the map of Packages that
 * must be sent to each other participant who has the given identifier in the
 * map key.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param secretPackage - The round 1 secret package
 * @param round1Packages - Map of identifier to round 1 packages
 * @returns A tuple of [round2.SecretPackage, Map of round2.Package by identifier]
 * @throws {FrostError} If validation fails
 */
export function refreshDkgPart2(
  ciphersuite: E,
  secretPackage: round1.SecretPackage,
  round1Packages: Map<string, round1.Package>,
): [round2.SecretPackage, Map<string, round2.Package>] {
  return coreRefreshDkgPart2(ciphersuite, secretPackage, round1Packages);
}

/**
 * Performs the third and final part of the refresh procedure for the
 * participant holding the given SecretPackage, given the received
 * round1::Packages and round2::Packages received from the other
 * participants.
 *
 * `round1Packages` must be the same used in {@link refreshDkgPart2}.
 *
 * `round2Packages` maps the identifier of each other participant to the
 * Package they sent to the current participant (the owner of
 * `secretPackage`). These identifiers must come from whatever mapping the
 * participant has between communication channels and participants, i.e. they
 * must have assurance that the Package came from the participant
 * with that identifier.
 *
 * `oldPubKeyPackage` and `oldKeyPackage` are the old values from the
 * participant, which are being refreshed.
 *
 * It returns the refreshed KeyPackage that has the long-lived key share
 * for the participant, and the refreshed PublicKeyPackage that has public
 * information about all participants; both of which are required to compute
 * FROST signatures. Note that while the verifying (group) key of the
 * PublicKeyPackage will stay the same, the verifying shares will change.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param round2SecretPackage - The round 2 secret package
 * @param round1Packages - Map of identifier to round 1 packages
 * @param round2Packages - Map of identifier to round 2 packages
 * @param oldPubKeyPackage - The old public key package
 * @param oldKeyPackage - The old key package
 * @returns A Promise of a tuple of [KeyPackage, PublicKeyPackage]
 * @throws {FrostError} If validation fails
 */
export function refreshDkgShares(
  ciphersuite: E,
  round2SecretPackage: round2.SecretPackage,
  round1Packages: Map<string, round1.Package>,
  round2Packages: Map<string, round2.Package>,
  oldPubKeyPackage: PublicKeyPackage,
  oldKeyPackage: KeyPackage,
): Promise<[KeyPackage, PublicKeyPackage]> {
  return coreRefreshDkgShares(
    ciphersuite,
    round2SecretPackage,
    round1Packages,
    round2Packages,
    oldPubKeyPackage,
    oldKeyPackage,
  );
}
