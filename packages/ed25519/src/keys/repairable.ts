/**
 * Repairable Threshold Scheme module for FROST(Ed25519, SHA-512).
 *
 * Implements the Repairable Threshold Scheme (RTS) from
 * https://eprint.iacr.org/2017/1155. The RTS is used to help a signer
 * (participant) repair their lost share. This is achieved using a subset of
 * the other signers known here as `helpers`.
 *
 * The repair procedure should be run as follows:
 *
 * - Participants need to agree somehow on who are going to be the `helpers`
 *   for the repair, and which participant is going to repair their share.
 * - Each helper runs {@link repairShareStep1}, generating a set of `delta` values
 *   to be sent to each helper (including themselves).
 * - Each helper runs {@link repairShareStep2}, passing the received `delta`
 *   values, generating a `sigma` value to be sent to the participant repairing
 *   their share.
 * - The participant repairing their share runs {@link repairShareStep3}, passing
 *   all the received `sigma` values, recovering their lost `KeyPackage`. (They
 *   will also need the `PublicKeyPackage` for this step which could be
 *   provided by any of the helpers).
 *
 * @module keys/repairable
 */

import type { Ed25519Sha512Impl } from "../index.js";
import type { Identifier, RandomSource } from "@frost/core";
import {
  type Delta as CoreDelta,
  type Sigma as CoreSigma,
  repairShareStep1 as coreRepairShareStep1,
  repairShareStep2 as coreRepairShareStep2,
  repairShareStep3 as coreRepairShareStep3,
} from "@frost/core";
import type { KeyPackage, PublicKeyPackage } from "./index.js";

// Re-use the ciphersuite type
type E = Ed25519Sha512Impl;

/**
 * A delta value which is the output of step 1 of RTS.
 */
export type Delta = CoreDelta<E>;

/**
 * A sigma value which is the output of step 2 of RTS.
 */
export type Sigma = CoreSigma<E>;

/**
 * Step 1 of RTS.
 *
 * Generates the "delta" values from the helper with `keyPackageI` to send to
 * `helpers` (which includes the helper with `keyPackageI`), to help
 * `participant` recover their share.
 *
 * Returns a Map mapping which value should be sent to which participant.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param helpers - Array of helper identifiers
 * @param keyPackageI - The helper's key package
 * @param rng - Random number generator
 * @param participant - The participant who is repairing their share
 * @returns Map of identifier string to Delta
 * @throws {FrostError} If parameters are invalid
 */
export function repairShareStep1(
  ciphersuite: E,
  helpers: Identifier<E>[],
  keyPackageI: KeyPackage,
  rng: RandomSource,
  participant: Identifier<E>,
): Map<string, Delta> {
  return coreRepairShareStep1(ciphersuite, helpers, keyPackageI, rng, participant);
}

/**
 * Step 2 of RTS.
 *
 * Generates the "sigma" value from all `deltas` received from all helpers.
 * The "sigma" value must be sent to the participant repairing their share.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param deltas - Array of Delta values received from all helpers
 * @returns The computed Sigma value
 */
export function repairShareStep2(ciphersuite: E, deltas: Delta[]): Sigma {
  return coreRepairShareStep2(ciphersuite, deltas);
}

/**
 * Step 3 of RTS.
 *
 * The participant with the given `identifier` recovers their `KeyPackage`
 * with the "sigma" values received from all helpers and the `PublicKeyPackage`
 * of the group (which can be sent by any of the helpers).
 *
 * Returns an error if the `minSigners` field is not set in the `PublicKeyPackage`.
 * This happens for `PublicKeyPackage`s created before the 3.0.0 release;
 * in that case, the user should set the `minSigners` field manually.
 *
 * @param ciphersuite - The Ed25519Sha512 ciphersuite instance
 * @param sigmas - Array of Sigma values received from all helpers
 * @param identifier - The identifier of the participant recovering their share
 * @param publicKeyPackage - The group's public key package
 * @returns The recovered KeyPackage
 * @throws {FrostError} If recovery fails or minSigners is not set
 */
export function repairShareStep3(
  ciphersuite: E,
  sigmas: Sigma[],
  identifier: Identifier<E>,
  publicKeyPackage: PublicKeyPackage,
): KeyPackage {
  return coreRepairShareStep3(ciphersuite, sigmas, identifier, publicKeyPackage);
}
