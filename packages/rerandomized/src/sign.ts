/**
 * Signing functions for FROST rerandomized signatures.
 *
 * This module provides signing functions that incorporate rerandomization
 * into the FROST signing protocol.
 *
 * @module sign
 */

import type { Identifier, SigningPackage } from "@frost/core";
import {
  sign as frostSign,
  type SigningNonces,
  type KeyPackage,
  type SignatureShare,
  type SigningCommitments,
  VerifyingKey,
} from "@frost/core";
import type { RandomizedCiphersuite } from "./types.js";
import { RandomizedParams } from "./params.js";
import { randomizeKeyPackage } from "./randomize.js";

/**
 * Re-randomized FROST signing using the given `randomizerSeed`, which should
 * be sent from the Coordinator using a confidential channel.
 *
 * This is the recommended signing function for re-randomized FROST. The
 * Coordinator should call `RandomizedParams.newFromCommitments()` and send
 * the generated randomizer seed to all participants along with the regular
 * SigningPackage.
 *
 * @param ciphersuite - The ciphersuite to use (must support rerandomization)
 * @param signingPackage - The signing package from the coordinator
 * @param signerNonces - The signer's nonces generated in round 1
 * @param keyPackage - The signer's key package containing their secret share
 * @param randomizerSeed - The randomizer seed bytes from the coordinator
 * @returns The signature share
 * @throws {FrostError} If signing fails
 *
 * @example
 * ```typescript
 * // Coordinator side:
 * const [randomizedParams, randomizerSeed] = RandomizedParams.newFromCommitments(
 *   ciphersuite,
 *   groupVerifyingKey,
 *   signingCommitments,
 *   rng,
 * );
 * // Send randomizerSeed to participants via confidential channel
 *
 * // Participant side:
 * const signatureShare = signWithRandomizerSeed(
 *   ciphersuite,
 *   signingPackage,
 *   signerNonces,
 *   keyPackage,
 *   randomizerSeed,
 * );
 * ```
 */
export function signWithRandomizerSeed<C extends RandomizedCiphersuite>(
  ciphersuite: C,
  signingPackage: SigningPackage<C>,
  signerNonces: SigningNonces<C>,
  keyPackage: KeyPackage<C>,
  randomizerSeed: Uint8Array,
): SignatureShare<C> {
  // Get the verifying key element from the key package and create a VerifyingKey
  const verifyingKeyElement = keyPackage.verifyingKey;
  const verifyingKey = VerifyingKey.create(ciphersuite, verifyingKeyElement);

  // Extract signing commitments from the signing package
  // The signingPackage.signingCommitments is Map<unknown, SigningCommitments<C>>
  // We need to convert it to Map<Identifier<C>, SigningCommitments<C>>
  const signingCommitments = signingPackage.signingCommitments as Map<
    Identifier<C>,
    SigningCommitments<C>
  >;

  // Regenerate the randomized params from the seed and commitments
  const randomizedParams = RandomizedParams.regenerateFromSeedAndCommitments(
    ciphersuite,
    verifyingKey,
    randomizerSeed,
    signingCommitments,
  );

  // Randomize the key package
  const randomizedKeyPackage = randomizeKeyPackage(ciphersuite, keyPackage, randomizedParams);

  // Perform the signing with the randomized key package
  return frostSign(ciphersuite, signingPackage, signerNonces, randomizedKeyPackage);
}
