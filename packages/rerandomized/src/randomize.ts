/**
 * Key randomization functions for FROST rerandomized signatures.
 *
 * This module provides functions to randomize KeyPackage and PublicKeyPackage
 * for use in rerandomized FROST signing operations.
 *
 * @module randomize
 */

/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */

import type { Ciphersuite, Identifier } from "@frost/core";
import { KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare } from "@frost/core";
import type { RandomizedParams } from "./params.js";

/**
 * Randomize the given KeyPackage for usage in a re-randomized FROST signing,
 * using the given RandomizedParams.
 *
 * It's recommended to use `signWithRandomizerSeed()` directly which already
 * handles the key package randomization.
 *
 * **IMPORTANT: You MUST NOT reuse the randomized key package for more than one signing.**
 *
 * @param ciphersuite - The ciphersuite to use
 * @param keyPackage - The original key package to randomize
 * @param randomizedParams - The randomized parameters
 * @returns The randomized key package
 *
 * @example
 * ```typescript
 * const randomizedKeyPackage = randomizeKeyPackage(
 *   ciphersuite,
 *   keyPackage,
 *   randomizedParams,
 * );
 * // Use randomizedKeyPackage for ONE signing operation only
 * ```
 */
export function randomizeKeyPackage<C extends Ciphersuite>(
  ciphersuite: C,
  keyPackage: KeyPackage<C>,
  randomizedParams: RandomizedParams<C>,
): KeyPackage<C> {
  // Randomize the verifying share: verifyingShare + randomizerElement
  const verifyingShare = keyPackage.verifyingShare;
  const randomizedVerifyingShareElement = ciphersuite.elementAdd(
    verifyingShare.toElement(),
    randomizedParams.randomizerElement,
  );
  const randomizedVerifyingShare = new VerifyingShare(ciphersuite, randomizedVerifyingShareElement);

  // Randomize the signing share: signingShare + randomizer
  const signingShare = keyPackage.signingShare;
  const randomizedSigningShareScalar = ciphersuite.scalarAdd(
    signingShare.toScalar(),
    randomizedParams.randomizer.toScalar(),
  );
  const randomizedSigningShare = new SigningShare(ciphersuite, randomizedSigningShareScalar);

  // Create the randomized key package
  return new KeyPackage(
    ciphersuite,
    keyPackage.identifier as Identifier<C>,
    randomizedSigningShare,
    randomizedVerifyingShare,
    randomizedParams.randomizedVerifyingKey.toElement(),
    keyPackage.minSigners,
  );
}

/**
 * Randomize the given PublicKeyPackage for usage in a re-randomized FROST
 * aggregation, using the given RandomizedParams.
 *
 * It's recommended to use `aggregate()` directly which already handles the
 * public key package randomization.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param publicKeyPackage - The original public key package to randomize
 * @param randomizedParams - The randomized parameters
 * @returns The randomized public key package
 *
 * @example
 * ```typescript
 * const randomizedPublicKeyPackage = randomizePublicKeyPackage(
 *   ciphersuite,
 *   publicKeyPackage,
 *   randomizedParams,
 * );
 * // Use for signature aggregation
 * ```
 */
export function randomizePublicKeyPackage<C extends Ciphersuite>(
  ciphersuite: C,
  publicKeyPackage: PublicKeyPackage<C>,
  randomizedParams: RandomizedParams<C>,
): PublicKeyPackage<C> {
  // Randomize all verifying shares
  const randomizedVerifyingShares = new Map<string, VerifyingShare<C>>();

  for (const [identifier, verifyingShare] of publicKeyPackage.verifyingShares) {
    const randomizedElement = ciphersuite.elementAdd(
      verifyingShare.toElement(),
      randomizedParams.randomizerElement,
    );
    randomizedVerifyingShares.set(identifier, new VerifyingShare(ciphersuite, randomizedElement));
  }

  // Create the randomized public key package with the randomized verifying key
  return new PublicKeyPackage(
    ciphersuite,
    randomizedVerifyingShares,
    randomizedParams.randomizedVerifyingKey.toElement(),
    publicKeyPackage.minSigners,
  );
}
