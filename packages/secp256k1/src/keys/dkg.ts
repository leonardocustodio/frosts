/**
 * DKG (Distributed Key Generation) module for FROST(secp256k1, SHA-256).
 *
 * This module provides types and functions for performing distributed key generation
 * among participants without a trusted dealer. The DKG protocol consists of three
 * rounds of communication between all participants.
 *
 * @module keys/dkg
 */

import type { Secp256K1Sha256Impl } from "../index.js";
import type { Identifier, RandomSource } from "@frost/core";
import {
  type round1 as coreRound1,
  type round2 as coreRound2,
  part1 as corePart1,
  part2 as corePart2,
  part3 as corePart3,
} from "@frost/core";
import type { KeyPackage, PublicKeyPackage } from "./index.js";

// Re-use the ciphersuite type
type S = Secp256K1Sha256Impl;

/**
 * DKG Round 1 structures.
 */
export namespace round1 {
  /**
   * The secret package that must be kept in memory by the participant
   * between the first and second parts of the DKG protocol (round 1).
   *
   * # Security
   *
   * This package MUST NOT be sent to other participants!
   */
  export type SecretPackage = coreRound1.SecretPackage<S>;

  /**
   * The package that must be broadcast by each participant to all other participants
   * between the first and second parts of the DKG protocol (round 1).
   */
  export type Package = coreRound1.Package<S>;
}

/**
 * DKG Round 2 structures.
 */
export namespace round2 {
  /**
   * The secret package that must be kept in memory by the participant
   * between the second and third parts of the DKG protocol (round 2).
   *
   * # Security
   *
   * This package MUST NOT be sent to other participants!
   */
  export type SecretPackage = coreRound2.SecretPackage<S>;

  /**
   * A package that must be sent by each participant to some other participants
   * in Round 2 of the DKG protocol. Note that there is one specific package
   * for each specific recipient, in contrast to Round 1.
   *
   * # Security
   *
   * The package must be sent on an *confidential* and *authenticated* channel.
   */
  export type Package = coreRound2.Package<S>;
}

/**
 * Performs the first part of the distributed key generation protocol
 * for the given participant.
 *
 * It returns the {@link round1.SecretPackage} that must be kept in memory
 * by the participant for the other steps, and the {@link round1.Package} that
 * must be sent to each other participant in the DKG run.
 *
 * @param ciphersuite - The Secp256K1Sha256 ciphersuite instance
 * @param identifier - The participant's identifier
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers (threshold)
 * @param rng - Random number generator
 * @returns A tuple of [SecretPackage, Package]
 * @throws {FrostError} If parameters are invalid
 */
export function part1(
  ciphersuite: S,
  identifier: Identifier<S>,
  maxSigners: number,
  minSigners: number,
  rng: RandomSource,
): [round1.SecretPackage, round1.Package] {
  return corePart1(ciphersuite, identifier, maxSigners, minSigners, rng);
}

/**
 * Performs the second part of the distributed key generation protocol for the
 * participant holding the given {@link round1.SecretPackage}, given the received
 * {@link round1.Package}s received from the other participants.
 *
 * `round1Packages` maps the identifier of each other participant to the
 * {@link round1.Package} they sent to the current participant (the owner of
 * `secretPackage`). These identifiers must come from whatever mapping the
 * coordinator has between communication channels and participants, i.e. they
 * must have assurance that the {@link round1.Package} came from the participant
 * with that identifier.
 *
 * It returns the {@link round2.SecretPackage} that must be kept in memory by the
 * participant for the final step, and the map of {@link round2.Package}s that
 * must be sent to each other participant who has the given identifier in the
 * map key.
 *
 * @param ciphersuite - The Secp256K1Sha256 ciphersuite instance
 * @param secretPackage - The round 1 secret package
 * @param round1Packages - Map of identifier string to round 1 packages
 * @returns A tuple of [round2.SecretPackage, Map of round2.Package by identifier string]
 * @throws {FrostError} If validation fails
 */
export function part2(
  ciphersuite: S,
  secretPackage: round1.SecretPackage,
  round1Packages: Map<string, round1.Package>,
): [round2.SecretPackage, Map<string, round2.Package>] {
  return corePart2(ciphersuite, secretPackage, round1Packages);
}

/**
 * Performs the third and final part of the distributed key generation protocol
 * for the participant holding the given {@link round2.SecretPackage}, given the
 * received {@link round1.Package}s and {@link round2.Package}s received from the
 * other participants.
 *
 * `round1Packages` must be the same used in {@link part2}.
 *
 * `round2Packages` maps the identifier of each other participant to the
 * {@link round2.Package} they sent to the current participant (the owner of
 * `secretPackage`). These identifiers must come from whatever mapping the
 * coordinator has between communication channels and participants, i.e. they
 * must have assurance that the {@link round2.Package} came from the participant
 * with that identifier.
 *
 * It returns the {@link KeyPackage} that has the long-lived key share for the
 * participant, and the {@link PublicKeyPackage} that has public information about
 * all participants; both of which are required to compute FROST signatures.
 *
 * @param ciphersuite - The Secp256K1Sha256 ciphersuite instance
 * @param round2SecretPackage - The round 2 secret package
 * @param round1Packages - Map of identifier string to round 1 packages
 * @param round2Packages - Map of identifier string to round 2 packages
 * @returns A Promise of a tuple of [KeyPackage, PublicKeyPackage]
 * @throws {FrostError} If validation fails
 */
export function part3(
  ciphersuite: S,
  round2SecretPackage: round2.SecretPackage,
  round1Packages: Map<string, round1.Package>,
  round2Packages: Map<string, round2.Package>,
): Promise<[KeyPackage, PublicKeyPackage]> {
  return corePart3(ciphersuite, round2SecretPackage, round1Packages, round2Packages);
}
