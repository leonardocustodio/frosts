/**
 * Repairable Threshold Scheme
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
 * - Each helper runs `repairShareStep1`, generating a set of `delta` values
 *   to be sent to each helper (including themselves).
 * - Each helper runs `repairShareStep2`, passing the received `delta`
 *   values, generating a `sigma` value to be sent to the participant repairing
 *   their share.
 * - The participant repairing their share runs `repairShareStep3`, passing
 *   all the received `sigma` values, recovering their lost `KeyPackage`. (They
 *   will also need the `PublicKeyPackage` for this step which could be
 *   provided by any of the helpers).
 *
 * @module keys/repairable
 */

import type { Ciphersuite } from "../ciphersuite";
import type { Identifier } from "../identifier";
import type { RandomSource } from "../random";
import { FrostError } from "../error";
import type { PublicKeyPackage } from "../keys";
import {
  KeyPackage,
  SigningShare,
  generateCoefficients,
  computeLagrangeCoefficient,
  identifierToString,
} from "../keys";

/**
 * A delta value which is the output of step 1 of RTS.
 */
export class Delta<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  private readonly scalar: C["Scalar"];

  /**
   * Create a new Delta from a scalar.
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
   * @returns The deserialized Delta
   * @throws {FrostError} If deserialization fails
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): Delta<C> {
    const scalar = ciphersuite.deserializeScalar(bytes);
    return new Delta(ciphersuite, scalar);
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
   * Check equality with another Delta.
   *
   * @param other - The other Delta
   * @returns True if equal
   */
  equals(other: Delta<C>): boolean {
    return this.ciphersuite.scalarsEqual(this.scalar, other.scalar);
  }
}

/**
 * A sigma value which is the output of step 2 of RTS.
 */
export class Sigma<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  private readonly scalar: C["Scalar"];

  /**
   * Create a new Sigma from a scalar.
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
   * @returns The deserialized Sigma
   * @throws {FrostError} If deserialization fails
   */
  static deserialize<C extends Ciphersuite>(ciphersuite: C, bytes: Uint8Array): Sigma<C> {
    const scalar = ciphersuite.deserializeScalar(bytes);
    return new Sigma(ciphersuite, scalar);
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
   * Check equality with another Sigma.
   *
   * @param other - The other Sigma
   * @returns True if equal
   */
  equals(other: Sigma<C>): boolean {
    return this.ciphersuite.scalarsEqual(this.scalar, other.scalar);
  }
}

/**
 * Step 1 of RTS.
 *
 * Generates the "delta" values from the helper with `keyPackage_i` to send to
 * `helpers` (which includes the helper with `keyPackage_i`), to help
 * `participant` recover their share.
 *
 * Returns a Map mapping which value should be sent to which participant.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param helpers - Array of helper identifiers
 * @param keyPackage_i - The helper's key package
 * @param rng - Random number generator
 * @param participant - The participant who is repairing their share
 * @returns Map of identifier to Delta
 * @throws {FrostError} If parameters are invalid
 */
export function repairShareStep1<C extends Ciphersuite>(
  ciphersuite: C,
  helpers: Identifier<C>[],
  keyPackage_i: KeyPackage<C>,
  rng: RandomSource,
  participant: Identifier<C>,
): Map<string, Delta<C>> {
  if (helpers.length < 2) {
    throw FrostError.incorrectNumberOfIdentifiers<C>();
  }

  // Check if key_package_i's identifier is in helpers
  const keyPackageIdStr = identifierToString(keyPackage_i.identifier);
  const helperStrs = helpers.map(identifierToString);
  if (!helperStrs.includes(keyPackageIdStr)) {
    throw FrostError.unknownIdentifier<C>();
  }

  // Check for duplicates
  const helperSet = new Set(helperStrs);
  if (helperSet.size !== helpers.length) {
    throw FrostError.duplicatedIdentifier<C>();
  }

  // Generate random values (one less than number of helpers)
  const randVal = generateCoefficients<C>(ciphersuite, helpers.length - 1, rng);

  return computeLastRandomValue(ciphersuite, helpers, keyPackage_i, randVal, participant);
}

/**
 * Compute the last delta value given the (generated uniformly at random) remaining ones
 * since they all must add up to `zeta_i * share_i`.
 *
 * Returns a Map mapping which value should be sent to which participant.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param helpers - Array of helper identifiers
 * @param keyPackage_i - The helper's key package
 * @param randomValues - Pre-generated random values
 * @param participant - The participant who is repairing their share
 * @returns Map of identifier to Delta
 * @throws {FrostError} If computation fails
 */
function computeLastRandomValue<C extends Ciphersuite>(
  ciphersuite: C,
  helpers: Identifier<C>[],
  keyPackage_i: KeyPackage<C>,
  randomValues: C["Scalar"][],
  participant: Identifier<C>,
): Map<string, Delta<C>> {
  // Calculate Lagrange Coefficient for helper_i
  const zeta_i = computeLagrangeCoefficient(
    ciphersuite,
    helpers,
    participant,
    keyPackage_i.identifier,
  );

  const lhs = ciphersuite.scalarMul(zeta_i, keyPackage_i.signingShare.toScalar());

  // Build the output map with random values for all but the last helper
  const out = new Map<string, Delta<C>>();

  for (let i = 0; i < helpers.length - 1; i++) {
    const helperIdStr = identifierToString(helpers[i]);
    out.set(helperIdStr, new Delta(ciphersuite, randomValues[i]));
  }

  // Sum up all the random deltas
  let sumIDeltas = ciphersuite.scalarZero();
  for (const v of randomValues) {
    sumIDeltas = ciphersuite.scalarAdd(sumIDeltas, v);
  }

  // The last helper gets lhs - sum_i_deltas so everything adds up correctly
  const lastHelper = helpers[helpers.length - 1];
  if (lastHelper === undefined) {
    throw FrostError.incorrectNumberOfIdentifiers<C>();
  }
  const lastHelperIdStr = identifierToString(lastHelper);
  const lastDelta = ciphersuite.scalarSub(lhs, sumIDeltas);
  out.set(lastHelperIdStr, new Delta(ciphersuite, lastDelta));

  return out;
}

/**
 * Step 2 of RTS.
 *
 * Generates the "sigma" value from all `deltas` received from all helpers.
 * The "sigma" value must be sent to the participant repairing their share.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param deltas - Array of Delta values received from all helpers
 * @returns The computed Sigma value
 */
export function repairShareStep2<C extends Ciphersuite>(
  ciphersuite: C,
  deltas: Delta<C>[],
): Sigma<C> {
  let sigma_j = ciphersuite.scalarZero();

  for (const d of deltas) {
    sigma_j = ciphersuite.scalarAdd(sigma_j, d.toScalar());
  }

  return new Sigma(ciphersuite, sigma_j);
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
 * @param ciphersuite - The ciphersuite to use
 * @param sigmas - Array of Sigma values received from all helpers
 * @param identifier - The identifier of the participant recovering their share
 * @param publicKeyPackage - The group's public key package
 * @returns The recovered KeyPackage
 * @throws {FrostError} If recovery fails or minSigners is not set
 */
export function repairShareStep3<C extends Ciphersuite>(
  ciphersuite: C,
  sigmas: Sigma<C>[],
  identifier: Identifier<C>,
  publicKeyPackage: PublicKeyPackage<C>,
): KeyPackage<C> {
  let share = ciphersuite.scalarZero();

  for (const s of sigmas) {
    share = ciphersuite.scalarAdd(share, s.toScalar());
  }

  const signingShare = new SigningShare(ciphersuite, share);
  const verifyingShare = signingShare.toVerifyingShare();

  if (publicKeyPackage.minSigners === undefined) {
    throw FrostError.invalidMinSigners();
  }

  return new KeyPackage(
    ciphersuite,
    identifier,
    signingShare,
    verifyingShare,
    publicKeyPackage.verifyingKey,
    publicKeyPackage.minSigners,
  );
}
