/**
 * Refresh Shares
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
 * `computeRefreshingShares()` and send the returned refreshing shares to
 * the participants. Each participant should then call `refreshShare()`.
 *
 * For the DKG approach, the flow is very similar to DKG itself. Each participant
 * calls `refreshDkgPart1()`, keeps the returned secret package and sends the
 * returned package to other participants. Then each participant calls
 * `refreshDkgPart2()` and sends the returned packages to the other
 * participants. Finally each participant calls `refreshDkgShares()`.
 *
 * @module keys/refresh
 */

import type { Ciphersuite } from "../ciphersuite";
import type { Identifier } from "../identifier";
import { Identifier as IdentifierClass } from "../identifier";
import type { RandomSource } from "../random";
import { FrostError } from "../error";
import {
  SigningShare,
  VerifyingShare,
  VerifiableSecretSharingCommitment,
  CoefficientCommitment,
  KeyPackage,
  PublicKeyPackage,
  SecretShare,
  validateNumOfSigners,
  generateCoefficients,
  generateSecretPolynomial,
  generateSecretShares,
  evaluatePolynomial,
  identifierToString,
} from "../keys";
import { round1, round2, computeProofOfKnowledge } from "./dkg";

/**
 * Convert a hex string to bytes.
 *
 * @param hex - The hex string
 * @returns The byte array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

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
 * @param ciphersuite - The ciphersuite to use
 * @param pubKeyPackage - The current public key package
 * @param identifiers - Array of participant identifiers to refresh
 * @param rng - Random number generator
 * @returns A tuple of [SecretShare[], PublicKeyPackage]
 * @throws {FrostError} If parameters are invalid
 */
export function computeRefreshingShares<C extends Ciphersuite>(
  ciphersuite: C,
  pubKeyPackage: PublicKeyPackage<C>,
  identifiers: Identifier<C>[],
  rng: RandomSource,
): [SecretShare<C>[], PublicKeyPackage<C>] {
  const minSigners = pubKeyPackage.minSigners;
  if (minSigners === undefined) {
    throw FrostError.invalidMinSigners();
  }

  const signers = identifiers.length;
  validateNumOfSigners(minSigners, signers);

  // Check all identifiers are in the public key package
  for (const id of identifiers) {
    const idStr = identifierToString(id);
    if (!pubKeyPackage.verifyingShares.has(idStr)) {
      throw FrostError.unknownIdentifier<C>();
    }
  }

  // Build refreshing shares with zero secret
  const refreshingKey = ciphersuite.scalarZero();

  const coefficients = generateCoefficients(ciphersuite, minSigners - 1, rng);
  const refreshingShares = generateSecretShares(
    ciphersuite,
    refreshingKey,
    signers,
    minSigners,
    coefficients,
    identifiers,
  );

  const refreshedVerifyingShares = new Map<string, VerifyingShare<C>>();
  const refreshingSharesMinusIdentity: SecretShare<C>[] = [];

  for (const share of refreshingShares) {
    const refreshingVerifyingShare = share.signingShare.toVerifyingShare();
    const idStr = identifierToString(share.identifier);

    const verifyingShare = pubKeyPackage.verifyingShares.get(idStr);
    if (verifyingShare === undefined) {
      throw FrostError.unknownIdentifier<C>();
    }

    const refreshedVerifyingShareElement = ciphersuite.elementAdd(
      refreshingVerifyingShare.toElement(),
      verifyingShare.toElement(),
    );
    refreshedVerifyingShares.set(
      idStr,
      new VerifyingShare(ciphersuite, refreshedVerifyingShareElement),
    );

    // Remove the first commitment (identity element) from the VSS commitment
    const coeffs = [...share.commitment.coefficients()];
    coeffs.shift(); // Remove first element
    const modifiedCommitment = new VerifiableSecretSharingCommitment(ciphersuite, coeffs);

    refreshingSharesMinusIdentity.push(
      new SecretShare(ciphersuite, share.identifier, share.signingShare, modifiedCommitment),
    );
  }

  const refreshedPubKeyPackage = new PublicKeyPackage(
    ciphersuite,
    refreshedVerifyingShares,
    pubKeyPackage.verifyingKey, // Verifying key stays the same
    pubKeyPackage.minSigners ?? minSigners,
  );

  return [refreshingSharesMinusIdentity, refreshedPubKeyPackage];
}

/**
 * Refresh a share in the Trusted Dealer refresh procedure.
 *
 * Must be called by each participant refreshing the shares, with the
 * `refreshingShare` received from the trusted dealer and the
 * `currentKeyPackage` of the participant.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param refreshingShare - The refreshing share received from the dealer
 * @param currentKeyPackage - The participant's current key package
 * @returns The refreshed KeyPackage
 * @throws {FrostError} If refresh fails
 */
export function refreshShare<C extends Ciphersuite>(
  ciphersuite: C,
  refreshingShare: SecretShare<C>,
  currentKeyPackage: KeyPackage<C>,
): KeyPackage<C> {
  // The identity commitment needs to be added to the VSS commitment
  const identityCommitment = new CoefficientCommitment(ciphersuite, ciphersuite.identity());

  const refreshingShareCommitments = [
    identityCommitment,
    ...refreshingShare.commitment.coefficients(),
  ];

  const modifiedCommitment = new VerifiableSecretSharingCommitment(
    ciphersuite,
    refreshingShareCommitments,
  );

  const modifiedRefreshingShare = new SecretShare(
    ciphersuite,
    refreshingShare.identifier,
    refreshingShare.signingShare,
    modifiedCommitment,
  );

  // Verify refreshing_share secret share
  const refreshedSharePackage = modifiedRefreshingShare.toKeyPackage();

  if (refreshedSharePackage.minSigners !== currentKeyPackage.minSigners) {
    throw FrostError.invalidMinSigners();
  }

  const newSigningShareScalar = ciphersuite.scalarAdd(
    refreshedSharePackage.signingShare.toScalar(),
    currentKeyPackage.signingShare.toScalar(),
  );

  const signingShare = new SigningShare(ciphersuite, newSigningShareScalar);

  return new KeyPackage(
    ciphersuite,
    currentKeyPackage.identifier,
    signingShare,
    currentKeyPackage.verifyingShare, // Keep the same verifying share for now
    currentKeyPackage.verifyingKey,
    currentKeyPackage.minSigners,
  );
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
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The participant's identifier
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers (threshold)
 * @param rng - Random number generator
 * @returns A tuple of [round1.SecretPackage, round1.Package]
 * @throws {FrostError} If parameters are invalid
 */
export function refreshDkgPart1<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  maxSigners: number,
  minSigners: number,
  rng: RandomSource,
): [round1.SecretPackage<C>, round1.Package<C>] {
  validateNumOfSigners(minSigners, maxSigners);

  // Build refreshing shares with zero secret
  const refreshingKey = ciphersuite.scalarZero();

  // Round 1, Step 1
  const coefficients = generateCoefficients(ciphersuite, minSigners - 1, rng);

  const [allCoefficients, commitment] = generateSecretPolynomial(
    ciphersuite,
    refreshingKey,
    maxSigners,
    minSigners,
    coefficients,
  );

  // Remove identity element from commitment coefficients
  const coeffCommitments = [...commitment.coefficients()];
  coeffCommitments.shift(); // Remove first element (identity)
  const modifiedCommitment = new VerifiableSecretSharingCommitment(ciphersuite, coeffCommitments);

  const proofOfKnowledge = computeProofOfKnowledge(
    ciphersuite,
    identifier,
    allCoefficients,
    modifiedCommitment,
    rng,
  );

  const secretPackage = new round1.SecretPackage(
    ciphersuite,
    identifier,
    allCoefficients,
    modifiedCommitment,
    minSigners,
    maxSigners,
  );

  const pkg = new round1.Package(ciphersuite, modifiedCommitment, proofOfKnowledge);

  return [secretPackage, pkg];
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
 * @param ciphersuite - The ciphersuite to use
 * @param secretPackage - The round 1 secret package
 * @param round1Packages - Map of identifier to round 1 packages
 * @returns A tuple of [round2.SecretPackage, Map of round2.Package by identifier]
 * @throws {FrostError} If validation fails
 */
export function refreshDkgPart2<C extends Ciphersuite>(
  ciphersuite: C,
  secretPackage: round1.SecretPackage<C>,
  round1Packages: Map<string, round1.Package<C>>,
): [round2.SecretPackage<C>, Map<string, round2.Package<C>>] {
  if (round1Packages.size !== secretPackage.maxSigners - 1) {
    throw FrostError.incorrectNumberOfPackages<C>();
  }

  // The identity commitment needs to be added to the VSS commitment for secret package
  const identityCommitment = new CoefficientCommitment(ciphersuite, ciphersuite.identity());

  const secretPackageCommitments = [identityCommitment, ...secretPackage.commitment.coefficients()];

  // This variable is computed but not currently used - kept for potential future use
  // to verify secret package commitment matches the expected value
  void new VerifiableSecretSharingCommitment(ciphersuite, secretPackageCommitments);

  const round2Packages = new Map<string, round2.Package<C>>();

  for (const [senderIdStr, round1Package] of round1Packages) {
    // The identity commitment needs to be added to the VSS commitment for every round 1 package
    const round1CommitmentCoeffs = [identityCommitment, ...round1Package.commitment.coefficients()];

    if (round1CommitmentCoeffs.length !== secretPackage.minSigners) {
      throw FrostError.incorrectNumberOfCommitments<C>();
    }

    // Parse the identifier from the string key
    const idBytes = hexToBytes(senderIdStr);
    const ell: Identifier<C> = IdentifierClass.deserialize(ciphersuite, idBytes);

    // Round 1, Step 5
    // We don't need to verify the proof of knowledge for refresh

    // Round 2, Step 1
    const signingShare = SigningShare.fromCoefficients(
      ciphersuite,
      secretPackage.coefficients(),
      ell,
    );

    round2Packages.set(senderIdStr, new round2.Package(ciphersuite, signingShare));
  }

  const fii = evaluatePolynomial(
    ciphersuite,
    secretPackage.identifier,
    secretPackage.coefficients(),
  );

  // We keep the commitment without identity for serialization
  const round2SecretPackage = new round2.SecretPackage(
    ciphersuite,
    secretPackage.identifier,
    secretPackage.commitment, // Original commitment (without identity)
    fii,
    secretPackage.minSigners,
    secretPackage.maxSigners,
  );

  return [round2SecretPackage, round2Packages];
}

/**
 * Performs the third and final part of the refresh procedure for the
 * participant holding the given SecretPackage, given the received
 * round1::Packages and round2::Packages received from the other
 * participants.
 *
 * `round1Packages` must be the same used in `refreshDkgPart2()`.
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
 * @param ciphersuite - The ciphersuite to use
 * @param round2SecretPackage - The round 2 secret package
 * @param round1Packages - Map of identifier to round 1 packages
 * @param round2Packages - Map of identifier to round 2 packages
 * @param oldPubKeyPackage - The old public key package
 * @param oldKeyPackage - The old key package
 * @returns A tuple of [KeyPackage, PublicKeyPackage]
 * @throws {FrostError} If validation fails
 */
export async function refreshDkgShares<C extends Ciphersuite>(
  ciphersuite: C,
  round2SecretPackage: round2.SecretPackage<C>,
  round1Packages: Map<string, round1.Package<C>>,
  round2Packages: Map<string, round2.Package<C>>,
  oldPubKeyPackage: PublicKeyPackage<C>,
  oldKeyPackage: KeyPackage<C>,
): Promise<[KeyPackage<C>, PublicKeyPackage<C>]> {
  if (round2SecretPackage.minSigners !== oldKeyPackage.minSigners) {
    throw FrostError.invalidMinSigners();
  }

  // Add identity commitment back into the round2_secret_package commitment
  const identityCommitment = new CoefficientCommitment(ciphersuite, ciphersuite.identity());

  const round2Commitment = new VerifiableSecretSharingCommitment(ciphersuite, [
    identityCommitment,
    ...round2SecretPackage.commitment.coefficients(),
  ]);

  // Add identity commitment back into round1_packages
  const newRound1Packages = new Map<string, round1.Package<C>>();
  for (const [senderIdStr, round1Package] of round1Packages) {
    const refreshingShareCommitments = [
      identityCommitment,
      ...round1Package.commitment.coefficients(),
    ];

    const newCommitments = new VerifiableSecretSharingCommitment(
      ciphersuite,
      refreshingShareCommitments,
    );

    newRound1Packages.set(
      senderIdStr,
      new round1.Package(ciphersuite, newCommitments, round1Package.proofOfKnowledge),
    );
  }

  if (newRound1Packages.size !== round2SecretPackage.maxSigners - 1) {
    throw FrostError.incorrectNumberOfPackages<C>();
  }
  if (newRound1Packages.size !== round2Packages.size) {
    throw FrostError.incorrectNumberOfPackages<C>();
  }
  for (const id of newRound1Packages.keys()) {
    if (!round2Packages.has(id)) {
      throw FrostError.incorrectPackage<C>();
    }
  }

  let signingShareScalar = ciphersuite.scalarZero();

  for (const [senderIdStr, round2Package] of round2Packages) {
    // Round 2, Step 2
    // Note: We validate the identifier but don't use ell directly - in Rust it's used for culprit identification
    const idBytes = hexToBytes(senderIdStr);
    void IdentifierClass.deserialize(ciphersuite, idBytes); // Validates the identifier
    const f_ell_i = round2Package.signingShare;

    const round1Pkg = newRound1Packages.get(senderIdStr);
    if (round1Pkg === undefined) {
      throw FrostError.packageNotFound<C>();
    }
    const commitment = round1Pkg.commitment;

    // Build a temporary SecretShare to verify
    const secretShare = new SecretShare(
      ciphersuite,
      round2SecretPackage.identifier,
      f_ell_i,
      commitment,
    );

    // Verify the share
    secretShare.verify();

    // Round 2, Step 3
    signingShareScalar = ciphersuite.scalarAdd(signingShareScalar, f_ell_i.toScalar());
  }

  signingShareScalar = ciphersuite.scalarAdd(signingShareScalar, round2SecretPackage.secretShare());

  // Build new signing share by adding old signing share
  const oldSigningShare = oldKeyPackage.signingShare.toScalar();
  signingShareScalar = ciphersuite.scalarAdd(signingShareScalar, oldSigningShare);
  const signingShare = new SigningShare(ciphersuite, signingShareScalar);

  // Round 2, Step 4
  const verifyingShare = signingShare.toVerifyingShare();

  // Build commitments map for zero-share PublicKeyPackage
  const commitments = new Map<string, VerifiableSecretSharingCommitment<C>>();
  for (const [id, pkg] of newRound1Packages) {
    commitments.set(id, pkg.commitment);
  }
  // Add own commitment
  const ownIdStr = identifierToString(round2SecretPackage.identifier);
  commitments.set(ownIdStr, round2Commitment);

  const zeroSharesPublicKeyPackage = await PublicKeyPackage.fromDkgCommitments(
    ciphersuite,
    commitments,
  );

  // Compute new verifying shares by adding old verifying shares
  const newVerifyingShares = new Map<string, VerifyingShare<C>>();
  for (const [idStr, zeroVerifyingShare] of zeroSharesPublicKeyPackage.verifyingShares) {
    const oldVerifyingShare = oldPubKeyPackage.verifyingShares.get(idStr);
    if (oldVerifyingShare === undefined) {
      throw FrostError.unknownIdentifier<C>();
    }
    const newVerifyingShareElement = ciphersuite.elementAdd(
      zeroVerifyingShare.toElement(),
      oldVerifyingShare.toElement(),
    );
    newVerifyingShares.set(idStr, new VerifyingShare(ciphersuite, newVerifyingShareElement));
  }

  const publicKeyPackage = new PublicKeyPackage(
    ciphersuite,
    newVerifyingShares,
    oldPubKeyPackage.verifyingKey, // Verifying key stays the same
    round2SecretPackage.minSigners,
  );

  const keyPackage = new KeyPackage(
    ciphersuite,
    round2SecretPackage.identifier,
    signingShare,
    verifyingShare,
    publicKeyPackage.verifyingKey,
    round2SecretPackage.minSigners,
  );

  return [keyPackage, publicKeyPackage];
}
