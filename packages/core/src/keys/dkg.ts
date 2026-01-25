/**
 * Distributed Key Generation functions and structures.
 *
 * The DKG module supports generating FROST key shares in a distributed manner,
 * without a trusted dealer, via two rounds of communication between all
 * participants.
 *
 * This implements FROST KeyGen from the original FROST paper, specifically
 * Figure 1. This protocol is a variant of Pedersen's DKG that additionally
 * requires each participant to demonstrate knowledge of their secret by providing
 * other participants with proof in zero knowledge, instantiated as a Schnorr signature,
 * to protect against rogue-key attacks in the setting where `t >= n/2`.
 *
 * In Pedersen's DKG, each of the `n` participants executes Feldman's
 * Verifiable Secret Sharing (VSS) as the dealer in parallel,
 * and derives their secret share as the sum of the shares received from each
 * of the `n` VSS executions.
 *
 * As required for any multi-party protocol using Feldman's VSS, the key
 * generation stage in FROST requires participants to maintain a consistent
 * view of the public commitments to the secret polynomial coefficients. This
 * DKG protocol requires participants to broadcast the commitment values
 * honestly (e.g., participants do not provide different commitment values to a
 * subset of participants) over a secure broadcast channel.
 *
 * @module keys/dkg
 */

import type { Ciphersuite } from "../ciphersuite";
import type { Identifier } from "../identifier";
import { Identifier as IdentifierClass } from "../identifier";
import type { RandomSource } from "../random";
import { FrostError } from "../error";
import type { VerifiableSecretSharingCommitment } from "../keys";
import {
  SigningShare,
  KeyPackage,
  PublicKeyPackage,
  SecretShare,
  validateNumOfSigners,
  generateCoefficients,
  generateSecretPolynomial,
  evaluatePolynomial,
  identifierToString,
} from "../keys";

/**
 * A Schnorr signature used as proof of knowledge in DKG.
 */
export interface DkgSignature<C extends Ciphersuite> {
  /** The R component (commitment element) */
  R: C["Element"];
  /** The z component (response scalar) */
  z: C["Scalar"];
}

/**
 * DKG Round 1 structures.
 */
export namespace round1 {
  /**
   * The package that must be broadcast by each participant to all other participants
   * between the first and second parts of the DKG protocol (round 1).
   */
  export class Package<C extends Ciphersuite> {
    readonly ciphersuite: C;
    /** The public commitment from the participant (C_i) */
    readonly commitment: VerifiableSecretSharingCommitment<C>;
    /** The proof of knowledge of the temporary secret (sigma_i = (R_i, mu_i)) */
    readonly proofOfKnowledge: DkgSignature<C>;

    /**
     * Create a new Package instance.
     *
     * @param ciphersuite - The ciphersuite to use
     * @param commitment - The VSS commitment
     * @param proofOfKnowledge - The proof of knowledge signature
     */
    constructor(
      ciphersuite: C,
      commitment: VerifiableSecretSharingCommitment<C>,
      proofOfKnowledge: DkgSignature<C>,
    ) {
      this.ciphersuite = ciphersuite;
      this.commitment = commitment;
      this.proofOfKnowledge = proofOfKnowledge;
    }

    /**
     * Check equality with another Package.
     *
     * @param other - The other Package
     * @returns True if equal
     */
    equals(other: Package<C>): boolean {
      return (
        this.commitment.equals(other.commitment) &&
        this.ciphersuite.elementsEqual(this.proofOfKnowledge.R, other.proofOfKnowledge.R) &&
        this.ciphersuite.scalarsEqual(this.proofOfKnowledge.z, other.proofOfKnowledge.z)
      );
    }

    /**
     * Clone this Package.
     *
     * @returns A new Package with the same values
     */
    clone(): Package<C> {
      return new Package(this.ciphersuite, this.commitment, this.proofOfKnowledge);
    }

    /**
     * Returns a string representation of this Package.
     */
    toString(): string {
      return `round1::Package { commitment: <${this.commitment.coefficients().length} coefficients>, proofOfKnowledge: <...> }`;
    }
  }

  /**
   * The secret package that must be kept in memory by the participant
   * between the first and second parts of the DKG protocol (round 1).
   *
   * # Security
   *
   * This package MUST NOT be sent to other participants!
   */
  export class SecretPackage<C extends Ciphersuite> {
    readonly ciphersuite: C;
    /** The identifier of the participant holding the secret */
    readonly identifier: Identifier<C>;
    /** Coefficients of the temporary secret polynomial for the participant */
    private readonly coefficientValues: C["Scalar"][];
    /** The public commitment for the participant (C_i) */
    readonly commitment: VerifiableSecretSharingCommitment<C>;
    /** The minimum number of signers */
    readonly minSigners: number;
    /** The total number of signers */
    readonly maxSigners: number;

    /**
     * Create a new SecretPackage.
     *
     * @param ciphersuite - The ciphersuite to use
     * @param identifier - Participant identifier
     * @param coefficients - Secret polynomial coefficients
     * @param commitment - The VSS commitment
     * @param minSigners - Minimum number of signers
     * @param maxSigners - Maximum number of signers
     */
    constructor(
      ciphersuite: C,
      identifier: Identifier<C>,
      coefficients: C["Scalar"][],
      commitment: VerifiableSecretSharingCommitment<C>,
      minSigners: number,
      maxSigners: number,
    ) {
      this.ciphersuite = ciphersuite;
      this.identifier = identifier;
      this.coefficientValues = coefficients;
      this.commitment = commitment;
      this.minSigners = minSigners;
      this.maxSigners = maxSigners;
    }

    /**
     * Returns the secret coefficients.
     *
     * @returns Array of scalar coefficients
     */
    coefficients(): C["Scalar"][] {
      return [...this.coefficientValues];
    }

    /**
     * Check equality with another SecretPackage.
     *
     * @param other - The other SecretPackage
     * @returns True if equal
     */
    equals(other: SecretPackage<C>): boolean {
      // identifier.equals() no longer needs ciphersuite
      if (
        !this.identifier.equals(other.identifier) ||
        this.minSigners !== other.minSigners ||
        this.maxSigners !== other.maxSigners ||
        !this.commitment.equals(other.commitment)
      ) {
        return false;
      }
      if (this.coefficientValues.length !== other.coefficientValues.length) {
        return false;
      }
      for (let i = 0; i < this.coefficientValues.length; i++) {
        if (!this.ciphersuite.scalarsEqual(this.coefficientValues[i], other.coefficientValues[i])) {
          return false;
        }
      }
      return true;
    }

    /**
     * Clone this SecretPackage.
     *
     * @returns A new SecretPackage with the same values
     */
    clone(): SecretPackage<C> {
      return new SecretPackage(
        this.ciphersuite,
        this.identifier,
        [...this.coefficientValues],
        this.commitment,
        this.minSigners,
        this.maxSigners,
      );
    }

    /**
     * Returns a string representation of this SecretPackage (redacted for security).
     */
    toString(): string {
      return `round1::SecretPackage { identifier: ${this.identifier.toString()}, minSigners: ${this.minSigners}, maxSigners: ${this.maxSigners}, coefficients: <redacted> }`;
    }
  }
}

/**
 * DKG Round 2 structures.
 */
export namespace round2 {
  /**
   * A package that must be sent by each participant to some other participants
   * in Round 2 of the DKG protocol. Note that there is one specific package
   * for each specific recipient, in contrast to Round 1.
   *
   * # Security
   *
   * The package must be sent on an *confidential* and *authenticated* channel.
   */
  export class Package<C extends Ciphersuite> {
    readonly ciphersuite: C;
    /** The secret share being sent */
    readonly signingShare: SigningShare<C>;

    /**
     * Create a new Package instance.
     *
     * @param ciphersuite - The ciphersuite to use
     * @param signingShare - The signing share
     */
    constructor(ciphersuite: C, signingShare: SigningShare<C>) {
      this.ciphersuite = ciphersuite;
      this.signingShare = signingShare;
    }

    /**
     * Check equality with another Package.
     *
     * @param other - The other Package
     * @returns True if equal
     */
    equals(other: Package<C>): boolean {
      return this.signingShare.equals(other.signingShare);
    }

    /**
     * Clone this Package.
     *
     * @returns A new Package with the same values
     */
    clone(): Package<C> {
      return new Package(this.ciphersuite, this.signingShare.clone());
    }

    /**
     * Returns a string representation of this Package (redacted for security).
     */
    toString(): string {
      return "round2::Package { signingShare: <redacted> }";
    }
  }

  /**
   * The secret package that must be kept in memory by the participant
   * between the second and third parts of the DKG protocol (round 2).
   *
   * # Security
   *
   * This package MUST NOT be sent to other participants!
   */
  export class SecretPackage<C extends Ciphersuite> {
    readonly ciphersuite: C;
    /** The identifier of the participant holding the secret */
    readonly identifier: Identifier<C>;
    /** The public commitment from the participant (C_i) */
    readonly commitment: VerifiableSecretSharingCommitment<C>;
    /** The participant's own secret share (f_i(i)) */
    private readonly secretShareValue: C["Scalar"];
    /** The minimum number of signers */
    readonly minSigners: number;
    /** The total number of signers */
    readonly maxSigners: number;

    /**
     * Create a new SecretPackage.
     *
     * @param ciphersuite - The ciphersuite to use
     * @param identifier - Participant identifier
     * @param commitment - The VSS commitment
     * @param secretShare - The participant's own secret share
     * @param minSigners - Minimum number of signers
     * @param maxSigners - Maximum number of signers
     */
    constructor(
      ciphersuite: C,
      identifier: Identifier<C>,
      commitment: VerifiableSecretSharingCommitment<C>,
      secretShare: C["Scalar"],
      minSigners: number,
      maxSigners: number,
    ) {
      this.ciphersuite = ciphersuite;
      this.identifier = identifier;
      this.commitment = commitment;
      this.secretShareValue = secretShare;
      this.minSigners = minSigners;
      this.maxSigners = maxSigners;
    }

    /**
     * Return the secret share.
     *
     * @returns The secret share scalar
     */
    secretShare(): C["Scalar"] {
      return this.secretShareValue;
    }

    /**
     * Check equality with another SecretPackage.
     *
     * @param other - The other SecretPackage
     * @returns True if equal
     */
    equals(other: SecretPackage<C>): boolean {
      return (
        this.identifier.equals(other.identifier) &&
        this.commitment.equals(other.commitment) &&
        this.ciphersuite.scalarsEqual(this.secretShareValue, other.secretShareValue) &&
        this.minSigners === other.minSigners &&
        this.maxSigners === other.maxSigners
      );
    }

    /**
     * Clone this SecretPackage.
     *
     * @returns A new SecretPackage with the same values
     */
    clone(): SecretPackage<C> {
      return new SecretPackage(
        this.ciphersuite,
        this.identifier,
        this.commitment,
        this.secretShareValue,
        this.minSigners,
        this.maxSigners,
      );
    }

    /**
     * Returns a string representation of this SecretPackage (redacted for security).
     */
    toString(): string {
      return `round2::SecretPackage { identifier: ${this.identifier.toString()}, minSigners: ${this.minSigners}, maxSigners: ${this.maxSigners}, secretShare: <redacted> }`;
    }
  }
}

/**
 * Generate a random nonzero scalar.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param rng - Random number generator
 * @returns A random nonzero scalar
 */
function randomNonzeroScalar<C extends Ciphersuite>(
  ciphersuite: C,
  rng: RandomSource,
): C["Scalar"] {
  let scalar: C["Scalar"];
  do {
    scalar = ciphersuite.scalarRandom(rng);
  } while (ciphersuite.scalarsEqual(scalar, ciphersuite.scalarZero()));
  return scalar;
}

/**
 * Performs the first part of the distributed key generation protocol
 * for the given participant.
 *
 * It returns the SecretPackage that must be kept in memory by the participant
 * for the other steps, and the Package that must be sent to each other
 * participant in the DKG run.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The participant's identifier
 * @param maxSigners - Maximum number of signers
 * @param minSigners - Minimum number of signers (threshold)
 * @param rng - Random number generator
 * @returns A tuple of [SecretPackage, Package]
 * @throws {FrostError} If parameters are invalid
 */
export function part1<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  maxSigners: number,
  minSigners: number,
  rng: RandomSource,
): [round1.SecretPackage<C>, round1.Package<C>] {
  validateNumOfSigners(minSigners, maxSigners);

  const secret = randomNonzeroScalar(ciphersuite, rng);

  // Round 1, Step 1
  // > Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)}) <- Z_q
  //
  // Round 1, Step 3
  // > Every participant P_i computes a public commitment
  // > C_i = <phi_{i0}, ..., phi_{i(t-1)}>, where phi_{ij} = g^{a_{ij}}, 0 <= j <= t - 1
  const coefficients = generateCoefficients(ciphersuite, minSigners - 1, rng);

  const [allCoefficients, commitment] = generateSecretPolynomial(
    ciphersuite,
    secret,
    maxSigners,
    minSigners,
    coefficients,
  );

  const proofOfKnowledge = computeProofOfKnowledge(
    ciphersuite,
    identifier,
    allCoefficients,
    commitment,
    rng,
  );

  const secretPackage = new round1.SecretPackage(
    ciphersuite,
    identifier,
    allCoefficients,
    commitment,
    minSigners,
    maxSigners,
  );

  const pkg = new round1.Package(ciphersuite, commitment, proofOfKnowledge);

  return [secretPackage, pkg];
}

/**
 * Generates the challenge for the proof of knowledge to a secret for the DKG.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The participant identifier
 * @param verifyingKey - The verifying key element
 * @param R - The commitment element
 * @returns The challenge scalar
 * @throws {FrostError} If DKG is not supported
 */
function dkgChallenge<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  verifyingKey: C["Element"],
  R: C["Element"],
): C["Scalar"] {
  const preimage: number[] = [];

  // identifier.serialize() no longer needs ciphersuite
  const idBytes = identifier.serialize();
  preimage.push(...idBytes);

  // verifying_key serialization
  const vkBytes = ciphersuite.serializeElement(verifyingKey);
  preimage.push(...vkBytes);

  // R serialization
  const rBytes = ciphersuite.serializeElement(R);
  preimage.push(...rBytes);

  if (ciphersuite.HDKG === undefined || ciphersuite.HDKG === null) {
    throw FrostError.dkgNotSupported<C>();
  }

  const scalar = ciphersuite.HDKG(new Uint8Array(preimage));
  if (scalar === null || scalar === undefined) {
    throw FrostError.dkgNotSupported<C>();
  }

  return scalar;
}

/**
 * Compute the proof of knowledge of the secret coefficients used to generate
 * the public secret sharing commitment.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The participant identifier
 * @param coefficients - The polynomial coefficients
 * @param commitment - The VSS commitment
 * @param rng - Random number generator
 * @returns The proof of knowledge signature
 * @throws {FrostError} If computation fails
 */
export function computeProofOfKnowledge<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  coefficients: C["Scalar"][],
  commitment: VerifiableSecretSharingCommitment<C>,
  rng: RandomSource,
): DkgSignature<C> {
  // Round 1, Step 2
  //
  // > Every P_i computes a proof of knowledge to the corresponding secret
  // > a_{i0} by calculating sigma_i = (R_i, mu_i), such that k <- Z_q, R_i = g^k,
  // > c_i = H(i, Phi, g^{a_{i0}}, R_i), mu_i = k + a_{i0} * c_i, with Phi being
  // > a context string to prevent replay attacks.
  const k = randomNonzeroScalar(ciphersuite, rng);
  const R_i = ciphersuite.scalarBaseMult(k);

  const verifyingKey = commitment.verifyingKey();
  const c_i = dkgChallenge(ciphersuite, identifier, verifyingKey, R_i);

  const a_i0 = coefficients[0];
  if (a_i0 === undefined) {
    throw FrostError.invalidCoefficients<C>();
  }

  const mu_i = ciphersuite.scalarAdd(k, ciphersuite.scalarMul(a_i0, c_i));

  return { R: R_i, z: mu_i };
}

/**
 * Verifies the proof of knowledge of the secret coefficients used to generate the
 * public secret sharing commitment.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param identifier - The sender's identifier
 * @param commitment - The VSS commitment
 * @param proofOfKnowledge - The proof of knowledge signature
 * @throws {FrostError} If verification fails
 */
export function verifyProofOfKnowledge<C extends Ciphersuite>(
  ciphersuite: C,
  identifier: Identifier<C>,
  commitment: VerifiableSecretSharingCommitment<C>,
  proofOfKnowledge: DkgSignature<C>,
): void {
  // Round 1, Step 5
  //
  // > Upon receiving C_ell, sigma_ell from participants 1 <= ell <= n, ell != i, participant
  // > P_i verifies sigma_ell = (R_ell, mu_ell), aborting on failure, by checking
  // > R_ell ?= g^{mu_ell} * phi^{-c_ell}_{ell0}, where c_ell = H(ell, Phi, phi_{ell0}, R_ell).
  const ell = identifier;
  const R_ell = proofOfKnowledge.R;
  const mu_ell = proofOfKnowledge.z;
  const phi_ell0 = commitment.verifyingKey();
  const c_ell = dkgChallenge(ciphersuite, ell, phi_ell0, R_ell);

  // g^{mu_ell}
  const gMuEll = ciphersuite.scalarBaseMult(mu_ell);

  // phi_ell0 * c_ell
  const phiCEll = ciphersuite.elementMul(phi_ell0, c_ell);

  // g^{mu_ell} - phi_ell0 * c_ell
  const expected = ciphersuite.elementSub(gMuEll, phiCEll);

  if (!ciphersuite.elementsEqual(R_ell, expected)) {
    throw FrostError.invalidProofOfKnowledge<C>(ell);
  }
}

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
 * Performs the second part of the distributed key generation protocol for the
 * participant holding the given SecretPackage, given the received
 * round1::Packages received from the other participants.
 *
 * `round1Packages` maps the identifier of each other participant to the
 * Package they sent to the current participant (the owner of `secretPackage`).
 * These identifiers must come from whatever mapping the participant has between
 * communication channels and participants, i.e. they must have assurance that
 * the Package came from the participant with that identifier.
 *
 * It returns the SecretPackage that must be kept in memory by the
 * participant for the final step, and the map of Packages that must be sent to
 * each other participant who has the given identifier in the map key.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param secretPackage - The round 1 secret package
 * @param round1Packages - Map of identifier string to round 1 packages
 * @returns A tuple of [round2.SecretPackage, Map of round2.Package by identifier string]
 * @throws {FrostError} If validation fails
 */
export function part2<C extends Ciphersuite>(
  ciphersuite: C,
  secretPackage: round1.SecretPackage<C>,
  round1Packages: Map<string, round1.Package<C>>,
): [round2.SecretPackage<C>, Map<string, round2.Package<C>>] {
  if (round1Packages.size !== secretPackage.maxSigners - 1) {
    throw FrostError.incorrectNumberOfPackages<C>();
  }

  for (const pkg of round1Packages.values()) {
    if (pkg.commitment.minSigners() !== secretPackage.minSigners) {
      throw FrostError.incorrectNumberOfCommitments<C>();
    }
  }

  const round2Packages = new Map<string, round2.Package<C>>();

  for (const [senderIdStr, round1Package] of round1Packages) {
    // Parse the identifier from the string key
    const idBytes = hexToBytes(senderIdStr);
    const ell: Identifier<C> = IdentifierClass.deserialize(ciphersuite, idBytes);

    // Round 1, Step 5
    verifyProofOfKnowledge(
      ciphersuite,
      ell,
      round1Package.commitment,
      round1Package.proofOfKnowledge,
    );

    // Round 2, Step 1
    //
    // > Each P_i securely sends to each other participant P_ell a secret share (ell, f_i(ell)),
    // > deleting f_i and each share afterward except for (i, f_i(i)),
    // > which they keep for themselves.
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

  const round2SecretPackage = new round2.SecretPackage(
    ciphersuite,
    secretPackage.identifier,
    secretPackage.commitment,
    fii,
    secretPackage.minSigners,
    secretPackage.maxSigners,
  );

  return [round2SecretPackage, round2Packages];
}

/**
 * Performs the third and final part of the distributed key generation protocol
 * for the participant holding the given SecretPackage, given the
 * received round1::Packages and round2::Packages received from the
 * other participants.
 *
 * `round1Packages` must be the same used in `part2()`.
 *
 * `round2Packages` maps the identifier of each other participant to the
 * Package they sent to the current participant (the owner of
 * `secretPackage`). These identifiers must come from whatever mapping the
 * participant has between communication channels and participants, i.e. they
 * must have assurance that the Package came from the participant
 * with that identifier.
 *
 * It returns the KeyPackage that has the long-lived key share for the
 * participant, and the PublicKeyPackage that has public information about
 * all participants; both of which are required to compute FROST signatures.
 *
 * @param ciphersuite - The ciphersuite to use
 * @param round2SecretPackage - The round 2 secret package
 * @param round1Packages - Map of identifier string to round 1 packages
 * @param round2Packages - Map of identifier string to round 2 packages
 * @returns A Promise of a tuple of [KeyPackage, PublicKeyPackage]
 * @throws {FrostError} If validation fails
 */
export async function part3<C extends Ciphersuite>(
  ciphersuite: C,
  round2SecretPackage: round2.SecretPackage<C>,
  round1Packages: Map<string, round1.Package<C>>,
  round2Packages: Map<string, round2.Package<C>>,
): Promise<[KeyPackage<C>, PublicKeyPackage<C>]> {
  if (round1Packages.size !== round2SecretPackage.maxSigners - 1) {
    throw FrostError.incorrectNumberOfPackages<C>();
  }
  if (round1Packages.size !== round2Packages.size) {
    throw FrostError.incorrectNumberOfPackages<C>();
  }
  for (const id of round1Packages.keys()) {
    if (!round2Packages.has(id)) {
      throw FrostError.incorrectPackage<C>();
    }
  }

  let signingShareScalar = ciphersuite.scalarZero();

  for (const [senderIdStr, round2Package] of round2Packages) {
    // Round 2, Step 2
    //
    // > Each P_i verifies their shares by calculating:
    // > g^{f_ell(i)} ?= product_{k=0}^{t-1} phi^{i^k mod q}_{ell k}, aborting if the
    // > check fails.
    const idBytes = hexToBytes(senderIdStr);
    const ell: Identifier<C> = IdentifierClass.deserialize(ciphersuite, idBytes);
    const f_ell_i = round2Package.signingShare;

    const round1Pkg = round1Packages.get(senderIdStr);
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

    // Verify the share. Identify the culprit if verification fails.
    try {
      secretShare.verify();
    } catch (e: unknown) {
      if (e instanceof FrostError && (e.type as string) === "InvalidSecretShare") {
        throw FrostError.invalidSecretShare<C>(ell);
      }
      throw e;
    }

    // Round 2, Step 3
    //
    // > Each P_i calculates their long-lived private signing share by computing
    // > s_i = sum_{ell=1}^{n} f_ell(i), stores s_i securely, and deletes each f_ell(i).
    signingShareScalar = ciphersuite.scalarAdd(signingShareScalar, f_ell_i.toScalar());
  }

  signingShareScalar = ciphersuite.scalarAdd(signingShareScalar, round2SecretPackage.secretShare());
  const signingShare = new SigningShare(ciphersuite, signingShareScalar);

  // Round 2, Step 4
  //
  // > Each P_i calculates their public verification share Y_i = g^{s_i}.
  const verifyingShare = signingShare.toVerifyingShare();

  // Build commitments map for PublicKeyPackage
  const commitments = new Map<string, VerifiableSecretSharingCommitment<C>>();
  for (const [id, pkg] of round1Packages) {
    commitments.set(id, pkg.commitment);
  }
  // Add own commitment
  const ownIdStr = identifierToString(round2SecretPackage.identifier);
  commitments.set(ownIdStr, round2SecretPackage.commitment);

  const publicKeyPackage = await PublicKeyPackage.fromDkgCommitments(ciphersuite, commitments);

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
