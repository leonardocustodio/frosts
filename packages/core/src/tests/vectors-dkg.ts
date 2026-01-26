/**
 * Helper functions for testing DKG with test vectors.
 * Ported from frost-core/src/tests/vectors_dkg.rs
 *
 * This module provides generic functions to parse and verify DKG test vectors
 * against a FROST ciphersuite implementation.
 */

import { hexToBytes } from "./helpers.js";

// Types will be imported from actual implementation
import type { Ciphersuite, Identifier } from "../index.js";

// Import concrete classes for DKG
import {
  SigningKey,
  SigningShare,
  VerifyingShare,
  KeyPackage,
  PublicKeyPackage,
  VerifiableSecretSharingCommitment,
  generateSecretPolynomial,
  identifierToString,
} from "../index.js";

// DKG-specific imports
import { round1, round2, part2, part3 } from "../keys/dkg.js";
import { Identifier as IdentifierClass } from "../identifier.js";

/**
 * DKG test vectors structure for a ciphersuite.
 */
export interface DKGTestVectors<C extends Ciphersuite> {
  secret: SigningKey<C>;
  coefficient: C["Scalar"];
  round1Packages: Map<string, round1.Package<C>>;
  round2Packages: Map<string, round2.Package<C>>;
  publicKeyPackage: PublicKeyPackage<C>;
  keyPackage: KeyPackage<C>;
  participantId: Identifier<C>;
}

/**
 * Participant data from JSON test vectors.
 */
interface ParticipantData {
  identifier: number;
  signing_key: string;
  coefficient: string;
  vss_commitments: string[];
  proof_of_knowledge: string;
  verifying_share: string;
  signing_share: string;
  signing_shares: Record<string, string>;
  secret?: string;
}

/**
 * JSON structure for DKG test vectors.
 */
export interface DKGTestVectorsJson {
  config: {
    MAX_PARTICIPANTS: number;
    MIN_PARTICIPANTS: number;
    name?: string;
    group?: string;
    hash?: string;
  };
  inputs: {
    verifying_key: string;
    secret?: string;
    [participantId: string]: ParticipantData | string | undefined;
  };
}

/**
 * Build a Round1Package from JSON data.
 */
export function buildRound1Package<C extends Ciphersuite>(
  ciphersuite: C,
  jsonData: {
    vss_commitments: string[];
    proof_of_knowledge: string;
  },
): round1.Package<C> {
  // Parse VSS commitments
  const vssCommitmentBytes = jsonData.vss_commitments.map((v) => hexToBytes(v));
  const commitment = VerifiableSecretSharingCommitment.deserialize(ciphersuite, vssCommitmentBytes);

  // Parse proof of knowledge (DKG Signature: R || z format)
  const pokBytes = hexToBytes(jsonData.proof_of_knowledge);
  const elementSize = ciphersuite.elementSize();
  const scalarSize = ciphersuite.scalarSize();
  // Default to elementSize + scalarSize for standard Schnorr, but ciphersuites like
  // BIP-340/Taproot may override with 64 bytes (2 * scalarSize)
  const signatureLength = ciphersuite.SIGNATURE_LENGTH ?? elementSize + scalarSize;

  let R: C["Element"];
  let z: C["Scalar"];

  // Standard format: elementSize + scalarSize (e.g., 33 + 32 = 65 for secp256k1)
  if (pokBytes.length === elementSize + scalarSize) {
    R = ciphersuite.deserializeElement(pokBytes.slice(0, elementSize));
    z = ciphersuite.deserializeScalar(pokBytes.slice(elementSize));
  }
  // BIP-340/Taproot format: x-only R (32 bytes) + z (32 bytes) = 64 bytes
  else if (pokBytes.length === signatureLength && signatureLength === 2 * scalarSize) {
    // For BIP-340, reconstruct the SEC1 compressed point from x-only R
    // x-only R is the first 32 bytes, prepend 0x02 for even Y (BIP-340 guarantees even Y)
    const xOnlyR = pokBytes.slice(0, scalarSize);
    const fullR = new Uint8Array(elementSize);
    fullR[0] = 0x02; // Even Y prefix for BIP-340
    fullR.set(xOnlyR, 1);
    R = ciphersuite.deserializeElement(fullR);
    z = ciphersuite.deserializeScalar(pokBytes.slice(scalarSize));
  } else {
    throw new Error(
      `Invalid proof_of_knowledge length: expected ${elementSize + scalarSize} or ${signatureLength}, got ${pokBytes.length}`,
    );
  }

  const proofOfKnowledge = { R, z };

  return new round1.Package(ciphersuite, commitment, proofOfKnowledge);
}

/**
 * Build a Round2Package from JSON data.
 * Note: In the test vectors, participant_data.signing_shares[sender_id] contains
 * the share that participant receives FROM sender_id.
 * So for the current participant's round2 packages, we look in the CURRENT
 * participant's data for the share they receive from each sender.
 */
export function buildRound2Package<C extends Ciphersuite>(
  ciphersuite: C,
  recipientData: { signing_shares: Record<string, string> },
  senderIdStr: string,
): round2.Package<C> {
  // Get the signing share that the recipient received from the sender
  const signingShareHex = recipientData.signing_shares[senderIdStr];
  if (signingShareHex === undefined || signingShareHex === "") {
    throw new Error(`No signing share found from sender ${senderIdStr}`);
  }

  const signingShare = SigningShare.deserialize(ciphersuite, hexToBytes(signingShareHex));

  return new round2.Package(ciphersuite, signingShare);
}

/**
 * Build a PublicKeyPackage from JSON data.
 */
export function buildPublicKeyPackage<C extends Ciphersuite>(
  ciphersuite: C,
  jsonVectors: DKGTestVectorsJson,
): PublicKeyPackage<C> {
  const inputs = jsonVectors.inputs;
  const maxParticipants = jsonVectors.config.MAX_PARTICIPANTS;
  const minParticipants = jsonVectors.config.MIN_PARTICIPANTS;

  const verifyingShares = new Map<string, VerifyingShare<C>>();

  for (let i = 1; i <= maxParticipants; i++) {
    const participantData = inputs[i.toString()];
    if (participantData === undefined || typeof participantData === "string") {
      continue;
    }

    const identifier = IdentifierClass.fromU16(ciphersuite, participantData.identifier);
    const idStr = identifierToString(identifier);

    const verifyingShare = VerifyingShare.deserialize(
      ciphersuite,
      hexToBytes(participantData.verifying_share),
    );
    verifyingShares.set(idStr, verifyingShare);
  }

  const verifyingKey = ciphersuite.deserializeElement(hexToBytes(inputs.verifying_key));

  return new PublicKeyPackage(ciphersuite, verifyingShares, verifyingKey, minParticipants);
}

/**
 * Parse DKG test vectors for a given ciphersuite.
 * Returns an array of test vectors, one per participant.
 */
export function parseTestVectorsDkg<C extends Ciphersuite>(
  ciphersuite: C,
  jsonVectors: DKGTestVectorsJson,
): DKGTestVectors<C>[] {
  const vectors: DKGTestVectors<C>[] = [];
  const inputs = jsonVectors.inputs;
  const maxParticipants = jsonVectors.config.MAX_PARTICIPANTS;
  const minSigners = jsonVectors.config.MIN_PARTICIPANTS;

  for (let i = 1; i <= maxParticipants; i++) {
    const participantIdStr = i.toString();
    const participantData = inputs[participantIdStr];
    if (participantData === undefined || typeof participantData === "string") {
      continue;
    }

    const participantId = IdentifierClass.fromU16(ciphersuite, participantData.identifier);

    // Build round1 packages from OTHER participants
    const round1Packages = new Map<string, round1.Package<C>>();
    const round2Packages = new Map<string, round2.Package<C>>();

    for (const [otherIdStr, otherData] of Object.entries(inputs)) {
      if (otherIdStr === participantIdStr) continue;
      if (otherIdStr === "verifying_key" || otherIdStr === "secret") continue;

      const parsedOtherId = parseInt(otherIdStr, 10);
      if (isNaN(parsedOtherId)) continue;

      if (otherData === undefined || typeof otherData === "string") {
        continue;
      }
      const otherParticipantData = otherData;

      const otherId = IdentifierClass.fromU16(ciphersuite, otherParticipantData.identifier);
      const otherIdKey = identifierToString(otherId);

      // Build round 1 package from this other participant
      round1Packages.set(
        otherIdKey,
        buildRound1Package(ciphersuite, {
          vss_commitments: otherParticipantData.vss_commitments,
          proof_of_knowledge: otherParticipantData.proof_of_knowledge,
        }),
      );

      // Build round 2 package: The package FROM the other participant TO the current participant
      // In test vectors, signing_shares[X] in participant's data = share participant receives FROM X
      // So for the current participant, we look in THEIR data (participantData) for the share
      // they receive from the other participant (indexed by otherIdStr)
      round2Packages.set(otherIdKey, buildRound2Package(ciphersuite, participantData, otherIdStr));
    }

    // Parse secret (signing key for this participant)
    const secret = SigningKey.deserialize(ciphersuite, hexToBytes(participantData.signing_key));

    // Parse coefficient
    const coefficient = ciphersuite.deserializeScalar(hexToBytes(participantData.coefficient));

    // Build public key package
    const publicKeyPackage = buildPublicKeyPackage(ciphersuite, jsonVectors);

    // Parse verifying share for this participant
    const verifyingShare = VerifyingShare.deserialize(
      ciphersuite,
      hexToBytes(participantData.verifying_share),
    );

    // Parse verifying key
    const verifyingKey = ciphersuite.deserializeElement(hexToBytes(inputs.verifying_key));

    // Parse signing share for this participant
    const signingShare = SigningShare.deserialize(
      ciphersuite,
      hexToBytes(participantData.signing_share),
    );

    // Build expected key package
    const keyPackage = new KeyPackage(
      ciphersuite,
      participantId,
      signingShare,
      verifyingShare,
      verifyingKey,
      minSigners,
    );

    vectors.push({
      secret,
      coefficient,
      round1Packages,
      round2Packages,
      publicKeyPackage,
      keyPackage,
      participantId,
    });
  }

  return vectors;
}

/**
 * Test DKG with the given test vectors for a ciphersuite.
 * This is the main test function that verifies the DKG flow
 * against known test vectors.
 *
 * @param ciphersuite - The FROST ciphersuite to test
 * @param jsonVectors - The DKG test vectors in JSON format
 * @param assertFn - Optional assertion function (defaults to throwing on failure)
 */
export async function checkDkgKeygen<C extends Ciphersuite>(
  ciphersuite: C,
  jsonVectors: DKGTestVectorsJson,
  assertFn?: (condition: boolean, message: string) => void,
): Promise<void> {
  const assert =
    assertFn ??
    ((cond: boolean, msg: string) => {
      if (!cond) throw new Error(msg);
    });

  const dkgVectorsList = parseTestVectorsDkg(ciphersuite, jsonVectors);

  const minSigners = jsonVectors.config.MIN_PARTICIPANTS;
  const maxSigners = jsonVectors.config.MAX_PARTICIPANTS;

  for (const dkgVectors of dkgVectorsList) {
    const {
      secret,
      coefficient,
      round1Packages,
      round2Packages,
      publicKeyPackage,
      keyPackage,
      participantId,
    } = dkgVectors;

    // Generate secret polynomial using the secret and coefficient from test vectors
    const [coefficients, commitment] = generateSecretPolynomial(
      ciphersuite,
      secret.toScalar(),
      maxSigners,
      minSigners,
      [coefficient],
    );

    // Create round 1 secret package
    const round1SecretPackage = new round1.SecretPackage(
      ciphersuite,
      participantId,
      coefficients,
      commitment,
      minSigners,
      maxSigners,
    );

    // Run DKG part 2 - this processes round 1 packages and produces round 2 packages
    const [round2SecretPackage, _round2PackagesOut] = part2(
      ciphersuite,
      round1SecretPackage,
      round1Packages,
    );

    // Run DKG part 3 - this produces the final key package and public key package
    const [expectedKeyPackage, expectedPublicKeyPackage] = await part3(
      ciphersuite,
      round2SecretPackage,
      round1Packages,
      round2Packages,
    );

    // Verify results match test vectors
    assert(
      expectedPublicKeyPackage.equals(publicKeyPackage),
      `PublicKeyPackage mismatch for participant ${identifierToString(participantId)}`,
    );
    assert(
      expectedKeyPackage.equals(keyPackage),
      `KeyPackage mismatch for participant ${identifierToString(participantId)}`,
    );
  }
}
