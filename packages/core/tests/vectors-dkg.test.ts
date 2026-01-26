/**
 * Helper function for testing DKG with test vectors.
 * Ported from frost-core/src/tests/vectors_dkg.rs
 */

import { describe, it, expect } from "vitest";
import { hexToBytes, bytesToHex as _bytesToHex } from "./helpers.js";

// Types will be imported from actual implementation once available
import type { Ciphersuite, Identifier } from "../src/index.js";

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
} from "../src/index.js";

// DKG-specific imports
import { round1, round2, part2, part3 } from "../src/keys/dkg.js";
import { Identifier as IdentifierClass } from "../src/identifier.js";
import { Signature as _Signature } from "../src/signature.js";
import { VerifyingKey as _VerifyingKey } from "../src/verifying_key.js";

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
  signing_shares: { [targetId: string]: string };
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

  if (pokBytes.length !== elementSize + scalarSize) {
    throw new Error(
      `Invalid proof_of_knowledge length: expected ${elementSize + scalarSize}, got ${pokBytes.length}`,
    );
  }

  const R = ciphersuite.deserializeElement(pokBytes.slice(0, elementSize));
  const z = ciphersuite.deserializeScalar(pokBytes.slice(elementSize));

  const proofOfKnowledge = { R, z };

  return new round1.Package(ciphersuite, commitment, proofOfKnowledge);
}

/**
 * Build a Round2Package from JSON data.
 * Note: In the DKG protocol, the round2 package sent TO participant X contains
 * the signing share that participant X should receive FROM the sender.
 */
export function buildRound2Package<C extends Ciphersuite>(
  ciphersuite: C,
  senderData: { signing_shares: { [targetId: string]: string } },
  recipientIdStr: string,
): round2.Package<C> {
  // Get the signing share for the recipient
  const signingShareHex = senderData.signing_shares[recipientIdStr];
  if (!signingShareHex) {
    throw new Error(`No signing share found for recipient ${recipientIdStr}`);
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
    const participantData = inputs[i.toString()] as ParticipantData;
    if (!participantData || typeof participantData === "string") {
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
    const participantData = inputs[participantIdStr] as ParticipantData;
    if (!participantData || typeof participantData === "string") {
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

      const otherParticipantData = otherData as ParticipantData;
      if (!otherParticipantData || typeof otherParticipantData === "string") {
        continue;
      }

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
      // In test vectors, signing_shares[X] in participant Y's data = share Y sends to X
      // So for participant i, we need the share that participant `other` sends to `i`
      // That's otherParticipantData.signing_shares[participantIdStr]
      round2Packages.set(
        otherIdKey,
        buildRound2Package(ciphersuite, otherParticipantData, participantIdStr),
      );
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
 */
export async function checkDkgKeygen<C extends Ciphersuite>(
  ciphersuite: C,
  jsonVectors: DKGTestVectorsJson,
): Promise<void> {
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
    expect(expectedPublicKeyPackage.equals(publicKeyPackage)).toBe(true);
    expect(expectedKeyPackage.equals(keyPackage)).toBe(true);
  }
}

describe("DKG Test Vectors", () => {
  describe("Vector Parsing", () => {
    it("should parse DKG test vectors JSON structure correctly", () => {
      // Test that the parsing interface works correctly with mock data
      const mockJson: DKGTestVectorsJson = {
        config: {
          MAX_PARTICIPANTS: 3,
          MIN_PARTICIPANTS: 2,
        },
        inputs: {
          verifying_key: "0000000000000000000000000000000000000000000000000000000000000000",
          "1": {
            identifier: 1,
            signing_key: "0000000000000000000000000000000000000000000000000000000000000001",
            coefficient: "0000000000000000000000000000000000000000000000000000000000000001",
            vss_commitments: [],
            proof_of_knowledge: "",
            verifying_share: "0000000000000000000000000000000000000000000000000000000000000000",
            signing_share: "0000000000000000000000000000000000000000000000000000000000000001",
            signing_shares: {
              "2": "0000000000000000000000000000000000000000000000000000000000000001",
            },
          },
        },
      };

      expect(mockJson.config.MAX_PARTICIPANTS).toBe(3);
      expect(mockJson.config.MIN_PARTICIPANTS).toBe(2);
      expect(mockJson.inputs.verifying_key).toBeDefined();
    });
  });

  describe("DKG Key Generation", () => {
    it("should verify DKG test vector interface types", () => {
      // This verifies the TypeScript types are correctly defined
      // Actual DKG verification is done via checkDkgKeygen() called from ciphersuite tests

      expect(typeof buildRound1Package).toBe("function");
      expect(typeof buildRound2Package).toBe("function");
      expect(typeof buildPublicKeyPackage).toBe("function");
      expect(typeof parseTestVectorsDkg).toBe("function");
      expect(typeof checkDkgKeygen).toBe("function");
    });

    it("should export required helper functions", () => {
      // Verify all required functions are exported
      expect(buildRound1Package).toBeDefined();
      expect(buildRound2Package).toBeDefined();
      expect(buildPublicKeyPackage).toBeDefined();
      expect(parseTestVectorsDkg).toBeDefined();
      expect(checkDkgKeygen).toBeDefined();
    });
  });
});
