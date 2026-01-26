/**
 * JSON serialization (serde) support for FROST secp256k1-SHA256 Taproot.
 *
 * This module provides JSON serialization and deserialization for all FROST types,
 * matching the Rust serde implementation format.
 *
 * Key differences from standard secp256k1:
 * - Ciphersuite name: "FROST-secp256k1-SHA256-TR-v1"
 * - Proof of knowledge is 64 bytes (BIP-340 format) instead of 65 bytes
 *
 * @module serde
 */

import {
  Secp256K1Sha256TR,
  type Secp256K1Sha256TRImpl,
  IdentifierImpl as Identifier,
} from "./index.js";

import {
  type SigningPackage,
  SigningPackageImpl,
  type round1,
  type round2,
  SigningCommitments,
  NonceCommitment,
  SignatureShare,
  SigningShare,
  VerifyingShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  VerifiableSecretSharingCommitment,
} from "@frosts/core";

/**
 * The ciphersuite name for JSON serialization headers.
 */
export const CIPHERSUITE_NAME = "FROST-secp256k1-SHA256-TR-v1";

/**
 * Signature length for BIP-340 format (x-only R + z = 32 + 32 = 64 bytes).
 */
const SIGNATURE_LENGTH = 64;

/**
 * JSON header for serialized FROST structures.
 */
export interface JsonHeader {
  version: number;
  ciphersuite: string;
}

/**
 * Default JSON header.
 */
export const DEFAULT_HEADER: JsonHeader = {
  version: 0,
  ciphersuite: CIPHERSUITE_NAME,
};

/**
 * Convert bytes to hex string (lowercase).
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert hex string to bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (isNaN(byte)) {
      throw new Error(`Invalid hex character at position ${i * 2}`);
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Validate a JSON header.
 */
export function validateHeader(header: unknown): void {
  if (typeof header !== "object" || header === null) {
    throw new Error("Missing or invalid header");
  }
  const h = header as Record<string, unknown>;
  if (h["version"] !== 0) {
    throw new Error(`Invalid version: ${String(h["version"])}, expected 0`);
  }
  if (h["ciphersuite"] !== CIPHERSUITE_NAME) {
    throw new Error(
      `Invalid ciphersuite: ${String(h["ciphersuite"])}, expected ${CIPHERSUITE_NAME}`,
    );
  }
}

/**
 * Check for unexpected fields in a JSON object.
 */
function checkNoExtraFields(obj: Record<string, unknown>, allowedFields: string[]): void {
  const extraFields = Object.keys(obj).filter((k) => !allowedFields.includes(k));
  if (extraFields.length > 0) {
    throw new Error(`Unexpected field(s): ${extraFields.join(", ")}`);
  }
}

/**
 * Check for required fields in a JSON object.
 */
function checkRequiredFields(obj: Record<string, unknown>, requiredFields: string[]): void {
  for (const field of requiredFields) {
    if (!(field in obj)) {
      throw new Error(`Missing required field: ${field}`);
    }
  }
}

// ============================================================================
// SigningCommitments JSON Serialization
// ============================================================================

/**
 * JSON representation of SigningCommitments.
 */
export interface SigningCommitmentsJson {
  header: JsonHeader;
  hiding: string;
  binding: string;
}

/**
 * Serialize SigningCommitments to JSON.
 */
export function signingCommitmentsToJson(
  commitments: SigningCommitments<Secp256K1Sha256TRImpl>,
): SigningCommitmentsJson {
  return {
    header: { ...DEFAULT_HEADER },
    hiding: bytesToHex(commitments.hiding.serialize()),
    binding: bytesToHex(commitments.binding.serialize()),
  };
}

/**
 * Deserialize SigningCommitments from JSON.
 */
export function signingCommitmentsFromJson(
  json: unknown,
): SigningCommitments<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "hiding", "binding"]);
  checkNoExtraFields(obj, ["header", "hiding", "binding"]);
  validateHeader(obj["header"]);

  const hidingBytes = hexToBytes(obj["hiding"] as string);
  const bindingBytes = hexToBytes(obj["binding"] as string);

  const hiding = NonceCommitment.deserialize(Secp256K1Sha256TR, hidingBytes);
  const binding = NonceCommitment.deserialize(Secp256K1Sha256TR, bindingBytes);

  return new SigningCommitments(Secp256K1Sha256TR, hiding, binding);
}

// ============================================================================
// SigningPackage JSON Serialization
// ============================================================================

/**
 * JSON representation of SigningPackage.
 */
export interface SigningPackageJson {
  header: JsonHeader;
  signing_commitments: Record<string, SigningCommitmentsJson>;
  message: string;
}

/**
 * Serialize SigningPackage to JSON.
 */
export function signingPackageToJson(
  pkg: SigningPackage<Secp256K1Sha256TRImpl>,
): SigningPackageJson {
  const commitmentsObj: Record<string, SigningCommitmentsJson> = {};

  for (const [id, commitment] of pkg.signingCommitments) {
    const idHex = bytesToHex(id.serialize());
    commitmentsObj[idHex] = signingCommitmentsToJson(commitment);
  }

  return {
    header: { ...DEFAULT_HEADER },
    signing_commitments: commitmentsObj,
    message: bytesToHex(pkg.message),
  };
}

/**
 * Deserialize SigningPackage from JSON.
 */
export function signingPackageFromJson(json: unknown): SigningPackage<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "signing_commitments", "message"]);
  checkNoExtraFields(obj, ["header", "signing_commitments", "message"]);
  validateHeader(obj["header"]);

  const commitmentsMap = new Map<
    Identifier<Secp256K1Sha256TRImpl>,
    SigningCommitments<Secp256K1Sha256TRImpl>
  >();
  const commitmentsObj = obj["signing_commitments"] as Record<string, unknown>;

  for (const [idHex, commitmentJson] of Object.entries(commitmentsObj)) {
    const idBytes = hexToBytes(idHex);
    const id = Identifier.deserialize(Secp256K1Sha256TR, idBytes);
    const commitment = signingCommitmentsFromJson(commitmentJson);
    commitmentsMap.set(id, commitment);
  }

  const message = hexToBytes(obj["message"] as string);

  return new SigningPackageImpl(Secp256K1Sha256TR, commitmentsMap, message);
}

// ============================================================================
// SignatureShare JSON Serialization
// ============================================================================

/**
 * JSON representation of SignatureShare.
 */
export interface SignatureShareJson {
  header: JsonHeader;
  share: string;
}

/**
 * Serialize SignatureShare to JSON.
 */
export function signatureShareToJson(
  share: SignatureShare<Secp256K1Sha256TRImpl>,
): SignatureShareJson {
  return {
    header: { ...DEFAULT_HEADER },
    share: bytesToHex(share.serialize()),
  };
}

/**
 * Deserialize SignatureShare from JSON.
 */
export function signatureShareFromJson(json: unknown): SignatureShare<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "share"]);
  checkNoExtraFields(obj, ["header", "share"]);
  validateHeader(obj["header"]);

  const shareBytes = hexToBytes(obj["share"] as string);
  return SignatureShare.deserialize(Secp256K1Sha256TR, shareBytes);
}

// ============================================================================
// SecretShare JSON Serialization
// ============================================================================

/**
 * JSON representation of SecretShare.
 */
export interface SecretShareJson {
  header: JsonHeader;
  identifier: string;
  signing_share: string;
  commitment: string[];
}

/**
 * Serialize SecretShare to JSON.
 */
export function secretShareToJson(share: SecretShare<Secp256K1Sha256TRImpl>): SecretShareJson {
  return {
    header: { ...DEFAULT_HEADER },
    identifier: bytesToHex(share.identifier.serialize()),
    signing_share: bytesToHex(share.signingShare.serialize()),
    commitment: share.commitment.serialize().map(bytesToHex),
  };
}

/**
 * Deserialize SecretShare from JSON.
 */
export function secretShareFromJson(json: unknown): SecretShare<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "identifier", "signing_share", "commitment"]);
  checkNoExtraFields(obj, ["header", "identifier", "signing_share", "commitment"]);
  validateHeader(obj["header"]);

  const idBytes = hexToBytes(obj["identifier"] as string);
  const id = Identifier.deserialize(Secp256K1Sha256TR, idBytes);

  const signingShareBytes = hexToBytes(obj["signing_share"] as string);
  const signingShare = SigningShare.deserialize(Secp256K1Sha256TR, signingShareBytes);

  const commitmentHexes = obj["commitment"] as string[];
  const commitmentBytes = commitmentHexes.map(hexToBytes);
  const commitment = VerifiableSecretSharingCommitment.deserialize(
    Secp256K1Sha256TR,
    commitmentBytes,
  );

  return new SecretShare(Secp256K1Sha256TR, id, signingShare, commitment);
}

// ============================================================================
// KeyPackage JSON Serialization
// ============================================================================

/**
 * JSON representation of KeyPackage.
 */
export interface KeyPackageJson {
  header: JsonHeader;
  identifier: string;
  signing_share: string;
  verifying_share: string;
  verifying_key: string;
  min_signers: number;
}

/**
 * Serialize KeyPackage to JSON.
 */
export function keyPackageToJson(pkg: KeyPackage<Secp256K1Sha256TRImpl>): KeyPackageJson {
  return {
    header: { ...DEFAULT_HEADER },
    identifier: bytesToHex(pkg.identifier.serialize()),
    signing_share: bytesToHex(pkg.signingShare.serialize()),
    verifying_share: bytesToHex(pkg.verifyingShare.serialize()),
    verifying_key: bytesToHex(Secp256K1Sha256TR.serializeElement(pkg.verifyingKey)),
    min_signers: pkg.minSigners,
  };
}

/**
 * Deserialize KeyPackage from JSON.
 */
export function keyPackageFromJson(json: unknown): KeyPackage<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, [
    "header",
    "identifier",
    "signing_share",
    "verifying_share",
    "verifying_key",
    "min_signers",
  ]);
  checkNoExtraFields(obj, [
    "header",
    "identifier",
    "signing_share",
    "verifying_share",
    "verifying_key",
    "min_signers",
  ]);
  validateHeader(obj["header"]);

  const idBytes = hexToBytes(obj["identifier"] as string);
  const id = Identifier.deserialize(Secp256K1Sha256TR, idBytes);

  const signingShareBytes = hexToBytes(obj["signing_share"] as string);
  const signingShare = SigningShare.deserialize(Secp256K1Sha256TR, signingShareBytes);

  const verifyingShareBytes = hexToBytes(obj["verifying_share"] as string);
  const verifyingShare = VerifyingShare.deserialize(Secp256K1Sha256TR, verifyingShareBytes);

  const verifyingKeyBytes = hexToBytes(obj["verifying_key"] as string);
  const verifyingKey = Secp256K1Sha256TR.deserializeElement(verifyingKeyBytes);

  return new KeyPackage(
    Secp256K1Sha256TR,
    id,
    signingShare,
    verifyingShare,
    verifyingKey,
    obj["min_signers"] as number,
  );
}

// ============================================================================
// PublicKeyPackage JSON Serialization
// ============================================================================

/**
 * JSON representation of PublicKeyPackage.
 */
export interface PublicKeyPackageJson {
  header: JsonHeader;
  verifying_shares: Record<string, string>;
  verifying_key: string;
  min_signers?: number;
}

/**
 * Serialize PublicKeyPackage to JSON.
 */
export function publicKeyPackageToJson(
  pkg: PublicKeyPackage<Secp256K1Sha256TRImpl>,
): PublicKeyPackageJson {
  const verifyingSharesObj: Record<string, string> = {};

  for (const [idHex, share] of pkg.verifyingShares) {
    verifyingSharesObj[idHex] = bytesToHex(share.serialize());
  }

  const result: PublicKeyPackageJson = {
    header: { ...DEFAULT_HEADER },
    verifying_shares: verifyingSharesObj,
    verifying_key: bytesToHex(Secp256K1Sha256TR.serializeElement(pkg.verifyingKey)),
  };

  if (pkg.minSigners !== undefined) {
    result.min_signers = pkg.minSigners;
  }

  return result;
}

/**
 * Deserialize PublicKeyPackage from JSON.
 */
export function publicKeyPackageFromJson(json: unknown): PublicKeyPackage<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "verifying_shares", "verifying_key"]);
  checkNoExtraFields(obj, ["header", "verifying_shares", "verifying_key", "min_signers"]);
  validateHeader(obj["header"]);

  const verifyingSharesObj = obj["verifying_shares"] as Record<string, string>;
  const verifyingShares = new Map<string, VerifyingShare<Secp256K1Sha256TRImpl>>();

  for (const [idHex, shareHex] of Object.entries(verifyingSharesObj)) {
    // Validate the identifier is not all zeros
    const idBytes = hexToBytes(idHex);
    Identifier.deserialize(Secp256K1Sha256TR, idBytes); // This will throw if invalid (all zeros)

    const shareBytes = hexToBytes(shareHex);
    const share = VerifyingShare.deserialize(Secp256K1Sha256TR, shareBytes);
    verifyingShares.set(idHex, share);
  }

  const verifyingKeyBytes = hexToBytes(obj["verifying_key"] as string);
  const verifyingKey = Secp256K1Sha256TR.deserializeElement(verifyingKeyBytes);

  const minSigners = obj["min_signers"] as number | undefined;

  return new PublicKeyPackage(Secp256K1Sha256TR, verifyingShares, verifyingKey, minSigners);
}

// ============================================================================
// Round1 Package JSON Serialization
// ============================================================================

/**
 * JSON representation of round1::Package.
 */
export interface Round1PackageJson {
  header: JsonHeader;
  commitment: string[];
  proof_of_knowledge: string;
}

/**
 * Serialize round1::Package to JSON.
 *
 * For Taproot, the proof of knowledge is serialized in BIP-340 format:
 * x-only R (32 bytes) + z (32 bytes) = 64 bytes total.
 */
export function round1PackageToJson(pkg: round1.Package<Secp256K1Sha256TRImpl>): Round1PackageJson {
  // Serialize the proof of knowledge in BIP-340 format (64 bytes)
  // x-only R (32 bytes) + z (32 bytes)
  const pokR = Secp256K1Sha256TR.serializeElement(pkg.proofOfKnowledge.R);
  const pokZ = Secp256K1Sha256TR.serializeScalar(pkg.proofOfKnowledge.z);

  // For BIP-340, R is x-only (32 bytes), so we skip the prefix byte
  const pokBytes = new Uint8Array(SIGNATURE_LENGTH);
  pokBytes.set(pokR.slice(1), 0); // x-only R (skip prefix byte)
  pokBytes.set(pokZ, 32);

  return {
    header: { ...DEFAULT_HEADER },
    commitment: pkg.commitment.serialize().map(bytesToHex),
    proof_of_knowledge: bytesToHex(pokBytes),
  };
}

/**
 * Deserialize round1::Package from JSON.
 *
 * For Taproot, the proof of knowledge is in BIP-340 format:
 * x-only R (32 bytes) + z (32 bytes) = 64 bytes total.
 */
export function round1PackageFromJson(json: unknown): round1.Package<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "commitment", "proof_of_knowledge"]);
  checkNoExtraFields(obj, ["header", "commitment", "proof_of_knowledge"]);
  validateHeader(obj["header"]);

  const commitmentHexes = obj["commitment"] as string[];
  const commitmentBytes = commitmentHexes.map(hexToBytes);
  const commitment = VerifiableSecretSharingCommitment.deserialize(
    Secp256K1Sha256TR,
    commitmentBytes,
  );

  // Deserialize proof of knowledge from BIP-340 format (64 bytes)
  const pokBytes = hexToBytes(obj["proof_of_knowledge"] as string);

  if (pokBytes.length !== SIGNATURE_LENGTH) {
    throw new Error(
      `Invalid proof_of_knowledge length: expected ${SIGNATURE_LENGTH}, got ${pokBytes.length}`,
    );
  }

  // Reconstruct R from x-only format (add 0x02 prefix for even Y)
  const elementSize = Secp256K1Sha256TR.elementSize();

  const rBytes = new Uint8Array(elementSize);
  rBytes[0] = 0x02; // BIP-340 R always has even Y
  rBytes.set(pokBytes.slice(0, 32), 1);

  const R = Secp256K1Sha256TR.deserializeElement(rBytes);
  const z = Secp256K1Sha256TR.deserializeScalar(pokBytes.slice(32));

  // Create DkgSignature object
  const proofOfKnowledge = { R, z };

  // Create a duck-typed round1.Package
  return {
    commitment,
    proofOfKnowledge,
    serialize(): Uint8Array[] {
      const result: Uint8Array[] = [];
      for (const c of commitment.serialize()) {
        result.push(c);
      }
      // Serialize in BIP-340 format
      const pokR = Secp256K1Sha256TR.serializeElement(proofOfKnowledge.R);
      const pokZ = Secp256K1Sha256TR.serializeScalar(proofOfKnowledge.z);
      const pokSerialized = new Uint8Array(SIGNATURE_LENGTH);
      pokSerialized.set(pokR.slice(1), 0); // x-only R
      pokSerialized.set(pokZ, 32);
      result.push(pokSerialized);
      return result;
    },
  } as unknown as round1.Package<Secp256K1Sha256TRImpl>;
}

// ============================================================================
// Round2 Package JSON Serialization
// ============================================================================

/**
 * JSON representation of round2::Package.
 */
export interface Round2PackageJson {
  header: JsonHeader;
  signing_share: string;
}

/**
 * Serialize round2::Package to JSON.
 */
export function round2PackageToJson(pkg: round2.Package<Secp256K1Sha256TRImpl>): Round2PackageJson {
  return {
    header: { ...DEFAULT_HEADER },
    signing_share: bytesToHex(pkg.signingShare.serialize()),
  };
}

/**
 * Deserialize round2::Package from JSON.
 */
export function round2PackageFromJson(json: unknown): round2.Package<Secp256K1Sha256TRImpl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "signing_share"]);
  checkNoExtraFields(obj, ["header", "signing_share"]);
  validateHeader(obj["header"]);

  const signingShareBytes = hexToBytes(obj["signing_share"] as string);
  const signingShare = SigningShare.deserialize(Secp256K1Sha256TR, signingShareBytes);

  // Create a duck-typed round2.Package
  return {
    signingShare,
    serialize(): Uint8Array {
      return signingShare.serialize();
    },
  } as unknown as round2.Package<Secp256K1Sha256TRImpl>;
}
