/**
 * JSON serialization (serde) support for FROST P256-SHA256.
 *
 * This module provides JSON serialization and deserialization for all FROST types,
 * matching the Rust serde implementation format.
 *
 * @module serde
 */

import {
  P256Sha256,
  type P256Sha256Impl,
  SigningCommitments,
  NonceCommitment,
  SignatureShare,
  SigningShare,
  VerifyingShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  VerifiableSecretSharingCommitment,
  Identifier,
} from "./index.js";

import { type SigningPackage, SigningPackageImpl, type round1, type round2 } from "@frosts/core";

/**
 * The ciphersuite name for JSON serialization headers.
 */
export const CIPHERSUITE_NAME = "FROST-P256-SHA256-v1";

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
  commitments: SigningCommitments<P256Sha256Impl>,
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
export function signingCommitmentsFromJson(json: unknown): SigningCommitments<P256Sha256Impl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "hiding", "binding"]);
  checkNoExtraFields(obj, ["header", "hiding", "binding"]);
  validateHeader(obj["header"]);

  const hidingBytes = hexToBytes(obj["hiding"] as string);
  const bindingBytes = hexToBytes(obj["binding"] as string);

  const hiding = NonceCommitment.deserialize(P256Sha256, hidingBytes);
  const binding = NonceCommitment.deserialize(P256Sha256, bindingBytes);

  return new SigningCommitments(P256Sha256, hiding, binding);
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
export function signingPackageToJson(pkg: SigningPackage<P256Sha256Impl>): SigningPackageJson {
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
export function signingPackageFromJson(json: unknown): SigningPackage<P256Sha256Impl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "signing_commitments", "message"]);
  checkNoExtraFields(obj, ["header", "signing_commitments", "message"]);
  validateHeader(obj["header"]);

  const commitmentsMap = new Map<Identifier<P256Sha256Impl>, SigningCommitments<P256Sha256Impl>>();
  const commitmentsObj = obj["signing_commitments"] as Record<string, unknown>;

  for (const [idHex, commitmentJson] of Object.entries(commitmentsObj)) {
    const idBytes = hexToBytes(idHex);
    const id = Identifier.deserialize(P256Sha256, idBytes);
    const commitment = signingCommitmentsFromJson(commitmentJson);
    commitmentsMap.set(id, commitment);
  }

  const message = hexToBytes(obj["message"] as string);

  return new SigningPackageImpl(P256Sha256, commitmentsMap, message);
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
export function signatureShareToJson(share: SignatureShare<P256Sha256Impl>): SignatureShareJson {
  return {
    header: { ...DEFAULT_HEADER },
    share: bytesToHex(share.serialize()),
  };
}

/**
 * Deserialize SignatureShare from JSON.
 */
export function signatureShareFromJson(json: unknown): SignatureShare<P256Sha256Impl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "share"]);
  checkNoExtraFields(obj, ["header", "share"]);
  validateHeader(obj["header"]);

  const shareBytes = hexToBytes(obj["share"] as string);
  return SignatureShare.deserialize(P256Sha256, shareBytes);
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
export function secretShareToJson(share: SecretShare<P256Sha256Impl>): SecretShareJson {
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
export function secretShareFromJson(json: unknown): SecretShare<P256Sha256Impl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "identifier", "signing_share", "commitment"]);
  checkNoExtraFields(obj, ["header", "identifier", "signing_share", "commitment"]);
  validateHeader(obj["header"]);

  const idBytes = hexToBytes(obj["identifier"] as string);
  const id = Identifier.deserialize(P256Sha256, idBytes);

  const signingShareBytes = hexToBytes(obj["signing_share"] as string);
  const signingShare = SigningShare.deserialize(P256Sha256, signingShareBytes);

  const commitmentHexes = obj["commitment"] as string[];
  const commitmentBytes = commitmentHexes.map(hexToBytes);
  const commitment = VerifiableSecretSharingCommitment.deserialize(P256Sha256, commitmentBytes);

  return new SecretShare(P256Sha256, id, signingShare, commitment);
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
export function keyPackageToJson(pkg: KeyPackage<P256Sha256Impl>): KeyPackageJson {
  return {
    header: { ...DEFAULT_HEADER },
    identifier: bytesToHex(pkg.identifier.serialize()),
    signing_share: bytesToHex(pkg.signingShare.serialize()),
    verifying_share: bytesToHex(pkg.verifyingShare.serialize()),
    verifying_key: bytesToHex(P256Sha256.serializeElement(pkg.verifyingKey)),
    min_signers: pkg.minSigners,
  };
}

/**
 * Deserialize KeyPackage from JSON.
 */
export function keyPackageFromJson(json: unknown): KeyPackage<P256Sha256Impl> {
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
  const id = Identifier.deserialize(P256Sha256, idBytes);

  const signingShareBytes = hexToBytes(obj["signing_share"] as string);
  const signingShare = SigningShare.deserialize(P256Sha256, signingShareBytes);

  const verifyingShareBytes = hexToBytes(obj["verifying_share"] as string);
  const verifyingShare = VerifyingShare.deserialize(P256Sha256, verifyingShareBytes);

  const verifyingKeyBytes = hexToBytes(obj["verifying_key"] as string);
  const verifyingKey = P256Sha256.deserializeElement(verifyingKeyBytes);

  return new KeyPackage(
    P256Sha256,
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
  pkg: PublicKeyPackage<P256Sha256Impl>,
): PublicKeyPackageJson {
  const verifyingSharesObj: Record<string, string> = {};

  for (const [idHex, share] of pkg.verifyingShares) {
    verifyingSharesObj[idHex] = bytesToHex(share.serialize());
  }

  const result: PublicKeyPackageJson = {
    header: { ...DEFAULT_HEADER },
    verifying_shares: verifyingSharesObj,
    verifying_key: bytesToHex(P256Sha256.serializeElement(pkg.verifyingKey)),
  };

  if (pkg.minSigners !== undefined) {
    result.min_signers = pkg.minSigners;
  }

  return result;
}

/**
 * Deserialize PublicKeyPackage from JSON.
 */
export function publicKeyPackageFromJson(json: unknown): PublicKeyPackage<P256Sha256Impl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "verifying_shares", "verifying_key"]);
  checkNoExtraFields(obj, ["header", "verifying_shares", "verifying_key", "min_signers"]);
  validateHeader(obj["header"]);

  const verifyingSharesObj = obj["verifying_shares"] as Record<string, string>;
  const verifyingShares = new Map<string, VerifyingShare<P256Sha256Impl>>();

  for (const [idHex, shareHex] of Object.entries(verifyingSharesObj)) {
    // Validate the identifier is not all zeros
    const idBytes = hexToBytes(idHex);
    Identifier.deserialize(P256Sha256, idBytes); // This will throw if invalid (all zeros)

    const shareBytes = hexToBytes(shareHex);
    const share = VerifyingShare.deserialize(P256Sha256, shareBytes);
    verifyingShares.set(idHex, share);
  }

  const verifyingKeyBytes = hexToBytes(obj["verifying_key"] as string);
  const verifyingKey = P256Sha256.deserializeElement(verifyingKeyBytes);

  const minSigners = obj["min_signers"] as number | undefined;

  return new PublicKeyPackage(P256Sha256, verifyingShares, verifyingKey, minSigners);
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
 */
export function round1PackageToJson(pkg: round1.Package<P256Sha256Impl>): Round1PackageJson {
  // Serialize the proof of knowledge (DkgSignature) as R || z
  const pokR = P256Sha256.serializeElement(pkg.proofOfKnowledge.R);
  const pokZ = P256Sha256.serializeScalar(pkg.proofOfKnowledge.z);
  const pokBytes = new Uint8Array(pokR.length + pokZ.length);
  pokBytes.set(pokR, 0);
  pokBytes.set(pokZ, pokR.length);

  return {
    header: { ...DEFAULT_HEADER },
    commitment: pkg.commitment.serialize().map(bytesToHex),
    proof_of_knowledge: bytesToHex(pokBytes),
  };
}

/**
 * Deserialize round1::Package from JSON.
 */
export function round1PackageFromJson(json: unknown): round1.Package<P256Sha256Impl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "commitment", "proof_of_knowledge"]);
  checkNoExtraFields(obj, ["header", "commitment", "proof_of_knowledge"]);
  validateHeader(obj["header"]);

  const commitmentHexes = obj["commitment"] as string[];
  const commitmentBytes = commitmentHexes.map(hexToBytes);
  const commitment = VerifiableSecretSharingCommitment.deserialize(P256Sha256, commitmentBytes);

  // Deserialize proof of knowledge from R || z format
  const pokBytes = hexToBytes(obj["proof_of_knowledge"] as string);
  const elementSize = P256Sha256.elementSize();
  const scalarSize = P256Sha256.scalarSize();

  if (pokBytes.length !== elementSize + scalarSize) {
    throw new Error(
      `Invalid proof_of_knowledge length: expected ${elementSize + scalarSize}, got ${pokBytes.length}`,
    );
  }

  const R = P256Sha256.deserializeElement(pokBytes.slice(0, elementSize));
  const z = P256Sha256.deserializeScalar(pokBytes.slice(elementSize));

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
      const pokR = P256Sha256.serializeElement(proofOfKnowledge.R);
      const pokZ = P256Sha256.serializeScalar(proofOfKnowledge.z);
      const pokSerialized = new Uint8Array(pokR.length + pokZ.length);
      pokSerialized.set(pokR, 0);
      pokSerialized.set(pokZ, pokR.length);
      result.push(pokSerialized);
      return result;
    },
  } as unknown as round1.Package<P256Sha256Impl>;
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
export function round2PackageToJson(pkg: round2.Package<P256Sha256Impl>): Round2PackageJson {
  return {
    header: { ...DEFAULT_HEADER },
    signing_share: bytesToHex(pkg.signingShare.serialize()),
  };
}

/**
 * Deserialize round2::Package from JSON.
 */
export function round2PackageFromJson(json: unknown): round2.Package<P256Sha256Impl> {
  if (typeof json !== "object" || json === null) {
    throw new Error("Invalid JSON: expected object");
  }
  const obj = json as Record<string, unknown>;

  checkRequiredFields(obj, ["header", "signing_share"]);
  checkNoExtraFields(obj, ["header", "signing_share"]);
  validateHeader(obj["header"]);

  const signingShareBytes = hexToBytes(obj["signing_share"] as string);
  const signingShare = SigningShare.deserialize(P256Sha256, signingShareBytes);

  // Create a duck-typed round2.Package
  return {
    signingShare,
    serialize(): Uint8Array {
      return signingShare.serialize();
    },
  } as unknown as round2.Package<P256Sha256Impl>;
}
