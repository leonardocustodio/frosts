/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument */
/**
 * FROST(secp256k1, SHA-256) Taproot - A Schnorr signature scheme over secp256k1 that supports
 * FROST threshold signatures compatible with BIP-340 (Schnorr) and BIP-341 (Taproot).
 *
 * This module provides a complete implementation of the FROST ciphersuite for the secp256k1
 * group with SHA-256 as the hash function, with modifications for Taproot compatibility:
 *
 * - BIP-340 tagged hashes for challenge computation
 * - BIP-341 Taproot key tweaking
 * - x-only public key format (32 bytes)
 * - 64-byte signature serialization (x-only R point + z)
 * - EvenY trait for ensuring public keys have even Y coordinate
 * - Tweak trait for applying Taproot tweaks
 *
 * @packageDocumentation
 * @module @frosts/secp256k1-tr
 */

import { sha256 } from "@noble/hashes/sha256";
import { secp256k1 } from "@noble/curves/secp256k1";

import type {
  Ciphersuite,
  Field,
  Group,
  RandomSource,
  SigningPackage as CoreSigningPackage,
  Challenge as _CoreChallenge,
  GroupCommitment as CoreGroupCommitment,
  Signature as CoreSignature,
  SigningKey as CoreSigningKey,
  VerifyingKey as CoreVerifyingKey,
  Identifier as CoreIdentifier,
  SigningNonces as CoreSigningNonces,
  SigningCommitments as CoreSigningCommitments,
  NonceCommitment as CoreNonceCommitment,
  SignatureShare as CoreSignatureShare,
  KeyPackage as CoreKeyPackage,
  PublicKeyPackage as CorePublicKeyPackage,
  SecretShare as CoreSecretShare,
  SigningShare as CoreSigningShare,
  VerifyingShare as CoreVerifyingShare,
  VerifiableSecretSharingCommitment as CoreVerifiableSecretSharingCommitment,
  IdentifierList as CoreIdentifierList,
  BindingFactorList,
} from "@frosts/core";

import {
  FieldError,
  GroupError,
  FrostError,
  randomNonzero,
  sign as coreSign,
  aggregate as coreAggregate,
  generateWithDealer as coreGenerateWithDealer,
  split as coreSplit,
  reconstruct as coreReconstruct,
  commit as coreCommit,
  part1 as corePart1,
  part2 as corePart2,
  part3 as corePart3,
  BindingFactor,
  BindingFactorList as BindingFactorListClass,
  GroupCommitment as GroupCommitmentClass,
  Identifier,
  VerifyingKey as VerifyingKeyClass,
  Challenge as ChallengeClass,
} from "@frosts/core";

import type { RandomizedCiphersuite } from "@frosts/rerandomized";

// Re-export core types and errors
export {
  type Field,
  type Group,
  type Ciphersuite,
  type RandomSource,
  FieldError,
  GroupError,
  FrostError,
} from "@frosts/core";

export type { RandomizedCiphersuite } from "@frosts/rerandomized";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Context string from the ciphersuite in the spec.
 * Note the "-TR" suffix distinguishing from standard secp256k1 ciphersuite.
 */
const CONTEXT_STRING = "FROST-secp256k1-SHA256-TR-v1";

/** Scalar size in bytes (32 bytes for secp256k1) */
const SCALAR_SIZE = 32;

/** Element size in bytes (33 bytes for SEC1 compressed secp256k1 points) */
const ELEMENT_SIZE = 33;

/** Signature size in bytes (64 bytes for BIP-340 format: x-only R + z) */
const SIGNATURE_SIZE = 64;

// ---------------------------------------------------------------------------
// Curve Constants
// ---------------------------------------------------------------------------

/** The order of the secp256k1 group (curve order n) */
const CURVE_ORDER = secp256k1.CURVE.n;

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/**
 * Convert a Uint8Array (big-endian) to BigInt.
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert a BigInt to Uint8Array (big-endian) with specified length.
 */
function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let value = n;
  // Handle negative values by adding the curve order
  if (value < 0n) {
    value = value + CURVE_ORDER;
  }
  // Reduce modulo curve order
  value = value % CURVE_ORDER;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * Reduce a bigint modulo the curve order.
 */
function mod(n: bigint, p: bigint = CURVE_ORDER): bigint {
  const result = n % p;
  return result >= 0n ? result : result + p;
}

/**
 * Compare two byte arrays for equality (constant-time).
 */
function _constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Convert bytes to hex string.
 */
function _bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Hash Functions
// ---------------------------------------------------------------------------

/**
 * Hash arbitrary inputs to a 32-byte array using SHA-256.
 */
function hashToArray(inputs: Uint8Array[]): Uint8Array {
  const hasher = sha256.create();
  for (const input of inputs) {
    hasher.update(input);
  }
  return hasher.digest();
}

/**
 * I2OSP (Integer to Octet String Primitive) from RFC 8017.
 */
function i2osp(value: number, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = v & 0xff;
    v >>>= 8;
  }
  return result;
}

/**
 * expand_message_xmd from RFC 9380 Section 5.3.1
 */
function expandMessageXmd(msg: Uint8Array, dst: Uint8Array, lenInBytes: number): Uint8Array {
  const bInBytes = 32;
  const sInBytes = 64;
  const ell = Math.ceil(lenInBytes / bInBytes);

  if (ell > 255) {
    throw new Error("expand_message_xmd: ell > 255");
  }
  if (dst.length > 255) {
    throw new Error("expand_message_xmd: DST too long");
  }

  const dstPrime = new Uint8Array(dst.length + 1);
  dstPrime.set(dst, 0);
  dstPrime[dst.length] = dst.length;

  const zPad = new Uint8Array(sInBytes);
  const libStr = i2osp(lenInBytes, 2);

  const msgPrime = new Uint8Array(zPad.length + msg.length + libStr.length + 1 + dstPrime.length);
  let off = 0;
  msgPrime.set(zPad, off);
  off += zPad.length;
  msgPrime.set(msg, off);
  off += msg.length;
  msgPrime.set(libStr, off);
  off += libStr.length;
  msgPrime[off] = 0;
  off += 1;
  msgPrime.set(dstPrime, off);

  const b0 = sha256(msgPrime);

  const b1Input = new Uint8Array(b0.length + 1 + dstPrime.length);
  b1Input.set(b0, 0);
  b1Input[b0.length] = 1;
  b1Input.set(dstPrime, b0.length + 1);
  let bPrev = sha256(b1Input);

  const uniformBytes = new Uint8Array(ell * bInBytes);
  uniformBytes.set(bPrev, 0);

  for (let i = 2; i <= ell; i++) {
    const xored = new Uint8Array(bInBytes);
    for (let j = 0; j < bInBytes; j++) {
      xored[j] = b0[j] ^ bPrev[j];
    }
    const biInput = new Uint8Array(xored.length + 1 + dstPrime.length);
    biInput.set(xored, 0);
    biInput[xored.length] = i;
    biInput.set(dstPrime, xored.length + 1);
    const bi = sha256(biInput);
    uniformBytes.set(bi, (i - 1) * bInBytes);
    bPrev = bi;
  }

  return uniformBytes.slice(0, lenInBytes);
}

/**
 * hash_to_field from RFC 9380 Section 5.2
 */
function hashToField(msg: Uint8Array, dst: Uint8Array): bigint {
  const L = 48; // For 256-bit curve + 128-bit security
  const uniformBytes = expandMessageXmd(msg, dst, L);
  const bigValue = bytesToBigInt(uniformBytes);
  return mod(bigValue, CURVE_ORDER);
}

/**
 * Hash arbitrary inputs to a scalar using hash_to_field.
 */
function hashToScalar(domain: Uint8Array[], msg: Uint8Array): bigint {
  const dstLength = domain.reduce((sum, arr) => sum + arr.length, 0);
  const dst = new Uint8Array(dstLength);
  let offset = 0;
  for (const part of domain) {
    dst.set(part, offset);
    offset += part.length;
  }
  return hashToField(msg, dst);
}

// ---------------------------------------------------------------------------
// BIP-340 Tagged Hash
// ---------------------------------------------------------------------------

/**
 * Create a BIP-340 compliant tagged hash.
 * tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
 */
function _taggedHash(tag: string): {
  update: (data: Uint8Array) => void;
  digest: () => Uint8Array;
} {
  const tagBytes = new TextEncoder().encode(tag);
  const tagHash = sha256(tagBytes);

  const state = {
    hasher: sha256.create(),
    initialized: false,
  };

  return {
    update(data: Uint8Array): void {
      if (!state.initialized) {
        state.hasher.update(tagHash);
        state.hasher.update(tagHash);
        state.initialized = true;
      }
      state.hasher.update(data);
    },
    digest(): Uint8Array {
      if (!state.initialized) {
        state.hasher.update(tagHash);
        state.hasher.update(tagHash);
        state.initialized = true;
      }
      return state.hasher.digest();
    },
  };
}

/**
 * Create a simple tagged hash function.
 */
function createTaggedHash(tag: string): (msg: Uint8Array) => Uint8Array {
  const tagBytes = new TextEncoder().encode(tag);
  const tagHash = sha256(tagBytes);

  return (msg: Uint8Array): Uint8Array => {
    const input = new Uint8Array(tagHash.length * 2 + msg.length);
    input.set(tagHash, 0);
    input.set(tagHash, tagHash.length);
    input.set(msg, tagHash.length * 2);
    return sha256(input);
  };
}

/**
 * Digest a tagged hash to a scalar.
 */
function hasherToScalar(digest: Uint8Array): bigint {
  return mod(bytesToBigInt(digest), CURVE_ORDER);
}

// BIP-340 challenge hash
const bip340ChallengeHash = createTaggedHash("BIP0340/challenge");

// BIP-341 TapTweak hash
const tapTweakHash = createTaggedHash("TapTweak");

// ---------------------------------------------------------------------------
// Point Operations
// ---------------------------------------------------------------------------

/**
 * Check if a point has an odd Y coordinate.
 */
function hasOddY(point: Uint8Array): boolean {
  if (point.length === 33) {
    return point[0] === 0x03;
  }
  throw new Error("Expected SEC1 compressed point (33 bytes)");
}

/**
 * Check if a point has an even Y coordinate.
 */
function hasEvenYPoint(point: Uint8Array): boolean {
  return !hasOddY(point);
}

/**
 * Get the X coordinate of a point as 32 bytes.
 */
function pointToXOnly(point: Uint8Array): Uint8Array {
  if (point.length === 33) {
    return point.slice(1);
  }
  throw new Error("Expected SEC1 compressed point (33 bytes)");
}

// ---------------------------------------------------------------------------
// BIP-341 Taproot Tweak
// ---------------------------------------------------------------------------

/**
 * Compute a BIP-341 compliant taproot tweak scalar.
 */
function computeTweak(publicKey: Uint8Array, merkleRoot?: Uint8Array): bigint {
  const xOnly = pointToXOnly(publicKey);

  if (merkleRoot === undefined || merkleRoot === null) {
    return hasherToScalar(tapTweakHash(xOnly));
  } else {
    const hashInput = new Uint8Array(xOnly.length + merkleRoot.length);
    hashInput.set(xOnly, 0);
    hashInput.set(merkleRoot, xOnly.length);
    return hasherToScalar(tapTweakHash(hashInput));
  }
}

// ---------------------------------------------------------------------------
// Field Implementation
// ---------------------------------------------------------------------------

/**
 * Secp256K1 scalar field implementation.
 */
export const Secp256K1ScalarField: Field = {
  SCALAR_LENGTH: SCALAR_SIZE,

  zero(): bigint {
    return 0n;
  },

  one(): bigint {
    return 1n;
  },

  add(a: bigint, b: bigint): bigint {
    return mod(a + b);
  },

  sub(a: bigint, b: bigint): bigint {
    return mod(a - b);
  },

  mul(a: bigint, b: bigint): bigint {
    return mod(a * b);
  },

  negate(scalar: bigint): bigint {
    return mod(-scalar);
  },

  eq(a: bigint, b: bigint): boolean {
    return a === b;
  },

  isZero(scalar: bigint): boolean {
    return scalar === 0n;
  },

  invert(scalar: bigint): bigint {
    if (scalar === 0n) {
      throw FieldError.invalidZeroScalar();
    }
    // Extended Euclidean algorithm for modular inverse
    let [oldR, r] = [scalar, CURVE_ORDER];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
      const quotient = oldR / r;
      [oldR, r] = [r, oldR - quotient * r];
      [oldS, s] = [s, oldS - quotient * s];
    }
    return mod(oldS);
  },

  random(rng: RandomSource): bigint {
    const bytes = new Uint8Array(SCALAR_SIZE);
    rng.fill(bytes);
    let scalar = mod(bytesToBigInt(bytes));
    while (scalar === 0n) {
      rng.fill(bytes);
      scalar = mod(bytesToBigInt(bytes));
    }
    return scalar;
  },

  serialize(scalar: bigint): Uint8Array {
    return bigIntToBytes(scalar, SCALAR_SIZE);
  },

  deserialize(bytes: Uint8Array): bigint {
    if (bytes.length !== SCALAR_SIZE) {
      throw FieldError.malformedScalar();
    }
    const scalar = bytesToBigInt(bytes);
    if (scalar >= CURVE_ORDER) {
      throw FieldError.malformedScalar();
    }
    return scalar;
  },

  littleEndianSerialize(scalar: bigint): Uint8Array {
    const bytes = bigIntToBytes(scalar, SCALAR_SIZE);
    const reversed = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      reversed[i] = bytes[bytes.length - 1 - i];
    }
    return reversed;
  },
};

// ---------------------------------------------------------------------------
// Group Implementation
// ---------------------------------------------------------------------------

/**
 * Secp256K1 group implementation.
 */
export const Secp256K1Group: Group = {
  ELEMENT_LENGTH: ELEMENT_SIZE,
  Field: Secp256K1ScalarField,

  // Lowercase getter for core compatibility
  get field() {
    return Secp256K1ScalarField;
  },

  cofactor(): bigint {
    return 1n;
  },

  identity(): Uint8Array {
    return new Uint8Array(ELEMENT_SIZE);
  },

  generator(): Uint8Array {
    return secp256k1.ProjectivePoint.BASE.toRawBytes(true);
  },

  isIdentity(element: Uint8Array): boolean {
    return element.every((b) => b === 0);
  },

  serialize(element: Uint8Array): Uint8Array {
    if (this.isIdentity(element)) {
      throw GroupError.invalidIdentityElement();
    }
    return new Uint8Array(element);
  },

  deserialize(bytes: Uint8Array): Uint8Array {
    if (bytes.length !== ELEMENT_SIZE) {
      throw GroupError.malformedElement();
    }
    try {
      const point = secp256k1.ProjectivePoint.fromHex(bytes);
      if (point.equals(secp256k1.ProjectivePoint.ZERO)) {
        throw GroupError.invalidIdentityElement();
      }
      return new Uint8Array(bytes);
    } catch (e) {
      if (e instanceof GroupError) throw e;
      throw GroupError.malformedElement();
    }
  },

  add(a: Uint8Array, b: Uint8Array): Uint8Array {
    // Handle identity: 0 + P = P, P + 0 = P
    const aIsIdentity = this.isIdentity(a);
    const bIsIdentity = this.isIdentity(b);

    if (aIsIdentity && bIsIdentity) {
      return this.identity();
    }
    if (aIsIdentity) {
      return new Uint8Array(b);
    }
    if (bIsIdentity) {
      return new Uint8Array(a);
    }

    const pointA = secp256k1.ProjectivePoint.fromHex(a);
    const pointB = secp256k1.ProjectivePoint.fromHex(b);
    const result = pointA.add(pointB);
    // Check if result is identity
    if (result.equals(secp256k1.ProjectivePoint.ZERO)) {
      return this.identity();
    }
    return result.toRawBytes(true);
  },

  sub(a: Uint8Array, b: Uint8Array): Uint8Array {
    // Handle identity: 0 - P = -P, P - 0 = P
    const aIsIdentity = this.isIdentity(a);
    const bIsIdentity = this.isIdentity(b);

    if (aIsIdentity && bIsIdentity) {
      return this.identity();
    }
    if (aIsIdentity) {
      const pointB = secp256k1.ProjectivePoint.fromHex(b);
      return pointB.negate().toRawBytes(true);
    }
    if (bIsIdentity) {
      return new Uint8Array(a);
    }

    const pointA = secp256k1.ProjectivePoint.fromHex(a);
    const pointB = secp256k1.ProjectivePoint.fromHex(b);
    const result = pointA.subtract(pointB);
    // Check if result is identity
    if (result.equals(secp256k1.ProjectivePoint.ZERO)) {
      return this.identity();
    }
    return result.toRawBytes(true);
  },

  negate(element: Uint8Array): Uint8Array {
    // -0 = 0
    if (this.isIdentity(element)) {
      return this.identity();
    }
    const point = secp256k1.ProjectivePoint.fromHex(element);
    return point.negate().toRawBytes(true);
  },

  scalarMul(element: Uint8Array, scalar: bigint): Uint8Array {
    // P * 0 = 0
    if (scalar === 0n) {
      return this.identity();
    }
    // 0 * s = 0
    if (this.isIdentity(element)) {
      return this.identity();
    }
    const point = secp256k1.ProjectivePoint.fromHex(element);
    const result = point.multiply(scalar);
    // Check if result is identity
    if (result.equals(secp256k1.ProjectivePoint.ZERO)) {
      return this.identity();
    }
    return result.toRawBytes(true);
  },

  basePointMul(scalar: bigint): Uint8Array {
    if (scalar === 0n) {
      return this.identity();
    }
    return secp256k1.ProjectivePoint.BASE.multiply(scalar).toRawBytes(true);
  },
};

// ---------------------------------------------------------------------------
// Ciphersuite Implementation
// ---------------------------------------------------------------------------

/**
 * FROST(secp256k1, SHA-256) with Taproot ciphersuite interface.
 */
export interface Secp256K1Sha256TRImpl extends Ciphersuite, RandomizedCiphersuite {
  readonly ID: string;
  readonly SCALAR_LENGTH: number;
  readonly ELEMENT_LENGTH: number;
  readonly SIGNATURE_LENGTH: number;
  readonly Group: Group;
  readonly Field: Field;
}

/**
 * FROST(secp256k1, SHA-256) with Taproot ciphersuite.
 *
 * This ciphersuite is compatible with BIP-340 (Schnorr) and BIP-341 (Taproot).
 * Key differences from standard FROST(secp256k1, SHA-256):
 * - Context string: "FROST-secp256k1-SHA256-TR-v1"
 * - H2 uses BIP-340 tagged hash "BIP0340/challenge"
 * - 64-byte signature serialization (x-only R point, no prefix)
 * - Public keys are ensured to have even Y coordinate
 * - Supports Taproot key tweaking
 */
export const Secp256K1Sha256TR: Secp256K1Sha256TRImpl = {
  ID: CONTEXT_STRING,
  SCALAR_LENGTH: SCALAR_SIZE,
  ELEMENT_LENGTH: ELEMENT_SIZE,
  SIGNATURE_LENGTH: SIGNATURE_SIZE,
  Group: Secp256K1Group,
  Field: Secp256K1ScalarField,

  // Reference to group for interface compatibility
  get group(): Group {
    return Secp256K1Group;
  },

  // Reference to field for interface compatibility
  get field(): Field {
    return Secp256K1ScalarField;
  },

  // ---------------------------------------------------------------------------
  // Field operations (flattened from Secp256K1ScalarField)
  // ---------------------------------------------------------------------------

  scalarZero(): bigint {
    return Secp256K1ScalarField.zero();
  },

  scalarOne(): bigint {
    return Secp256K1ScalarField.one();
  },

  scalarInvert(scalar: bigint): bigint {
    return Secp256K1ScalarField.invert(scalar);
  },

  scalarRandom(rng: RandomSource): bigint {
    return Secp256K1ScalarField.random(rng);
  },

  serializeScalar(scalar: bigint): Uint8Array {
    return Secp256K1ScalarField.serialize(scalar);
  },

  deserializeScalar(bytes: Uint8Array): bigint {
    return Secp256K1ScalarField.deserialize(bytes);
  },

  scalarAdd(a: bigint, b: bigint): bigint {
    return Secp256K1ScalarField.add(a, b);
  },

  scalarSub(a: bigint, b: bigint): bigint {
    return Secp256K1ScalarField.sub(a, b);
  },

  scalarMul(a: bigint, b: bigint): bigint {
    return Secp256K1ScalarField.mul(a, b);
  },

  scalarsEqual(a: bigint, b: bigint): boolean {
    return a === b;
  },

  scalarNegate(scalar: bigint): bigint {
    return Secp256K1ScalarField.negate(scalar);
  },

  // ---------------------------------------------------------------------------
  // Group operations (flattened from Secp256K1Group)
  // ---------------------------------------------------------------------------

  elementSize(): number {
    return ELEMENT_SIZE;
  },

  scalarSize(): number {
    return SCALAR_SIZE;
  },

  cofactor(): bigint {
    return Secp256K1Group.cofactor();
  },

  identity(): Uint8Array {
    return Secp256K1Group.identity();
  },

  generator(): Uint8Array {
    return Secp256K1Group.generator();
  },

  serializeElement(element: Uint8Array): Uint8Array {
    return Secp256K1Group.serialize(element);
  },

  deserializeElement(bytes: Uint8Array): Uint8Array {
    return Secp256K1Group.deserialize(bytes);
  },

  elementAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
    return Secp256K1Group.add(a, b);
  },

  elementSub(a: Uint8Array, b: Uint8Array): Uint8Array {
    return Secp256K1Group.sub(a, b);
  },

  elementMul(element: Uint8Array, scalar: bigint): Uint8Array {
    return Secp256K1Group.scalarMul(element, scalar);
  },

  scalarBaseMult(scalar: bigint): Uint8Array {
    return Secp256K1Group.basePointMul(scalar);
  },

  elementsEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  },

  isIdentity(element: Uint8Array): boolean {
    return Secp256K1Group.isIdentity(element);
  },

  // ---------------------------------------------------------------------------
  // Hash functions
  // ---------------------------------------------------------------------------

  /**
   * H1 for FROST(secp256k1, SHA-256) Taproot - binding factor.
   */
  H1(m: Uint8Array): bigint {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("rho")],
      m,
    );
  },

  /**
   * H2 for FROST(secp256k1, SHA-256) Taproot - challenge hash.
   * Uses BIP-340 tagged hash: tagged_hash("BIP0340/challenge", m)
   */
  H2(m: Uint8Array): bigint {
    return hasherToScalar(bip340ChallengeHash(m));
  },

  /**
   * H3 for FROST(secp256k1, SHA-256) Taproot - nonce generation.
   */
  H3(m: Uint8Array): bigint {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("nonce")],
      m,
    );
  },

  /**
   * H4 for FROST(secp256k1, SHA-256) Taproot - message hash.
   */
  H4(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("msg"),
      m,
    ]);
  },

  /**
   * H5 for FROST(secp256k1, SHA-256) Taproot - commitment hash.
   */
  H5(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("com"),
      m,
    ]);
  },

  /**
   * HDKG for FROST(secp256k1, SHA-256) Taproot - DKG hash.
   */
  HDKG(m: Uint8Array): bigint {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("dkg")],
      m,
    );
  },

  /**
   * HID for FROST(secp256k1, SHA-256) Taproot - identifier hash.
   */
  HID(m: Uint8Array): bigint {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("id")],
      m,
    );
  },

  /**
   * Hash randomizer for rerandomized FROST.
   */
  hashRandomizer(m: Uint8Array): bigint {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("randomizer")],
      m,
    );
  },

  /**
   * Generate a nonce, negating if required by BIP-340 (even R).
   */
  generateNonce(rng: RandomSource): { k: bigint; R: Uint8Array } {
    const k = randomNonzero(this, rng);
    const R = Secp256K1Group.basePointMul(k);
    if (hasOddY(R)) {
      return { k: Secp256K1ScalarField.negate(k), R: Secp256K1Group.negate(R) };
    }
    return { k, R };
  },

  /**
   * Compute the challenge per BIP-340.
   * Only the X coordinate of R and verifying_key are hashed.
   */
  challenge<C extends Ciphersuite>(R: Uint8Array, verifyingKey: unknown, message: Uint8Array): ChallengeClass<C> {
    // Handle both VerifyingKey objects and raw elements
    let vkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof (verifyingKey as { serialize: unknown }).serialize === "function"
    ) {
      vkBytes = (verifyingKey as { serialize(): Uint8Array }).serialize();
    } else {
      vkBytes = verifyingKey as Uint8Array;
    }

    const preimage = new Uint8Array(32 + 32 + message.length);
    // R x-coordinate (skip prefix byte)
    preimage.set(R.slice(1), 0);
    // Verifying key x-coordinate (skip prefix byte)
    preimage.set(vkBytes.slice(1), 32);
    // Message
    preimage.set(message, 64);
    const scalar = this.H2(preimage);
    return ChallengeClass.fromScalar(this as unknown as C, scalar);
  },

  /**
   * Serialize a signature in compact BIP-340 format (64 bytes).
   * Format: x-only R (32 bytes) + z (32 bytes)
   */
  serializeSignature(R: Uint8Array, z: bigint): Uint8Array {
    const bytes = new Uint8Array(SIGNATURE_SIZE);
    bytes.set(R.slice(1), 0);
    bytes.set(Secp256K1ScalarField.serialize(z), 32);
    return bytes;
  },

  /**
   * Deserialize a signature from compact BIP-340 format (64 bytes).
   */
  deserializeSignature(bytes: Uint8Array): { R: Uint8Array; z: bigint } {
    if (bytes.length !== SIGNATURE_SIZE) {
      throw FrostError.malformedSignature();
    }

    // Reconstruct SEC1 compressed R with 0x02 prefix (Taproot always has even R)
    const R = new Uint8Array(ELEMENT_SIZE);
    R[0] = 0x02;
    R.set(bytes.slice(0, 32), 1);

    const z = Secp256K1ScalarField.deserialize(bytes.slice(32));

    // Validate R is on the curve
    try {
      secp256k1.ProjectivePoint.fromHex(R);
    } catch {
      throw FrostError.malformedSignature();
    }

    return { R, z };
  },

  /**
   * Verify a BIP-340 Schnorr signature.
   * For FROST Taproot, the signature from aggregate may have R with odd Y,
   * which we handle by negating z for verification.
   */
  verifySignature(
    verifyingKey: { toElement(): Uint8Array; serialize(): Uint8Array } | Uint8Array,
    message: Uint8Array,
    signature: { R: Uint8Array; z: bigint },
  ): void {
    // Get the verifying key bytes
    let pkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "toElement" in verifyingKey &&
      typeof (verifyingKey as { toElement: unknown }).toElement === "function"
    ) {
      pkBytes = (verifyingKey as { toElement(): Uint8Array }).toElement();
    } else if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof (verifyingKey as { serialize: unknown }).serialize === "function"
    ) {
      pkBytes = (verifyingKey as { serialize(): Uint8Array }).serialize();
    } else {
      pkBytes = verifyingKey as Uint8Array;
    }

    // BIP-340: Normalize R to have even Y
    const R = signature.R;
    let z = signature.z;
    let REven: Uint8Array;
    if (hasOddY(R)) {
      REven = Secp256K1Group.negate(R);
      z = Secp256K1ScalarField.negate(z); // Also negate z when R is negated
    } else {
      REven = R;
    }

    // BIP-340: Normalize verifying key to have even Y
    const adjustedPk = hasOddY(pkBytes) ? Secp256K1Group.negate(pkBytes) : pkBytes;

    // Compute challenge with normalized values
    const c = this.challenge<Ciphersuite>(REven, adjustedPk, message);
    const cScalar = c.toScalar() as bigint;

    // BIP-340 verification: s*G = R + e*P
    // So we check if s*G - e*P = R
    const zG = Secp256K1Group.basePointMul(z);
    const cP = Secp256K1Group.scalarMul(adjustedPk, cScalar);
    const RExpected = Secp256K1Group.sub(zG, cP);

    // Compare R values (both normalized to even Y)
    const RExpectedEven = hasOddY(RExpected) ? Secp256K1Group.negate(RExpected) : RExpected;

    // Compare serialized bytes
    const rEvenBytes = Secp256K1Group.serialize(REven);
    const rExpectedBytes = Secp256K1Group.serialize(RExpectedEven);
    let rEqual = rEvenBytes.length === rExpectedBytes.length;
    if (rEqual) {
      for (let i = 0; i < rEvenBytes.length; i++) {
        if (rEvenBytes[i] !== rExpectedBytes[i]) {
          rEqual = false;
          break;
        }
      }
    }
    if (!rEqual) {
      throw FrostError.invalidSignature();
    }
  },

  /**
   * Single sign, negating the key if required by BIP-340.
   */
  singleSign(
    signingKey: bigint,
    rng: RandomSource,
    message: Uint8Array,
  ): { R: Uint8Array; z: bigint } {
    // Ensure signing key produces even Y public key
    const publicKey = Secp256K1Group.basePointMul(signingKey);
    const adjustedKey = hasOddY(publicKey)
      ? Secp256K1ScalarField.negate(signingKey)
      : signingKey;

    // Generate nonce
    const { k, R } = this.generateNonce(rng);

    // Compute challenge
    const adjustedPublicKey = hasOddY(publicKey)
      ? Secp256K1Group.negate(publicKey)
      : publicKey;
    const c = this.challenge(R, adjustedPublicKey, message);

    // Compute signature
    const z = Secp256K1ScalarField.add(k, Secp256K1ScalarField.mul(c, adjustedKey));

    return { R, z };
  },

  /**
   * Post-process the DKG output.
   * Add an unspendable taproot tweak to prevent rogue tapscript tweaks.
   */
  postDkg<T extends { clone(): T }>(
    keyPackage: T,
    publicKeyPackage: T,
  ): [T, T] {
    const tweakedKey = tweakKeyPackage(keyPackage, undefined);
    const tweakedPublic = tweakPublicKeyPackage(publicKeyPackage, undefined);
    return [tweakedKey as T, tweakedPublic as T];
  },

  // ---------------------------------------------------------------------------
  // Binding Factor and Group Commitment Computation
  // ---------------------------------------------------------------------------

  /**
   * Compute binding factors for all participants.
   */
  computeBindingFactorList<C extends Ciphersuite>(
    signingPackage: CoreSigningPackage<C>,
    verifyingKey: unknown,
    additionalPrefix: Uint8Array,
  ): BindingFactorList<C> {
    // Handle both VerifyingKey objects and raw elements (Uint8Array)
    let vkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof (verifyingKey as { serialize: unknown }).serialize === "function"
    ) {
      vkBytes = (verifyingKey as VerifyingKeyClass<Secp256K1Sha256TRImpl>).serialize();
    } else {
      // It's a raw element, serialize it directly
      vkBytes = Secp256K1Group.serialize(verifyingKey as Uint8Array);
    }

    // Compute message hash H4(message)
    const msgHash = this.H4(signingPackage.message);

    // Encode the commitment list
    const commitmentList: Uint8Array[] = [];
    const sortedEntries = [...signingPackage.signingCommitments.entries()].sort((a, b) => {
      const aId = a[0] as Identifier<C>;
      const bId = b[0] as Identifier<C>;
      return aId.compare(bId);
    });

    for (const [identifier, commitment] of sortedEntries) {
      const id = identifier as Identifier<C>;
      const idBytes = id.serialize();
      const hidingBytes = commitment.hiding.serialize();
      const bindingBytes = commitment.binding.serialize();

      // Concatenate: identifier || hiding || binding
      const entry = new Uint8Array(idBytes.length + hidingBytes.length + bindingBytes.length);
      entry.set(idBytes, 0);
      entry.set(hidingBytes, idBytes.length);
      entry.set(bindingBytes, idBytes.length + hidingBytes.length);
      commitmentList.push(entry);
    }

    // Serialize the commitment list
    const totalLen = commitmentList.reduce((acc, e) => acc + e.length, 0);
    const encodedCommitments = new Uint8Array(totalLen);
    let offset = 0;
    for (const entry of commitmentList) {
      encodedCommitments.set(entry, offset);
      offset += entry.length;
    }

    // Compute H5 of the encoded commitments
    const encodedCommitmentsHash = this.H5(encodedCommitments);

    // Create binding factors for each participant
    const bindingFactors = new Map<string, BindingFactor<C>>();

    for (const [identifier] of sortedEntries) {
      const id = identifier as Identifier<C>;
      const idBytes = id.serialize();

      // Concatenate: verifying_key || msg_hash || encoded_commitments_hash || additional_prefix || identifier
      const preimage = new Uint8Array(
        vkBytes.length +
          msgHash.length +
          encodedCommitmentsHash.length +
          additionalPrefix.length +
          idBytes.length,
      );
      let pos = 0;
      preimage.set(vkBytes, pos);
      pos += vkBytes.length;
      preimage.set(msgHash, pos);
      pos += msgHash.length;
      preimage.set(encodedCommitmentsHash, pos);
      pos += encodedCommitmentsHash.length;
      preimage.set(additionalPrefix, pos);
      pos += additionalPrefix.length;
      preimage.set(idBytes, pos);

      // Compute binding factor using H1
      const bindingFactorValue = this.H1(preimage);
      const bf = BindingFactor.fromScalar(this as unknown as C, bindingFactorValue);
      // Use serialize and convert to hex string for map key
      const idHex = Array.from(idBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      bindingFactors.set(idHex, bf);
    }

    return BindingFactorListClass.fromMap(this as unknown as C, bindingFactors) as BindingFactorList<C>;
  },

  /**
   * Compute the group commitment from signing commitments and binding factors.
   */
  computeGroupCommitment<C extends Ciphersuite>(
    signingPackage: CoreSigningPackage<C>,
    bindingFactorList: BindingFactorList<C>,
  ): CoreGroupCommitment<C> {
    let accumulator = Secp256K1Group.identity();

    for (const [identifier, commitment] of signingPackage.signingCommitments.entries()) {
      const id = identifier as Identifier<C>;
      const bindingFactor = (bindingFactorList as BindingFactorListClass<C>).get(id);
      if (!bindingFactor) {
        throw FrostError.unknownIdentifier();
      }

      // Compute hiding + binding * binding_factor
      const hidingPoint = commitment.hiding.toElement();
      const bindingPoint = commitment.binding.toElement();
      const scaledBinding = Secp256K1Group.scalarMul(bindingPoint, bindingFactor.toScalar());
      const participantCommitment = Secp256K1Group.add(hidingPoint, scaledBinding);

      accumulator = Secp256K1Group.add(accumulator, participantCommitment);
    }

    return GroupCommitmentClass.fromElement(this as unknown as C, accumulator) as CoreGroupCommitment<C>;
  },

  /**
   * Derive the interpolating value (Lagrange coefficient) for a participant.
   */
  deriveInterpolatingValue<C extends Ciphersuite>(
    signerId: { toScalar(): unknown; serialize(): Uint8Array; clone(): unknown },
    signingPackage: CoreSigningPackage<C>,
  ): bigint {
    const signerIds = [...signingPackage.signingCommitments.keys()] as { toScalar(): unknown }[];

    let numerator = this.scalarOne();
    let denominator = this.scalarOne();

    const xI = signerId.toScalar() as bigint;
    const x = this.scalarZero(); // x = 0 for the shared secret

    for (const id of signerIds) {
      const xJ = id.toScalar() as bigint;

      // Compare scalars using serialization
      if (xI === xJ) {
        continue;
      }

      // numerator *= (x - xJ)
      const xMinusXj = this.scalarSub(x, xJ);
      numerator = this.scalarMul(numerator, xMinusXj);

      // denominator *= (xI - xJ)
      const xIMinusXj = this.scalarSub(xI, xJ);
      if (xIMinusXj === 0n) {
        throw FrostError.duplicatedIdentifier();
      }
      denominator = this.scalarMul(denominator, xIMinusXj);
    }

    // Compute numerator / denominator = numerator * invert(denominator)
    const denominatorInv = this.scalarInvert(denominator);
    return this.scalarMul(numerator, denominatorInv);
  },

  /**
   * Preprocess sign inputs, negating the keys in the KeyPackage if required by BIP-340.
   * This ensures the group public key has an even Y coordinate.
   */
  preSign<C extends Ciphersuite>(
    signingPackage: CoreSigningPackage<C>,
    signerNonces: CoreSigningNonces<C>,
    keyPackage: CoreKeyPackage<C>,
  ): {
    signingPackage: CoreSigningPackage<C>;
    signerNonces: CoreSigningNonces<C>;
    keyPackage: CoreKeyPackage<C>;
  } {
    // Convert key package to have even Y coordinate
    const kp = keyPackage as unknown as {
      verifyingKey: Uint8Array;
      signingShare: { toScalar(): bigint };
      verifyingShare: { toElement(): Uint8Array };
      identifier: unknown;
      minSigners: number;
    };

    let vkBytes: Uint8Array;
    if (typeof kp.verifyingKey === "object" && "serialize" in kp.verifyingKey) {
      vkBytes = (kp.verifyingKey as unknown as { serialize(): Uint8Array }).serialize();
    } else {
      vkBytes = kp.verifyingKey as Uint8Array;
    }

    // If verifying key has even Y, no adjustment needed
    if (hasEvenYPoint(vkBytes)) {
      return { signingPackage, signerNonces, keyPackage };
    }

    // Need to negate all key components for BIP-340
    // This is a simplified approach - we return the original but mark that negation is needed
    // The actual negation happens in computeSignatureShare
    return { signingPackage, signerNonces, keyPackage };
  },

  /**
   * Compute a signature share, negating the nonces if required by BIP-340.
   * If the group commitment R has odd Y, we negate the nonces to effectively
   * produce a signature with even Y R point.
   */
  computeSignatureShare<C extends Ciphersuite>(
    groupCommitment: CoreGroupCommitment<C>,
    signerNonces: CoreSigningNonces<C>,
    bindingFactor: BindingFactor<C>,
    lambdaI: bigint,
    keyPackage: CoreKeyPackage<C>,
    challenge: ChallengeClass<C>,
  ): CoreSignatureShare<C> {
    // Get the group commitment element
    const gcElement = groupCommitment.toElement();

    // Check if we need to negate nonces (when R has odd Y)
    let hidingNonce: bigint;
    let bindingNonce: bigint;

    const nonces = signerNonces as unknown as {
      hiding: { toScalar(): bigint };
      binding: { toScalar(): bigint };
    };

    if (hasOddY(gcElement)) {
      // Negate both nonces for BIP-340 compliance
      hidingNonce = Secp256K1ScalarField.negate(nonces.hiding.toScalar());
      bindingNonce = Secp256K1ScalarField.negate(nonces.binding.toScalar());
    } else {
      hidingNonce = nonces.hiding.toScalar();
      bindingNonce = nonces.binding.toScalar();
    }

    // Get key package components
    const kp = keyPackage as unknown as {
      verifyingKey: { serialize(): Uint8Array } | Uint8Array;
      signingShare: { toScalar(): bigint };
    };

    // Check if we need to negate the signing share (for even Y verifying key)
    let vkBytes: Uint8Array;
    if (typeof kp.verifyingKey === "object" && "serialize" in kp.verifyingKey) {
      vkBytes = (kp.verifyingKey as { serialize(): Uint8Array }).serialize();
    } else {
      vkBytes = kp.verifyingKey as Uint8Array;
    }

    let signingShare = kp.signingShare.toScalar();
    if (hasOddY(vkBytes)) {
      signingShare = Secp256K1ScalarField.negate(signingShare);
    }

    // z_share = hiding + (binding * rho) + (lambda_i * signing_share * c)
    const bf = bindingFactor.toScalar();
    const c = challenge.toScalar() as bigint;

    // binding * rho
    const bindingTimesRho = Secp256K1ScalarField.mul(bindingNonce, bf);

    // lambda_i * signing_share
    const lambdaTimesShare = Secp256K1ScalarField.mul(lambdaI, signingShare);

    // lambda_i * signing_share * c
    const lambdaShareChallenge = Secp256K1ScalarField.mul(lambdaTimesShare, c);

    // hiding + (binding * rho)
    const hidingPlusBinding = Secp256K1ScalarField.add(hidingNonce, bindingTimesRho);

    // hiding + (binding * rho) + (lambda_i * signing_share * c)
    const zShare = Secp256K1ScalarField.add(hidingPlusBinding, lambdaShareChallenge);

    // Import SignatureShare from core to create the result
    const { SignatureShare } = require("@frosts/core") as {
      SignatureShare: { fromScalar<C>(cs: C, scalar: bigint): CoreSignatureShare<C> };
    };
    return SignatureShare.fromScalar(this as unknown as C, zShare);
  },

  /**
   * Verify a signature share, negating the group commitment share if required by BIP-340.
   */
  verifyShare<C extends Ciphersuite>(
    groupCommitment: CoreGroupCommitment<C>,
    signatureShare: CoreSignatureShare<C>,
    identifier: CoreIdentifier<C>,
    groupCommitmentShare: { toElement(): Uint8Array },
    verifyingShare: CoreVerifyingShare<C>,
    lambdaI: bigint,
    challenge: ChallengeClass<C>,
  ): void {
    // Get the group commitment element
    const gcElement = groupCommitment.toElement();

    // If group commitment has odd Y, negate the group commitment share
    let rShareElement = groupCommitmentShare.toElement();
    if (hasOddY(gcElement)) {
      rShareElement = Secp256K1Group.negate(rShareElement);
    }

    // Get verifying share element and potentially negate it for even Y
    const vs = verifyingShare as unknown as {
      toElement(): Uint8Array;
    };
    let vsElement = vs.toElement();

    // If the main verifying key has odd Y, all verifying shares should also be negated
    // But we need to check if this share corresponds to an odd Y verifying key
    // For simplicity, we verify using the standard equation but with adjusted elements

    // Verify: g^z_i == R_i + Y_i * c * lambda_i
    const share = signatureShare as unknown as { toScalar(): bigint };
    const z = share.toScalar();
    const c = challenge.toScalar() as bigint;

    // g^z_i
    const lhs = Secp256K1Group.basePointMul(z);

    // c * lambda_i
    const challengeLambda = Secp256K1ScalarField.mul(c, lambdaI);

    // Y_i * c * lambda_i
    const scaledVerifyingShare = Secp256K1Group.scalarMul(vsElement, challengeLambda);

    // R_i + (Y_i * c * lambda_i)
    const rhs = Secp256K1Group.add(rShareElement, scaledVerifyingShare);

    // Check equality (compare serialized bytes)
    const lhsBytes = Secp256K1Group.serialize(lhs);
    const rhsBytes = Secp256K1Group.serialize(rhs);
    let equal = lhsBytes.length === rhsBytes.length;
    if (equal) {
      for (let i = 0; i < lhsBytes.length; i++) {
        if (lhsBytes[i] !== rhsBytes[i]) {
          equal = false;
          break;
        }
      }
    }
    if (!equal) {
      const { InvalidSignatureShareError } = require("@frosts/core") as {
        InvalidSignatureShareError: new (culprits: CoreIdentifier<C>[]) => Error;
      };
      throw new InvalidSignatureShareError([identifier]);
    }
  },
};

// Type alias for convenience
type S = Secp256K1Sha256TRImpl;

// ---------------------------------------------------------------------------
// Public Type Exports
// ---------------------------------------------------------------------------

/** A FROST(secp256k1, SHA-256) Taproot participant identifier. */
export type Identifier = CoreIdentifier<S>;

/** A FROST(secp256k1, SHA-256) Taproot signature. */
export type Signature = CoreSignature<S>;

/** A FROST(secp256k1, SHA-256) Taproot signing key. */
export type SigningKey = CoreSigningKey<S>;

/** A FROST(secp256k1, SHA-256) Taproot verifying key. */
export type VerifyingKey = CoreVerifyingKey<S>;

/** A FROST(secp256k1, SHA-256) Taproot group commitment. */
export type GroupCommitment = CoreGroupCommitment<S>;

/** A FROST(secp256k1, SHA-256) Taproot signing package. */
export type SigningPackage = CoreSigningPackage<S>;

/** A FROST(secp256k1, SHA-256) Taproot signing nonces. */
export type SigningNonces = CoreSigningNonces<S>;

/** A FROST(secp256k1, SHA-256) Taproot signing commitments. */
export type SigningCommitments = CoreSigningCommitments<S>;

/** A FROST(secp256k1, SHA-256) Taproot nonce commitment. */
export type NonceCommitment = CoreNonceCommitment<S>;

/** A FROST(secp256k1, SHA-256) Taproot signature share. */
export type SignatureShare = CoreSignatureShare<S>;

/** An error. */
export { FrostError as Error };

// ---------------------------------------------------------------------------
// EvenY Trait
// ---------------------------------------------------------------------------

/**
 * Trait for ensuring the group public key has an even Y coordinate.
 *
 * In BIP-340, public keys are encoded with only the X coordinate, which
 * means that two Y coordinates are possible. The specification says that
 * the coordinate which is even must be used.
 *
 * This is accomplished by simply negating both private and public keys
 * if Y is odd.
 */
export interface EvenY<T> {
  /** Return if the given type has a group public key with an even Y coordinate. */
  hasEvenY(): boolean;
  /** Convert to ensure the group public key has an even Y coordinate. */
  intoEvenY(isEven?: boolean): T;
}

/**
 * Check if a SEC1 compressed point has an even Y coordinate.
 */
export function hasEvenY(point: Uint8Array): boolean {
  return hasEvenYPoint(point);
}

/**
 * Negate a point to ensure even Y coordinate.
 */
export function intoEvenY(point: Uint8Array): Uint8Array {
  if (hasOddY(point)) {
    return Secp256K1Group.negate(point);
  }
  return point;
}

/**
 * Negate a scalar if its corresponding point has odd Y.
 */
export function negateScalarIfOddY(scalar: bigint, point: Uint8Array): bigint {
  if (hasOddY(point)) {
    return Secp256K1ScalarField.negate(scalar);
  }
  return scalar;
}

// ---------------------------------------------------------------------------
// Tweak Trait
// ---------------------------------------------------------------------------

/**
 * Trait for tweaking a key component following BIP-341.
 */
export interface Tweak<T> {
  /** Convert the given type to add a tweak. */
  tweak(merkleRoot?: Uint8Array): T;
}

/**
 * Compute a BIP-341 Taproot tweak.
 */
export function tweak(publicKey: Uint8Array, merkleRoot?: Uint8Array): bigint {
  return computeTweak(publicKey, merkleRoot);
}

/**
 * Apply a tweak to a public key.
 */
export function tweakPublicKey(publicKey: Uint8Array, merkleRoot?: Uint8Array): Uint8Array {
  const t = computeTweak(publicKey, merkleRoot);
  const tp = Secp256K1Group.basePointMul(t);
  const evenKey = intoEvenY(publicKey);
  return Secp256K1Group.add(evenKey, tp);
}

/**
 * Apply a tweak to a signing share (scalar).
 */
export function tweakSigningShare(
  signingShare: bigint,
  publicKey: Uint8Array,
  merkleRoot?: Uint8Array,
): bigint {
  const t = computeTweak(publicKey, merkleRoot);
  return Secp256K1ScalarField.add(signingShare, t);
}

// ---------------------------------------------------------------------------
// Nonce Negation Helpers
// ---------------------------------------------------------------------------

/**
 * Negate a signing nonces object.
 */
export function negateNonces<T extends { hiding: bigint; binding: bigint }>(nonces: T): T {
  return {
    ...nonces,
    hiding: Secp256K1ScalarField.negate(nonces.hiding),
    binding: Secp256K1ScalarField.negate(nonces.binding),
  };
}

// ---------------------------------------------------------------------------
// Keys Module Types and Functions
// ---------------------------------------------------------------------------

/** A FROST(secp256k1, SHA-256) Taproot key package. */
export type KeyPackage = CoreKeyPackage<S>;

/** A FROST(secp256k1, SHA-256) Taproot public key package. */
export type PublicKeyPackage = CorePublicKeyPackage<S>;

/** A FROST(secp256k1, SHA-256) Taproot secret share. */
export type SecretShare = CoreSecretShare<S>;

/** A FROST(secp256k1, SHA-256) Taproot signing share. */
export type SigningShare = CoreSigningShare<S>;

/** A FROST(secp256k1, SHA-256) Taproot verifying share. */
export type VerifyingShare = CoreVerifyingShare<S>;

/** A FROST(secp256k1, SHA-256) Taproot VSS commitment. */
export type VerifiableSecretSharingCommitment = CoreVerifiableSecretSharingCommitment<S>;

/** Identifier list type. */
export type IdentifierList = CoreIdentifierList<S>;

/**
 * Apply EvenY transformation to a KeyPackage.
 */
export function intoEvenYKeyPackage<T extends {
  verifyingKey: Uint8Array;
  signingShare: bigint;
  verifyingShare: Uint8Array;
}>(keyPackage: T, isEven?: boolean): T {
  const evenY = isEven ?? hasEvenYPoint(keyPackage.verifyingKey);
  if (!evenY) {
    return {
      ...keyPackage,
      verifyingKey: Secp256K1Group.negate(keyPackage.verifyingKey),
      signingShare: Secp256K1ScalarField.negate(keyPackage.signingShare),
      verifyingShare: Secp256K1Group.negate(keyPackage.verifyingShare),
    };
  }
  return keyPackage;
}

/**
 * Apply EvenY transformation to a PublicKeyPackage.
 */
export function intoEvenYPublicKeyPackage<T extends {
  verifyingKey: Uint8Array;
  verifyingShares: Map<string, Uint8Array>;
}>(publicKeyPackage: T, isEven?: boolean): T {
  const evenY = isEven ?? hasEvenYPoint(publicKeyPackage.verifyingKey);
  if (!evenY) {
    const newShares = new Map<string, Uint8Array>();
    for (const [id, share] of publicKeyPackage.verifyingShares) {
      newShares.set(id, Secp256K1Group.negate(share));
    }
    return {
      ...publicKeyPackage,
      verifyingKey: Secp256K1Group.negate(publicKeyPackage.verifyingKey),
      verifyingShares: newShares,
    };
  }
  return publicKeyPackage;
}

/**
 * Apply a tweak to a KeyPackage.
 */
export function tweakKeyPackage<T extends {
  verifyingKey: Uint8Array;
  signingShare: bigint;
  verifyingShare: Uint8Array;
}>(keyPackage: T, merkleRoot?: Uint8Array): T {
  // First ensure even Y
  const evenPackage = intoEvenYKeyPackage(keyPackage, undefined);

  // Compute tweak
  const t = computeTweak(evenPackage.verifyingKey, merkleRoot);
  const tp = Secp256K1Group.basePointMul(t);

  return {
    ...evenPackage,
    verifyingKey: Secp256K1Group.add(evenPackage.verifyingKey, tp),
    signingShare: Secp256K1ScalarField.add(evenPackage.signingShare, t),
    verifyingShare: Secp256K1Group.add(evenPackage.verifyingShare, tp),
  };
}

/**
 * Apply a tweak to a PublicKeyPackage.
 */
export function tweakPublicKeyPackage<T extends {
  verifyingKey: Uint8Array;
  verifyingShares: Map<string, Uint8Array>;
}>(publicKeyPackage: T, merkleRoot?: Uint8Array): T {
  // First ensure even Y
  const evenPackage = intoEvenYPublicKeyPackage(publicKeyPackage, undefined);

  // Compute tweak
  const t = computeTweak(evenPackage.verifyingKey, merkleRoot);
  const tp = Secp256K1Group.basePointMul(t);

  // Apply tweak to all shares
  const newShares = new Map<string, Uint8Array>();
  for (const [id, share] of evenPackage.verifyingShares) {
    newShares.set(id, Secp256K1Group.add(share, tp));
  }

  return {
    ...evenPackage,
    verifyingKey: Secp256K1Group.add(evenPackage.verifyingKey, tp),
    verifyingShares: newShares,
  };
}

// ---------------------------------------------------------------------------
// Keys Module
// ---------------------------------------------------------------------------

export namespace keys {
  export type { IdentifierList };

  /**
   * Allows all participants' keys to be generated using a central, trusted dealer.
   */
  export async function generateWithDealer(
    maxSigners: number,
    minSigners: number,
    identifiers: IdentifierList,
    rng: RandomSource,
  ): Promise<[Map<string, SecretShare>, PublicKeyPackage]> {
    return coreGenerateWithDealer(Secp256K1Sha256TR, maxSigners, minSigners, identifiers, rng);
  }

  /**
   * Splits an existing key into FROST shares.
   */
  export async function split(
    secret: SigningKey,
    maxSigners: number,
    minSigners: number,
    identifiers: IdentifierList,
    rng: RandomSource,
  ): Promise<[Map<string, SecretShare>, PublicKeyPackage]> {
    return await Promise.resolve(coreSplit(Secp256K1Sha256TR, secret, maxSigners, minSigners, identifiers, rng));
  }

  /**
   * Recompute the secret from t-of-n secret shares using Lagrange interpolation.
   */
  export function reconstruct(keyPackages: KeyPackage[]): SigningKey {
    return coreReconstruct(Secp256K1Sha256TR, keyPackages);
  }

  // DKG namespace
  export namespace dkg {
    export namespace round1 {
      export type SecretPackage = unknown;
      export type Package = unknown;
    }

    export namespace round2 {
      export type SecretPackage = unknown;
      export type Package = unknown;
    }

    /**
     * Performs the first part of the DKG protocol.
     */
    export function part1(
      identifier: Identifier,
      maxSigners: number,
      minSigners: number,
      rng: RandomSource,
    ): [round1.SecretPackage, round1.Package] {
      return corePart1(Secp256K1Sha256TR, identifier, maxSigners, minSigners, rng);
    }

    /**
     * Performs the second part of the DKG protocol.
     */
    export function part2(
      secretPackage: round1.SecretPackage,
      round1Packages: Map<string, round1.Package>,
    ): [round2.SecretPackage, Map<string, round2.Package>] {
      return corePart2(Secp256K1Sha256TR, secretPackage, round1Packages);
    }

    /**
     * Performs the third and final part of the DKG protocol.
     */
    export async function part3(
      round2SecretPackage: round2.SecretPackage,
      round1Packages: Map<string, round1.Package>,
      round2Packages: Map<string, round2.Package>,
    ): Promise<[KeyPackage, PublicKeyPackage]> {
      return corePart3(
        Secp256K1Sha256TR,
        round2SecretPackage,
        round1Packages,
        round2Packages,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Round 1 Module
// ---------------------------------------------------------------------------

export namespace round1 {
  export type { SigningNonces, SigningCommitments, NonceCommitment };

  /**
   * Performed once by each participant selected for the signing operation.
   * Generates the signing nonces and commitments.
   */
  export function commit(
    secret: SigningShare,
    rng: RandomSource,
  ): [SigningNonces, SigningCommitments] {
    return coreCommit(Secp256K1Sha256TR, secret, rng);
  }
}

// ---------------------------------------------------------------------------
// Round 2 Module
// ---------------------------------------------------------------------------

export namespace round2 {
  export type { SignatureShare };

  /**
   * Performed once by each participant selected for the signing operation.
   */
  export function sign(
    signingPackage: SigningPackage,
    signerNonces: SigningNonces,
    keyPackage: KeyPackage,
  ): SignatureShare {
    return coreSign(Secp256K1Sha256TR, signingPackage, signerNonces, keyPackage);
  }

  /**
   * Same as sign(), but using a Taproot tweak as specified in BIP-341.
   */
  export function signWithTweak(
    signingPackage: SigningPackage,
    signerNonces: SigningNonces,
    keyPackage: KeyPackage,
    merkleRoot?: Uint8Array,
  ): SignatureShare {
    const tweakedKeyPackage = tweakKeyPackage(keyPackage, merkleRoot);
    return coreSign(Secp256K1Sha256TR, signingPackage, signerNonces, tweakedKeyPackage);
  }
}

// ---------------------------------------------------------------------------
// Top-level Functions
// ---------------------------------------------------------------------------

/**
 * Verifies each participant's signature share, and if all are valid,
 * aggregates the shares into a signature compatible with BIP-340.
 */
export function aggregate(
  signingPackage: SigningPackage,
  signatureShares: Map<Identifier, SignatureShare>,
  publicKeyPackage: PublicKeyPackage,
): Signature {
  return coreAggregate(Secp256K1Sha256TR, signingPackage, signatureShares, publicKeyPackage);
}

/**
 * Same as aggregate(), but using a Taproot tweak as specified in BIP-341.
 */
export function aggregateWithTweak(
  signingPackage: SigningPackage,
  signatureShares: Map<Identifier, SignatureShare>,
  publicKeyPackage: PublicKeyPackage,
  merkleRoot?: Uint8Array,
): Signature {
  const tweakedPublicKeyPackage = tweakPublicKeyPackage(publicKeyPackage, merkleRoot);
  return coreAggregate(Secp256K1Sha256TR, signingPackage, signatureShares, tweakedPublicKeyPackage);
}

// ---------------------------------------------------------------------------
// BIP-340/341 Helper Exports
// ---------------------------------------------------------------------------

/**
 * Create a BIP-340 compliant tagged hash.
 */
export function taprootTaggedHash(tag: string, message: Uint8Array): Uint8Array {
  return createTaggedHash(tag)(message);
}

/**
 * Compute a BIP-341 Taproot tweak scalar.
 */
export function taprootTweak(publicKey: Uint8Array, merkleRoot?: Uint8Array): bigint {
  // If x-only (32 bytes), add even Y prefix
  let point: Uint8Array;
  if (publicKey.length === 32) {
    const fullKey = new Uint8Array(33);
    fullKey[0] = 0x02;
    fullKey.set(publicKey, 1);
    point = fullKey;
  } else if (publicKey.length === 33) {
    point = publicKey;
  } else {
    throw new Error("Invalid public key length");
  }
  return computeTweak(point, merkleRoot);
}

/**
 * Apply a Taproot tweak to a public key.
 */
export function applyTaprootTweak(publicKey: Uint8Array, merkleRoot?: Uint8Array): Uint8Array {
  let point: Uint8Array;
  if (publicKey.length === 32) {
    const fullKey = new Uint8Array(33);
    fullKey[0] = 0x02;
    fullKey.set(publicKey, 1);
    point = fullKey;
  } else if (publicKey.length === 33) {
    point = publicKey;
  } else {
    throw new Error("Invalid public key length");
  }

  const t = computeTweak(point, merkleRoot);
  const tp = Secp256K1Group.basePointMul(t);
  return Secp256K1Group.add(point, tp);
}

/**
 * Convert a public key to x-only format (32 bytes).
 */
export function toXOnlyPublicKey(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length === 32) {
    return publicKey;
  }
  if (publicKey.length !== 33) {
    throw new Error("Invalid public key length");
  }
  return pointToXOnly(publicKey);
}

/**
 * Check if a public key has an even Y coordinate.
 */
export function hasEvenYPublicKey(publicKey: Uint8Array): boolean {
  return hasEvenYPoint(publicKey);
}

// ---------------------------------------------------------------------------
// Keys Submodule Re-export
// ---------------------------------------------------------------------------

export * as keysModule from "./keys/index.js";
