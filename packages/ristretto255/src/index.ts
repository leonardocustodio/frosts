/**
 * FROST(ristretto255, SHA-512) - A Schnorr signature scheme over ristretto255 that supports FROST threshold signatures
 *
 * This module provides a complete implementation of the FROST ciphersuite for the ristretto255
 * group with SHA-512 as the hash function, following RFC 9591 Section 6.2.
 *
 * @packageDocumentation
 * @module @frosts/ristretto255
 */

import { sha512 } from "@noble/hashes/sha512";
import { RistrettoPoint } from "@noble/curves/ed25519";

import type {
  Ciphersuite,
  Field,
  Group,
  CryptoRng,
  SigningPackage,
  Challenge as CoreChallenge,
  BindingFactorList,
  GroupCommitment,
} from "@frosts/core";

import {
  Challenge,
  BindingFactor,
  BindingFactorList as BindingFactorListClass,
  GroupCommitment as GroupCommitmentClass,
  Identifier,
  SigningKey,
  VerifyingKey,
  Signature,
  FrostError,
  FieldError,
  GroupError,
} from "@frosts/core";

import type { RandomizedCiphersuite } from "@frosts/rerandomized";

// Re-export core types and errors for convenience
export type { Ciphersuite, Field, Group } from "@frosts/core";
export { FieldError, GroupError } from "@frosts/core";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Context string from the ciphersuite in the spec (RFC 9591 Section 6.2) */
const CONTEXT_STRING = "FROST-RISTRETTO255-SHA512-v1";

/** Scalar size in bytes (32 bytes for ristretto255) */
const SCALAR_SIZE = 32;

/** Element size in bytes (32 bytes for compressed ristretto255 points) */
const ELEMENT_SIZE = 32;

/** Hash output size for SHA-512 (64 bytes = 512 bits) */
const HASH_OUTPUT_SIZE = 64;

// ---------------------------------------------------------------------------
// Type Definitions
// ---------------------------------------------------------------------------

/**
 * Ristretto255 scalar type - a 32-byte little-endian encoded value representing
 * an element of the scalar field.
 */
type Ristretto255Scalar = Uint8Array;

/**
 * Ristretto255 point type - a 32-byte compressed ristretto255 point representation.
 */
type Ristretto255Point = Uint8Array;

// ---------------------------------------------------------------------------
// Field Operations for Ristretto255 Scalar Field
// ---------------------------------------------------------------------------

/**
 * The order of the ristretto255 group.
 *
 * l = 2^252 + 27742317777372353535851937790883648493
 */
const CURVE_ORDER =
  7237005577332262213973186563042994240857116359379907606001950938285454250989n;

/** Zero scalar (additive identity) - 32 zero bytes */
const ZERO_SCALAR = new Uint8Array(SCALAR_SIZE);

/** One scalar (multiplicative identity) - encoded as [1, 0, 0, ...] in little-endian */
const _ONE_SCALAR = (() => {
  const s = new Uint8Array(SCALAR_SIZE);
  s[0] = 1;
  return s;
})();

/**
 * Convert a Uint8Array (little-endian) to BigInt
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert a BigInt to Uint8Array (little-endian) with specified length
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
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * Compare two byte arrays for equality (constant-time)
 */
function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Check if a scalar is zero
 */
function isScalarZero(scalar: Ristretto255Scalar): boolean {
  return constantTimeEquals(scalar, ZERO_SCALAR);
}

/**
 * Add two scalars modulo the curve order
 */
function scalarAdd(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig + bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Subtract two scalars modulo the curve order
 */
function scalarSub(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  let result = aBig - bBig;
  if (result < 0n) {
    result += CURVE_ORDER;
  }
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Multiply two scalars modulo the curve order
 */
function scalarMul(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig * bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Negate a scalar modulo the curve order
 */
function scalarNegate(a: Ristretto255Scalar): Ristretto255Scalar {
  if (isScalarZero(a)) return new Uint8Array(a);
  const aBig = bytesToBigInt(a);
  const result = CURVE_ORDER - aBig;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Compute the multiplicative inverse of a scalar modulo the curve order.
 * Uses the extended Euclidean algorithm (Fermat's little theorem).
 */
function scalarInvert(a: Ristretto255Scalar): Ristretto255Scalar {
  const aBig = bytesToBigInt(a);
  if (aBig === 0n) {
    throw FieldError.invalidZeroScalar();
  }
  // Using Fermat's little theorem: a^(-1) = a^(q-2) mod q
  const result = modPow(aBig, CURVE_ORDER - 2n, CURVE_ORDER);
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Modular exponentiation using binary method
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if ((exp & 1n) !== 0n) {
      result = (result * base) % mod;
    }
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Generate a random scalar in the range [0, q-1]
 */
function randomScalar(rng: CryptoRng): Ristretto255Scalar {
  // Generate 64 random bytes (2x the scalar size) and reduce mod q
  // This ensures uniform distribution
  const randomBytes = new Uint8Array(HASH_OUTPUT_SIZE);
  rng.fill(randomBytes);
  const bigValue = bytesToBigInt(randomBytes);
  const reduced = bigValue % CURVE_ORDER;
  return bigIntToBytes(reduced, SCALAR_SIZE);
}

/**
 * Deserialize a scalar from bytes, validating it's in canonical form
 */
function deserializeScalar(bytes: Uint8Array): Ristretto255Scalar {
  if (bytes.length !== SCALAR_SIZE) {
    throw FieldError.malformedScalar();
  }
  const value = bytesToBigInt(bytes);
  if (value >= CURVE_ORDER) {
    throw FieldError.malformedScalar();
  }
  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Group Operations for Ristretto255 Curve
// ---------------------------------------------------------------------------

/**
 * Check if a point is the identity element
 */
function isIdentityPoint(point: Ristretto255Point): boolean {
  try {
    const decoded = RistrettoPoint.fromHex(point);
    return decoded.equals(RistrettoPoint.ZERO);
  } catch {
    return false;
  }
}

/**
 * Add two points on the curve
 */
function pointAdd(a: Ristretto255Point, b: Ristretto255Point): Ristretto255Point {
  try {
    const aPoint = RistrettoPoint.fromHex(a);
    const bPoint = RistrettoPoint.fromHex(b);
    const result = aPoint.add(bPoint);
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Subtract two points on the curve
 */
function pointSub(a: Ristretto255Point, b: Ristretto255Point): Ristretto255Point {
  try {
    const aPoint = RistrettoPoint.fromHex(a);
    const bPoint = RistrettoPoint.fromHex(b);
    const result = aPoint.subtract(bPoint);
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Negate a point on the curve
 */
function pointNegate(a: Ristretto255Point): Ristretto255Point {
  try {
    const aPoint = RistrettoPoint.fromHex(a);
    const result = aPoint.negate();
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Scalar multiplication: point * scalar
 */
function pointMul(point: Ristretto255Point, scalar: Ristretto255Scalar): Ristretto255Point {
  try {
    const p = RistrettoPoint.fromHex(point);
    const s = bytesToBigInt(scalar);
    const result = p.multiply(s);
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Scalar base multiplication: generator * scalar
 */
function scalarBaseMul(scalar: Ristretto255Scalar): Ristretto255Point {
  try {
    const s = bytesToBigInt(scalar);
    const result = RistrettoPoint.BASE.multiply(s);
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Get the generator point
 */
function getGenerator(): Ristretto255Point {
  return RistrettoPoint.BASE.toRawBytes();
}

/**
 * Get the identity point
 */
function getIdentity(): Ristretto255Point {
  return RistrettoPoint.ZERO.toRawBytes();
}

/**
 * Check if two points are equal
 */
function pointsEqual(a: Ristretto255Point, b: Ristretto255Point): boolean {
  return constantTimeEquals(a, b);
}

/**
 * Serialize a point (already in compressed form)
 */
function serializePoint(point: Ristretto255Point): Uint8Array {
  // Check if point is identity - forbidden in FROST
  if (isIdentityPoint(point)) {
    throw GroupError.invalidIdentityElement();
  }
  return new Uint8Array(point);
}

/**
 * Deserialize a point from bytes
 */
function deserializePoint(bytes: Uint8Array): Ristretto255Point {
  if (bytes.length !== ELEMENT_SIZE) {
    throw GroupError.malformedElement();
  }

  try {
    const point = RistrettoPoint.fromHex(bytes);

    // Check for identity element
    if (point.equals(RistrettoPoint.ZERO)) {
      throw GroupError.invalidIdentityElement();
    }

    // Verify canonical encoding by re-encoding and comparing
    const reencoded = point.toRawBytes();
    if (!constantTimeEquals(bytes, reencoded)) {
      throw GroupError.malformedElement();
    }

    return reencoded;
  } catch (e) {
    if (e instanceof Error && e.message.includes("identity")) {
      throw e;
    }
    throw GroupError.malformedElement();
  }
}

// ---------------------------------------------------------------------------
// Ristretto255 Field Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(ristretto255, SHA-512) ciphersuite scalar field.
 */
class RistrettoScalarFieldImpl implements Field<Ristretto255Scalar, Uint8Array> {
  zero(): Ristretto255Scalar {
    return new Uint8Array(SCALAR_SIZE);
  }

  one(): Ristretto255Scalar {
    const s = new Uint8Array(SCALAR_SIZE);
    s[0] = 1;
    return s;
  }

  invert(scalar: Ristretto255Scalar): Ristretto255Scalar {
    return scalarInvert(scalar);
  }

  random(rng: CryptoRng): Ristretto255Scalar {
    return randomScalar(rng);
  }

  serialize(scalar: Ristretto255Scalar): Uint8Array {
    return new Uint8Array(scalar);
  }

  littleEndianSerialize(scalar: Ristretto255Scalar): Uint8Array {
    // Ristretto255 scalars are already in little-endian format
    return this.serialize(scalar);
  }

  deserialize(buf: Uint8Array): Ristretto255Scalar {
    return deserializeScalar(buf);
  }

  add(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
    return scalarAdd(a, b);
  }

  sub(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
    return scalarSub(a, b);
  }

  mul(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
    return scalarMul(a, b);
  }

  negate(scalar: Ristretto255Scalar): Ristretto255Scalar {
    return scalarNegate(scalar);
  }

  eq(a: Ristretto255Scalar, b: Ristretto255Scalar): boolean {
    return constantTimeEquals(a, b);
  }

  isZero(scalar: Ristretto255Scalar): boolean {
    return isScalarZero(scalar);
  }
}

// ---------------------------------------------------------------------------
// Ristretto255 Group Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(ristretto255, SHA-512) ciphersuite group.
 */
class RistrettoGroupImpl implements Group<RistrettoScalarFieldImpl, Ristretto255Point, Uint8Array> {
  readonly field: RistrettoScalarFieldImpl;

  constructor() {
    this.field = new RistrettoScalarFieldImpl();
  }

  cofactor(): Ristretto255Scalar {
    // Ristretto255 has cofactor 1 (it's a prime-order group)
    return this.field.one();
  }

  identity(): Ristretto255Point {
    return getIdentity();
  }

  generator(): Ristretto255Point {
    return getGenerator();
  }

  serialize(element: Ristretto255Point): Uint8Array {
    return serializePoint(element);
  }

  deserialize(buf: Uint8Array): Ristretto255Point {
    return deserializePoint(buf);
  }

  add(a: Ristretto255Point, b: Ristretto255Point): Ristretto255Point {
    return pointAdd(a, b);
  }

  sub(a: Ristretto255Point, b: Ristretto255Point): Ristretto255Point {
    return pointSub(a, b);
  }

  scalarMul(element: Ristretto255Point, scalar: Ristretto255Scalar): Ristretto255Point {
    return pointMul(element, scalar);
  }

  scalarBaseMul(scalar: Ristretto255Scalar): Ristretto255Point {
    return scalarBaseMul(scalar);
  }

  negate(element: Ristretto255Point): Ristretto255Point {
    return pointNegate(element);
  }

  eq(a: Ristretto255Point, b: Ristretto255Point): boolean {
    return pointsEqual(a, b);
  }

  isIdentity(element: Ristretto255Point): boolean {
    return isIdentityPoint(element);
  }
}

// ---------------------------------------------------------------------------
// Hash Functions
// ---------------------------------------------------------------------------

/**
 * Hash arbitrary inputs to a 64-byte array using SHA-512.
 * This is the internal hash function used by H1-H5 and HDKG/HID.
 *
 * @param inputs - Array of byte arrays to concatenate and hash
 * @returns 64-byte output from SHA-512
 */
function hashToArray(inputs: Uint8Array[]): Uint8Array {
  // Concatenate all inputs
  const totalLength = inputs.reduce((sum, arr) => sum + arr.length, 0);
  const concatenated = new Uint8Array(totalLength);
  let offset = 0;
  for (const input of inputs) {
    concatenated.set(input, offset);
    offset += input.length;
  }

  // Use SHA-512 to produce 64 bytes
  return sha512(concatenated);
}

/**
 * Hash arbitrary inputs to a scalar using SHA-512.
 * Uses wide reduction from 64 bytes to ensure uniform distribution.
 *
 * @param inputs - Array of byte arrays to concatenate and hash
 * @returns A scalar in the ristretto255 field
 */
function hashToScalar(inputs: Uint8Array[]): Ristretto255Scalar {
  const hashOutput = hashToArray(inputs);
  const bigValue = bytesToBigInt(hashOutput);
  const reduced = bigValue % CURVE_ORDER;
  return bigIntToBytes(reduced, SCALAR_SIZE);
}

// ---------------------------------------------------------------------------
// Ristretto255Sha512 Ciphersuite Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(ristretto255, SHA-512) ciphersuite.
 *
 * This ciphersuite uses:
 * - ristretto255 group for group operations
 * - SHA-512 for hashing
 * - 32-byte serialization for both scalars and points
 *
 * The ciphersuite follows RFC 9591 Section 6.2 specification.
 */
class Ristretto255Sha512Impl implements RandomizedCiphersuite {
  readonly ID = CONTEXT_STRING;
  readonly group: RistrettoGroupImpl;

  // Type brand properties
  Scalar!: Ristretto255Scalar;
  Element!: Ristretto255Point;
  VerifyingKey!: VerifyingKey<Ristretto255Sha512Impl>;
  SigningKey!: SigningKey<Ristretto255Sha512Impl>;

  constructor() {
    this.group = new RistrettoGroupImpl();
  }

  // ---------------------------------------------------------------------------
  // Field Operations (flattened)
  // ---------------------------------------------------------------------------

  scalarZero(): Ristretto255Scalar {
    return this.group.field.zero();
  }

  scalarOne(): Ristretto255Scalar {
    return this.group.field.one();
  }

  scalarInvert(scalar: Ristretto255Scalar): Ristretto255Scalar {
    return this.group.field.invert(scalar);
  }

  scalarRandom(rng: { fill(array: Uint8Array): void }): Ristretto255Scalar {
    return this.group.field.random(rng as CryptoRng);
  }

  serializeScalar(scalar: Ristretto255Scalar): Uint8Array {
    return this.group.field.serialize(scalar);
  }

  deserializeScalar(bytes: Uint8Array): Ristretto255Scalar {
    return this.group.field.deserialize(bytes);
  }

  scalarAdd(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
    return this.group.field.add(a, b);
  }

  scalarSub(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
    return this.group.field.sub(a, b);
  }

  scalarMul(a: Ristretto255Scalar, b: Ristretto255Scalar): Ristretto255Scalar {
    return this.group.field.mul(a, b);
  }

  scalarsEqual(a: Ristretto255Scalar, b: Ristretto255Scalar): boolean {
    return this.group.field.eq(a, b);
  }

  // ---------------------------------------------------------------------------
  // Group Operations (flattened)
  // ---------------------------------------------------------------------------

  elementSize(): number {
    return ELEMENT_SIZE;
  }

  scalarSize(): number {
    return SCALAR_SIZE;
  }

  cofactor(): Ristretto255Scalar {
    return this.group.cofactor();
  }

  identity(): Ristretto255Point {
    return this.group.identity();
  }

  generator(): Ristretto255Point {
    return this.group.generator();
  }

  serializeElement(element: Ristretto255Point): Uint8Array {
    return this.group.serialize(element);
  }

  deserializeElement(bytes: Uint8Array): Ristretto255Point {
    return this.group.deserialize(bytes);
  }

  elementAdd(a: Ristretto255Point, b: Ristretto255Point): Ristretto255Point {
    return this.group.add(a, b);
  }

  elementSub(a: Ristretto255Point, b: Ristretto255Point): Ristretto255Point {
    return this.group.sub(a, b);
  }

  elementMul(element: Ristretto255Point, scalar: Ristretto255Scalar): Ristretto255Point {
    return this.group.scalarMul(element, scalar);
  }

  scalarBaseMult(scalar: Ristretto255Scalar): Ristretto255Point {
    return this.group.scalarBaseMul(scalar);
  }

  elementsEqual(a: Ristretto255Point, b: Ristretto255Point): boolean {
    return this.group.eq(a, b);
  }

  isIdentity(element: Ristretto255Point): boolean {
    return this.group.isIdentity(element);
  }

  // ---------------------------------------------------------------------------
  // Hash Functions (RFC 9591 Section 6.2)
  // ---------------------------------------------------------------------------

  /**
   * H1 for FROST(ristretto255, SHA-512)
   *
   * H1(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "rho" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.2-2.4.2.2
   */
  H1(m: Uint8Array): Ristretto255Scalar {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("rho"),
      m,
    ]);
  }

  /**
   * H2 for FROST(ristretto255, SHA-512)
   *
   * H2(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "chal" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.2-2.4.2.4
   */
  H2(m: Uint8Array): Ristretto255Scalar {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("chal"),
      m,
    ]);
  }

  /**
   * H3 for FROST(ristretto255, SHA-512)
   *
   * H3(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "nonce" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.2-2.4.2.6
   */
  H3(m: Uint8Array): Ristretto255Scalar {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("nonce"),
      m,
    ]);
  }

  /**
   * H4 for FROST(ristretto255, SHA-512)
   *
   * H4(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "msg" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.2-2.4.2.8
   */
  H4(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("msg"),
      m,
    ]);
  }

  /**
   * H5 for FROST(ristretto255, SHA-512)
   *
   * H5(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "com" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.2-2.4.2.10
   */
  H5(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("com"),
      m,
    ]);
  }

  /**
   * HDKG for FROST(ristretto255, SHA-512)
   *
   * HDKG(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "dkg" || m)
   *
   * Used for distributed key generation.
   */
  HDKG(m: Uint8Array): Ristretto255Scalar | null {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("dkg"),
      m,
    ]);
  }

  /**
   * HID for FROST(ristretto255, SHA-512)
   *
   * HID(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "id" || m)
   *
   * Used for deriving identifiers from arbitrary byte strings.
   */
  HID(m: Uint8Array): Ristretto255Scalar | null {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("id"),
      m,
    ]);
  }

  /**
   * hashRandomizer for RandomizedCiphersuite
   *
   * hashRandomizer(m) = SHA-512("FROST-RISTRETTO255-SHA512-v1" || "randomizer" || m)
   *
   * Used for re-randomized FROST signatures.
   */
  hashRandomizer(m: Uint8Array): Ristretto255Scalar | null {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("randomizer"),
      m,
    ]);
  }

  // ---------------------------------------------------------------------------
  // Signature Challenge Computation
  // ---------------------------------------------------------------------------

  /**
   * Compute the signature challenge.
   *
   * For ristretto255, this follows the FROST challenge computation
   * from RFC 9591 Section 6.2.
   */
  challenge(
    R: Ristretto255Point,
    verifyingKey: unknown,
    message: Uint8Array,
  ): CoreChallenge<this> {
    // Build the preimage: R || verifying_key || message
    const rBytes = this.serializeElement(R);
    // Handle both VerifyingKey objects and raw elements
    let pkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof (verifyingKey as { serialize: unknown }).serialize === "function"
    ) {
      pkBytes = (verifyingKey as VerifyingKey<Ristretto255Sha512Impl>).serialize();
    } else {
      pkBytes = this.group.serialize(verifyingKey as Ristretto255Point);
    }

    const preimage = new Uint8Array(rBytes.length + pkBytes.length + message.length);
    preimage.set(rBytes, 0);
    preimage.set(pkBytes, rBytes.length);
    preimage.set(message, rBytes.length + pkBytes.length);

    const scalar = this.H2(preimage);
    return Challenge.fromScalar(this, scalar);
  }

  // ---------------------------------------------------------------------------
  // Binding Factor and Group Commitment Computation
  // ---------------------------------------------------------------------------

  /**
   * Compute binding factors for all participants.
   */
  computeBindingFactorList<C extends Ciphersuite>(
    signingPackage: SigningPackage<C>,
    verifyingKey: unknown,
    additionalPrefix: Uint8Array,
  ): BindingFactorList<C> {
    // Handle both VerifyingKey objects and raw elements (Ristretto255 points)
    let vkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof (verifyingKey as { serialize: unknown }).serialize === "function"
    ) {
      vkBytes = (verifyingKey as VerifyingKey<Ristretto255Sha512Impl>).serialize();
    } else {
      // It's a raw element, serialize it directly
      vkBytes = this.group.serialize(verifyingKey as Ristretto255Point);
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
      commitmentList.push(id.serialize());
      commitmentList.push(commitment.hiding.serialize());
      commitmentList.push(commitment.binding.serialize());
    }

    // Concatenate commitment list
    const totalLen = commitmentList.reduce((s, a) => s + a.length, 0);
    const encodedCommitments = new Uint8Array(totalLen);
    let off = 0;
    for (const chunk of commitmentList) {
      encodedCommitments.set(chunk, off);
      off += chunk.length;
    }

    // Compute H5(encoded_commitments)
    const commitmentsHash = this.H5(encodedCommitments);

    // Build the binding factor preimage prefix
    const prefixParts = [vkBytes, msgHash, commitmentsHash, additionalPrefix];
    const prefixLen = prefixParts.reduce((s, a) => s + a.length, 0);
    const prefix = new Uint8Array(prefixLen);
    let prefixOff = 0;
    for (const part of prefixParts) {
      prefix.set(part, prefixOff);
      prefixOff += part.length;
    }

    // Compute binding factors for each participant
    const factors = new Map<string, BindingFactor<C>>();

    for (const [identifier] of sortedEntries) {
      const id = identifier as Identifier<C>;
      const idBytes = id.serialize();

      // rho_i = H1(prefix || i_enc)
      const input = new Uint8Array(prefix.length + idBytes.length);
      input.set(prefix, 0);
      input.set(idBytes, prefix.length);

      const rho = this.H1(input);
      const factor = BindingFactor.fromScalar(this as unknown as C, rho);
      const idKey = bytesToHex(idBytes);
      factors.set(idKey, factor);
    }

    return new BindingFactorListClass(this as unknown as C, factors);
  }

  /**
   * Compute the group commitment from all signing commitments.
   */
  computeGroupCommitment<C extends Ciphersuite>(
    signingPackage: SigningPackage<C>,
    bindingFactorList: BindingFactorList<C>,
  ): GroupCommitment<C> {
    let groupCommitment = this.identity();

    for (const [identifier, commitment] of signingPackage.signingCommitments) {
      const id = identifier as Identifier<C>;
      const bindingFactor = bindingFactorList.get(id);

      if (bindingFactor === null || bindingFactor === undefined) {
        throw FrostError.unknownIdentifier();
      }

      // commitment_i = hiding_i + binding_i * rho_i
      const hidingElement = commitment.hiding.toElement() as Ristretto255Point;
      const bindingElement = commitment.binding.toElement() as Ristretto255Point;
      const scaledBinding = this.elementMul(bindingElement, bindingFactor.toScalar() as Ristretto255Scalar);
      const commitmentShare = this.elementAdd(hidingElement, scaledBinding);

      groupCommitment = this.elementAdd(groupCommitment, commitmentShare);
    }

    return GroupCommitmentClass.fromElement(this as unknown as C, groupCommitment);
  }

  /**
   * Derive the interpolating value (Lagrange coefficient) for a participant.
   */
  deriveInterpolatingValue<C extends Ciphersuite>(
    signerId: { toScalar(): unknown; serialize(): Uint8Array; clone(): unknown },
    signingPackage: SigningPackage<C>,
  ): Ristretto255Scalar {
    const signerIds = [...signingPackage.signingCommitments.keys()] as { toScalar(): unknown }[];

    let numerator = this.scalarOne();
    let denominator = this.scalarOne();

    const xI = signerId.toScalar() as Ristretto255Scalar;
    const x = this.scalarZero(); // x = 0 for the shared secret

    for (const id of signerIds) {
      const xJ = id.toScalar() as Ristretto255Scalar;

      if (constantTimeEquals(xJ, xI)) {
        continue;
      }

      // numerator *= (x - xJ)
      const xMinusXj = this.scalarSub(x, xJ);
      numerator = this.scalarMul(numerator, xMinusXj);

      // denominator *= (xI - xJ)
      const xIMinusXj = this.scalarSub(xI, xJ);
      if (isScalarZero(xIMinusXj)) {
        throw FrostError.duplicatedIdentifier();
      }
      denominator = this.scalarMul(denominator, xIMinusXj);
    }

    const denominatorInverse = this.scalarInvert(denominator);
    return this.scalarMul(numerator, denominatorInverse);
  }
}

// ---------------------------------------------------------------------------
// Singleton Instance
// ---------------------------------------------------------------------------

/**
 * The Ristretto255Sha512 ciphersuite instance.
 * This is a singleton that should be used for all ristretto255 FROST operations.
 */
export const Ristretto255Sha512: Ristretto255Sha512Impl = new Ristretto255Sha512Impl();

// Export the implementation class for type references
export type { Ristretto255Sha512Impl };

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/** A FROST(ristretto255, SHA-512) participant identifier */
export type Ristretto255Identifier = Identifier<Ristretto255Sha512Impl>;

/** An error from FROST(ristretto255, SHA-512) operations */
export type Ristretto255Error = ReturnType<typeof FrostError.invalidMinSigners>;

/** A FROST(ristretto255, SHA-512) signing package */
export type Ristretto255SigningPackage = SigningPackage<Ristretto255Sha512Impl>;

/** A FROST(ristretto255, SHA-512) signature */
export type Ristretto255Signature = Signature<Ristretto255Sha512Impl>;

/** A FROST(ristretto255, SHA-512) signing key */
export type Ristretto255SigningKey = SigningKey<Ristretto255Sha512Impl>;

/** A FROST(ristretto255, SHA-512) verifying key */
export type Ristretto255VerifyingKey = VerifyingKey<Ristretto255Sha512Impl>;

/** Cheater detection mode for aggregation */
export enum CheaterDetection {
  /** No cheater detection, faster but less secure */
  None = "none",
  /** Full cheater detection, identifies malicious signers */
  Full = "full",
}

// ---------------------------------------------------------------------------
// Re-exports from @frosts/core for keys module
// ---------------------------------------------------------------------------

// Keys module exports
export {
  SigningShare,
  VerifyingShare,
  SecretShare,
  KeyPackage,
  PublicKeyPackage,
  VerifiableSecretSharingCommitment,
  CoefficientCommitment,
  generateWithDealer,
  reconstruct,
  splitFromScalar as split,
  computeLagrangeCoefficient,
  identifierToString,
} from "@frosts/core";

export type { IdentifierList } from "@frosts/core";

// Round 1 exports
export {
  SigningNonces,
  SigningCommitments,
  NonceCommitment,
  Nonce,
  GroupCommitmentShare,
  commit,
  preprocess,
} from "@frosts/core";

// Round 2 exports
export { SignatureShare, sign, computeSignatureShare } from "@frosts/core";

// Re-export Identifier and key types
export { Identifier, SigningKey, VerifyingKey, Signature };

// ---------------------------------------------------------------------------
// Keys submodule re-export
// ---------------------------------------------------------------------------

// Re-export the keys module
export * as keys from "./keys/index.js";

// ---------------------------------------------------------------------------
// Round 1 type aliases
// ---------------------------------------------------------------------------

import {
  type SigningNonces as CoreSigningNonces,
  type SigningCommitments as CoreSigningCommitments,
  type NonceCommitment as CoreNonceCommitment,
  commit as coreCommit,
} from "@frosts/core";

/** Comprised of FROST(ristretto255, SHA-512) hiding and binding nonces */
export type Ristretto255SigningNonces = CoreSigningNonces<Ristretto255Sha512Impl>;

/** Published by each participant in the first round of the signing protocol */
export type Ristretto255SigningCommitments = CoreSigningCommitments<Ristretto255Sha512Impl>;

/** A commitment to a signing nonce share */
export type Ristretto255NonceCommitment = CoreNonceCommitment<Ristretto255Sha512Impl>;

/**
 * Performed once by each participant selected for the signing operation.
 *
 * Generates the signing nonces and commitments to be used in the signing operation.
 *
 * @param secret - The participant's signing share
 * @param rng - A cryptographically secure random number generator
 * @returns A tuple of [signing nonces, signing commitments]
 */
export function commitRound1(
  secret: CoreSigningShare<Ristretto255Sha512Impl>,
  rng: RandomSource,
): [Ristretto255SigningNonces, Ristretto255SigningCommitments] {
  return coreCommit(Ristretto255Sha512, secret, rng);
}

// ---------------------------------------------------------------------------
// Round 2 type aliases
// ---------------------------------------------------------------------------

import {
  type SignatureShare as CoreSignatureShare,
  sign as coreSign,
  type PublicKeyPackage as CorePublicKeyPackage,
  type SigningShare as CoreSigningShare,
  type KeyPackage as CoreKeyPackage,
  type RandomSource,
} from "@frosts/core";

/** A FROST(ristretto255, SHA-512) participant's signature share */
export type Ristretto255SignatureShare = CoreSignatureShare<Ristretto255Sha512Impl>;

/**
 * Performed once by each participant selected for the signing operation.
 *
 * Receives the message to be signed and a set of signing commitments to be used
 * in that signing operation, including that for this participant.
 *
 * @param signingPackage - The signing package from the coordinator
 * @param signerNonces - The signer's nonces generated in round 1
 * @param keyPackage - The signer's key package
 * @returns The signature share
 */
export function signRound2(
  signingPackage: Ristretto255SigningPackage,
  signerNonces: CoreSigningNonces<Ristretto255Sha512Impl>,
  keyPackage: CoreKeyPackage<Ristretto255Sha512Impl>,
): Ristretto255SignatureShare {
  return coreSign(Ristretto255Sha512, signingPackage, signerNonces, keyPackage);
}

// ---------------------------------------------------------------------------
// Top-level Functions
// ---------------------------------------------------------------------------

/**
 * Verifies each FROST(ristretto255, SHA-512) participant's signature share, and if all are valid,
 * aggregates the shares into a signature to publish.
 *
 * Resulting signature is compatible with verification of a plain Schnorr signature.
 *
 * This function performs the final aggregation step of the FROST protocol:
 * 1. Recomputes the binding factors and group commitment
 * 2. Computes the challenge
 * 3. Verifies each signature share against the corresponding verifying share
 * 4. Aggregates all signature shares into the final signature
 *
 * @param signingPackage - The signing package containing commitments and message
 * @param signatureShares - Map of identifier to signature share
 * @param pubkeys - The public key package
 * @returns The aggregated signature
 * @throws Error if any signature share is invalid
 */
export function aggregate(
  signingPackage: Ristretto255SigningPackage,
  signatureShares: Map<Ristretto255Identifier, CoreSignatureShare<Ristretto255Sha512Impl>>,
  pubkeys: CorePublicKeyPackage<Ristretto255Sha512Impl>,
): Ristretto255Signature {
  return aggregateImpl(signingPackage, signatureShares, pubkeys, true);
}

/**
 * Like aggregate(), but allows specifying a specific cheater detection strategy.
 *
 * @param signingPackage - The signing package containing commitments and message
 * @param signatureShares - Map of identifier to signature share
 * @param pubkeys - The public key package
 * @param cheaterDetection - The cheater detection mode to use
 * @returns The aggregated signature
 */
export function aggregateCustom(
  signingPackage: Ristretto255SigningPackage,
  signatureShares: Map<Ristretto255Identifier, CoreSignatureShare<Ristretto255Sha512Impl>>,
  pubkeys: CorePublicKeyPackage<Ristretto255Sha512Impl>,
  cheaterDetection: CheaterDetection,
): Ristretto255Signature {
  return aggregateImpl(signingPackage, signatureShares, pubkeys, cheaterDetection === CheaterDetection.Full);
}

/**
 * Internal aggregate implementation.
 */
function aggregateImpl(
  signingPackage: Ristretto255SigningPackage,
  signatureShares: Map<Ristretto255Identifier, CoreSignatureShare<Ristretto255Sha512Impl>>,
  pubkeys: CorePublicKeyPackage<Ristretto255Sha512Impl>,
  verifySigShares: boolean,
): Ristretto255Signature {
  // Get the verifying key
  const verifyingKey = VerifyingKey.create(Ristretto255Sha512, pubkeys.verifyingKey);

  // Compute the binding factor list
  const bindingFactorList = Ristretto255Sha512.computeBindingFactorList(
    signingPackage,
    verifyingKey,
    new Uint8Array(0),
  );

  // Compute the group commitment
  const groupCommitment = Ristretto255Sha512.computeGroupCommitment(
    signingPackage,
    bindingFactorList,
  );

  // Compute the challenge
  const challenge = Ristretto255Sha512.challenge(
    groupCommitment.toElement(),
    verifyingKey,
    signingPackage.message,
  );

  // Aggregate the signature shares
  let z = Ristretto255Sha512.scalarZero();

  for (const [identifier, share] of signatureShares) {
    // Optionally verify each signature share
    if (verifySigShares) {
      const verifyingShare = pubkeys.verifyingShares.get(bytesToHex(identifier.serialize()));
      if (verifyingShare === null || verifyingShare === undefined) {
        throw FrostError.unknownIdentifier();
      }

      // Compute binding factor for this participant
      const bindingFactor = bindingFactorList.get(identifier);
      if (bindingFactor === null || bindingFactor === undefined) {
        throw FrostError.unknownIdentifier();
      }

      // Get commitment for this participant
      const commitment = signingPackage.signingCommitments.get(identifier);
      if (commitment === null || commitment === undefined) {
        throw FrostError.unknownIdentifier();
      }

      // Compute commitment share: hiding + binding * rho
      const hidingElement = commitment.hiding.toElement();
      const bindingElement = commitment.binding.toElement();
      const scaledBinding = Ristretto255Sha512.elementMul(bindingElement, bindingFactor.toScalar());
      const commitmentShare = Ristretto255Sha512.elementAdd(hidingElement, scaledBinding);

      // Compute lambda_i (Lagrange coefficient)
      const lambdaI = Ristretto255Sha512.deriveInterpolatingValue(identifier, signingPackage);

      // Verify: z_i * G = R_i + (c * lambda_i) * Y_i
      const shareScalar = share.toScalar();
      const lhs = Ristretto255Sha512.scalarBaseMult(shareScalar);

      const challengeTimesLambda = Ristretto255Sha512.scalarMul(
        challenge.toScalar(),
        lambdaI,
      );
      const verifyingElement = verifyingShare.toElement();
      const scaledVerifyingShare = Ristretto255Sha512.elementMul(verifyingElement, challengeTimesLambda);
      const rhs = Ristretto255Sha512.elementAdd(commitmentShare, scaledVerifyingShare);

      if (!Ristretto255Sha512.elementsEqual(lhs, rhs)) {
        throw new Error(`Invalid signature share from participant ${identifier.toString()}`);
      }
    }

    // Add to aggregate
    z = Ristretto255Sha512.scalarAdd(z, share.toScalar());
  }

  // Create the signature: (R, z)
  return new Signature(
    groupCommitment.toElement(),
    z,
  );
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
