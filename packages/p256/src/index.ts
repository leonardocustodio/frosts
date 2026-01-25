/**
 * FROST(P-256, SHA-256) - A Schnorr signature scheme over P-256 that supports FROST threshold signatures
 *
 * This module provides a complete implementation of the FROST ciphersuite for the P-256
 * group (NIST P-256 / secp256r1) with SHA-256 as the hash function, following RFC 9591 Section 6.4.
 *
 * @packageDocumentation
 * @module @frosts/p256
 */

import { sha256 } from "@noble/hashes/sha256";
import { p256 } from "@noble/curves/p256";

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

/** Context string from the ciphersuite in the spec (RFC 9591 Section 6.4) */
const CONTEXT_STRING = "FROST-P256-SHA256-v1";

/** Scalar size in bytes (32 bytes for P-256) */
const SCALAR_SIZE = 32;

/** Element size in bytes (33 bytes for SEC1 compressed P-256 points) */
const ELEMENT_SIZE = 33;

// Hash output size for SHA-256 (32 bytes = 256 bits)
// Note: The actual hash output size is implicit in SHA-256 (32 bytes)

// ---------------------------------------------------------------------------
// Type Definitions
// ---------------------------------------------------------------------------

/**
 * P-256 scalar type - a 32-byte big-endian encoded value representing
 * an element of the scalar field.
 */
type P256Scalar = Uint8Array;

/**
 * P-256 point type - a 33-byte SEC1 compressed point representation.
 */
type P256Point = Uint8Array;

// ---------------------------------------------------------------------------
// Field Operations for P-256 Scalar Field
// ---------------------------------------------------------------------------

/**
 * The order of the P-256 group (curve order n).
 *
 * n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 */
const CURVE_ORDER = p256.CURVE.n;

/** Zero scalar (additive identity) - 32 zero bytes */
const ZERO_SCALAR = new Uint8Array(SCALAR_SIZE);

// One scalar (multiplicative identity) - encoded as [0, 0, ..., 1] in big-endian
// Note: computed via field.one() method when needed

/**
 * Convert a Uint8Array (big-endian) to BigInt
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert a BigInt to Uint8Array (big-endian) with specified length
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
function isScalarZero(scalar: P256Scalar): boolean {
  return constantTimeEquals(scalar, ZERO_SCALAR);
}

/**
 * Add two scalars modulo the curve order
 */
function scalarAdd(a: P256Scalar, b: P256Scalar): P256Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig + bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Subtract two scalars modulo the curve order
 */
function scalarSub(a: P256Scalar, b: P256Scalar): P256Scalar {
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
function scalarMul(a: P256Scalar, b: P256Scalar): P256Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig * bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Negate a scalar modulo the curve order
 */
function scalarNegate(a: P256Scalar): P256Scalar {
  if (isScalarZero(a)) return new Uint8Array(a);
  const aBig = bytesToBigInt(a);
  const result = CURVE_ORDER - aBig;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Compute the multiplicative inverse of a scalar modulo the curve order.
 * Uses the extended Euclidean algorithm (Fermat's little theorem).
 */
function scalarInvert(a: P256Scalar): P256Scalar {
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
function randomScalar(rng: CryptoRng): P256Scalar {
  // Generate 64 random bytes (2x the scalar size) and reduce mod q
  // This ensures uniform distribution
  const randomBytes = new Uint8Array(64);
  rng.fill(randomBytes);
  const bigValue = bytesToBigInt(randomBytes);
  const reduced = bigValue % CURVE_ORDER;
  return bigIntToBytes(reduced, SCALAR_SIZE);
}

/**
 * Deserialize a scalar from bytes (big-endian), validating it's in canonical form
 */
function deserializeScalar(bytes: Uint8Array): P256Scalar {
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
// Group Operations for P-256 Curve
// ---------------------------------------------------------------------------

// Use ProjectivePoint from @noble/curves
const ProjectivePoint = p256.ProjectivePoint;

/**
 * The identity point encoding (33 zero bytes).
 * noble-curves P256 doesn't support serializing/deserializing identity,
 * so we use this special representation.
 */
const IDENTITY_BYTES = new Uint8Array(ELEMENT_SIZE);

/**
 * Check if bytes represent our special identity encoding (all zeros)
 */
function isIdentityBytes(point: P256Point): boolean {
  if (point.length !== ELEMENT_SIZE) return false;
  for (let i = 0; i < point.length; i++) {
    if (point[i] !== 0) return false;
  }
  return true;
}

/**
 * Check if a point is the identity element
 */
function isIdentityPoint(point: P256Point): boolean {
  // First check our special identity encoding
  if (isIdentityBytes(point)) return true;
  // Then try to decode and check if it's ZERO (shouldn't happen with noble-curves but be safe)
  try {
    const decoded = ProjectivePoint.fromHex(point);
    return decoded.equals(ProjectivePoint.ZERO);
  } catch {
    return false;
  }
}

/**
 * Add two points on the curve.
 * Handles identity specially since noble-curves P256 can't serialize/deserialize identity.
 */
function pointAdd(a: P256Point, b: P256Point): P256Point {
  // Handle identity: 0 + P = P, P + 0 = P
  const aIsIdentity = isIdentityBytes(a);
  const bIsIdentity = isIdentityBytes(b);

  if (aIsIdentity && bIsIdentity) {
    return new Uint8Array(IDENTITY_BYTES);
  }
  if (aIsIdentity) {
    return new Uint8Array(b);
  }
  if (bIsIdentity) {
    return new Uint8Array(a);
  }

  try {
    const aPoint = ProjectivePoint.fromHex(a);
    const bPoint = ProjectivePoint.fromHex(b);
    const result = aPoint.add(bPoint);
    // Check if result is identity (P + (-P) = 0)
    if (result.equals(ProjectivePoint.ZERO)) {
      return new Uint8Array(IDENTITY_BYTES);
    }
    return result.toRawBytes(true); // compressed
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Subtract two points on the curve.
 * Handles identity specially since noble-curves P256 can't serialize/deserialize identity.
 */
function pointSub(a: P256Point, b: P256Point): P256Point {
  // Handle identity: 0 - P = -P, P - 0 = P
  const aIsIdentity = isIdentityBytes(a);
  const bIsIdentity = isIdentityBytes(b);

  if (aIsIdentity && bIsIdentity) {
    return new Uint8Array(IDENTITY_BYTES);
  }
  if (aIsIdentity) {
    // 0 - P = -P
    try {
      const bPoint = ProjectivePoint.fromHex(b);
      return bPoint.negate().toRawBytes(true);
    } catch (_e) {
      throw GroupError.malformedElement();
    }
  }
  if (bIsIdentity) {
    return new Uint8Array(a);
  }

  try {
    const aPoint = ProjectivePoint.fromHex(a);
    const bPoint = ProjectivePoint.fromHex(b);
    const result = aPoint.subtract(bPoint);
    // Check if result is identity (P - P = 0)
    if (result.equals(ProjectivePoint.ZERO)) {
      return new Uint8Array(IDENTITY_BYTES);
    }
    return result.toRawBytes(true); // compressed
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Negate a point on the curve.
 * Handles identity specially: -0 = 0
 */
function pointNegate(a: P256Point): P256Point {
  // -0 = 0
  if (isIdentityBytes(a)) {
    return new Uint8Array(IDENTITY_BYTES);
  }

  try {
    const aPoint = ProjectivePoint.fromHex(a);
    const result = aPoint.negate();
    return result.toRawBytes(true); // compressed
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Scalar multiplication: point * scalar.
 * Handles identity and zero scalar specially.
 */
function pointMul(point: P256Point, scalar: P256Scalar): P256Point {
  const s = bytesToBigInt(scalar);

  // P * 0 = 0
  if (s === 0n) {
    return new Uint8Array(IDENTITY_BYTES);
  }

  // 0 * s = 0 (identity times anything is identity)
  if (isIdentityBytes(point)) {
    return new Uint8Array(IDENTITY_BYTES);
  }

  try {
    const p = ProjectivePoint.fromHex(point);
    const result = p.multiply(s);
    // Check if result is identity (can happen with certain scalars)
    if (result.equals(ProjectivePoint.ZERO)) {
      return new Uint8Array(IDENTITY_BYTES);
    }
    return result.toRawBytes(true); // compressed
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Scalar base multiplication: generator * scalar.
 * Handles zero scalar specially.
 */
function scalarBaseMulPoint(scalar: P256Scalar): P256Point {
  try {
    const s = bytesToBigInt(scalar);
    if (s === 0n) {
      return new Uint8Array(IDENTITY_BYTES);
    }
    const result = ProjectivePoint.BASE.multiply(s);
    return result.toRawBytes(true); // compressed
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Get the generator point
 */
function getGenerator(): P256Point {
  return ProjectivePoint.BASE.toRawBytes(true); // compressed
}

/**
 * Get the identity point (point at infinity)
 * Note: In SEC1 format, identity is encoded as a single 0x00 byte,
 * but for FROST we pad to 33 bytes
 */
function getIdentity(): P256Point {
  // For FROST purposes, we represent identity as 33 zero bytes
  return new Uint8Array(ELEMENT_SIZE);
}

/**
 * Check if two points are equal
 */
function pointsEqual(a: P256Point, b: P256Point): boolean {
  return constantTimeEquals(a, b);
}

/**
 * Serialize a point to SEC1 compressed format
 */
function serializePoint(point: P256Point): Uint8Array {
  // Check if point is identity - forbidden in FROST
  if (isIdentityPoint(point)) {
    throw GroupError.invalidIdentityElement();
  }
  return new Uint8Array(point);
}

/**
 * Deserialize a point from SEC1 compressed bytes
 */
function deserializePoint(bytes: Uint8Array): P256Point {
  if (bytes.length !== ELEMENT_SIZE) {
    throw GroupError.malformedElement();
  }

  // Check for all zeros (our identity representation)
  let allZero = true;
  for (const byte of bytes) {
    if (byte !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    throw GroupError.invalidIdentityElement();
  }

  try {
    const point = ProjectivePoint.fromHex(bytes);

    // Check for identity element
    if (point.equals(ProjectivePoint.ZERO)) {
      throw GroupError.invalidIdentityElement();
    }

    // Verify canonical encoding by re-encoding and comparing
    const reencoded = point.toRawBytes(true);
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
// P256 Field Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(P-256, SHA-256) ciphersuite scalar field.
 */
class P256ScalarFieldImpl implements Field<P256Scalar, Uint8Array> {
  zero(): P256Scalar {
    return new Uint8Array(SCALAR_SIZE);
  }

  one(): P256Scalar {
    const s = new Uint8Array(SCALAR_SIZE);
    s[SCALAR_SIZE - 1] = 1; // big-endian: one is [0, 0, ..., 1]
    return s;
  }

  invert(scalar: P256Scalar): P256Scalar {
    return scalarInvert(scalar);
  }

  random(rng: CryptoRng): P256Scalar {
    return randomScalar(rng);
  }

  serialize(scalar: P256Scalar): Uint8Array {
    // P-256 scalars are serialized in big-endian format
    return new Uint8Array(scalar);
  }

  littleEndianSerialize(scalar: P256Scalar): Uint8Array {
    // Reverse the big-endian serialization to get little-endian
    const serialized = this.serialize(scalar);
    const reversed = new Uint8Array(serialized.length);
    for (let i = 0; i < serialized.length; i++) {
      reversed[i] = serialized[serialized.length - 1 - i];
    }
    return reversed;
  }

  deserialize(buf: Uint8Array): P256Scalar {
    return deserializeScalar(buf);
  }

  add(a: P256Scalar, b: P256Scalar): P256Scalar {
    return scalarAdd(a, b);
  }

  sub(a: P256Scalar, b: P256Scalar): P256Scalar {
    return scalarSub(a, b);
  }

  mul(a: P256Scalar, b: P256Scalar): P256Scalar {
    return scalarMul(a, b);
  }

  negate(scalar: P256Scalar): P256Scalar {
    return scalarNegate(scalar);
  }

  eq(a: P256Scalar, b: P256Scalar): boolean {
    return constantTimeEquals(a, b);
  }

  isZero(scalar: P256Scalar): boolean {
    return isScalarZero(scalar);
  }
}

// ---------------------------------------------------------------------------
// P256 Group Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(P-256, SHA-256) ciphersuite group.
 */
class P256GroupImpl implements Group<P256ScalarFieldImpl, P256Point, Uint8Array> {
  readonly field: P256ScalarFieldImpl;

  constructor() {
    this.field = new P256ScalarFieldImpl();
  }

  cofactor(): P256Scalar {
    // P-256 has cofactor 1 (it's a prime-order group)
    return this.field.one();
  }

  identity(): P256Point {
    return getIdentity();
  }

  generator(): P256Point {
    return getGenerator();
  }

  serialize(element: P256Point): Uint8Array {
    return serializePoint(element);
  }

  deserialize(buf: Uint8Array): P256Point {
    return deserializePoint(buf);
  }

  add(a: P256Point, b: P256Point): P256Point {
    return pointAdd(a, b);
  }

  sub(a: P256Point, b: P256Point): P256Point {
    return pointSub(a, b);
  }

  scalarMul(element: P256Point, scalar: P256Scalar): P256Point {
    return pointMul(element, scalar);
  }

  scalarBaseMul(scalar: P256Scalar): P256Point {
    return scalarBaseMulPoint(scalar);
  }

  negate(element: P256Point): P256Point {
    return pointNegate(element);
  }

  eq(a: P256Point, b: P256Point): boolean {
    return pointsEqual(a, b);
  }

  isIdentity(element: P256Point): boolean {
    return isIdentityPoint(element);
  }
}

// ---------------------------------------------------------------------------
// Hash Functions
// ---------------------------------------------------------------------------

/**
 * Hash arbitrary inputs to a 32-byte array using SHA-256.
 * This is the internal hash function used by H4-H5.
 *
 * @param inputs - Array of byte arrays to concatenate and hash
 * @returns 32-byte output from SHA-256
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

  // Use SHA-256 to produce 32 bytes
  return sha256(concatenated);
}

/**
 * I2OSP (Integer to Octet String Primitive) from RFC 8017
 * Converts a non-negative integer to a big-endian byte string of specified length.
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
 * Expands a message using XMD (Expand Message XOF) with SHA-256.
 *
 * @param msg - The message to expand
 * @param dst - Domain separation tag
 * @param lenInBytes - Desired output length in bytes
 * @returns The expanded message
 */
function expandMessageXmd(msg: Uint8Array, dst: Uint8Array, lenInBytes: number): Uint8Array {
  // b_in_bytes = 32 (SHA-256 output size)
  // s_in_bytes = 64 (SHA-256 block size)
  const bInBytes = 32;
  const sInBytes = 64;

  // ell = ceil(len_in_bytes / b_in_bytes)
  const ell = Math.ceil(lenInBytes / bInBytes);

  // Check constraints
  if (ell > 255) {
    throw new Error("expand_message_xmd: ell > 255");
  }
  if (dst.length > 255) {
    throw new Error("expand_message_xmd: DST too long");
  }

  // DST_prime = DST || I2OSP(len(DST), 1)
  const dstPrime = new Uint8Array(dst.length + 1);
  dstPrime.set(dst, 0);
  dstPrime[dst.length] = dst.length;

  // Z_pad = I2OSP(0, s_in_bytes)
  const zPad = new Uint8Array(sInBytes);

  // l_i_b_str = I2OSP(len_in_bytes, 2)
  const libStr = i2osp(lenInBytes, 2);

  // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
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

  // b_0 = H(msg_prime)
  const b0 = sha256(msgPrime);

  // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  const b1Input = new Uint8Array(b0.length + 1 + dstPrime.length);
  b1Input.set(b0, 0);
  b1Input[b0.length] = 1;
  b1Input.set(dstPrime, b0.length + 1);
  let bPrev = sha256(b1Input);

  // uniform_bytes = b_1
  const uniformBytes = new Uint8Array(ell * bInBytes);
  uniformBytes.set(bPrev, 0);

  // for i in (2, ..., ell):
  for (let i = 2; i <= ell; i++) {
    // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
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

  // return substr(uniform_bytes, 0, len_in_bytes)
  return uniformBytes.slice(0, lenInBytes);
}

/**
 * hash_to_field from RFC 9380 Section 5.2
 * Hashes a message to one or more field elements.
 *
 * For P-256, we hash to a single scalar using expand_message_xmd.
 *
 * @param msg - The message to hash
 * @param dst - Domain separation tag
 * @returns A scalar in the P-256 field
 */
function hashToField(msg: Uint8Array, dst: Uint8Array): P256Scalar {
  // count = 1 (one field element)
  // m = 1 (extension degree for P-256 scalar field)
  // L = ceil((ceil(log2(p)) + k) / 8) where k = 128 (security parameter)
  // For P-256: ceil((256 + 128) / 8) = 48
  const L = 48;
  const lenInBytes = L;

  // uniform_bytes = expand_message(msg, DST, len_in_bytes)
  const uniformBytes = expandMessageXmd(msg, dst, lenInBytes);

  // Convert to scalar: interpret as big-endian integer and reduce mod n
  const bigValue = bytesToBigInt(uniformBytes);
  const reduced = bigValue % CURVE_ORDER;

  return bigIntToBytes(reduced, SCALAR_SIZE);
}

/**
 * Hash arbitrary inputs to a scalar using hash_to_field (RFC 9380 style).
 *
 * @param domain - Array of domain separation tag components
 * @param msg - The message to hash
 * @returns A scalar in the P-256 field
 */
function hashToScalar(domain: Uint8Array[], msg: Uint8Array): P256Scalar {
  // Concatenate domain components to form DST
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
// P256Sha256 Ciphersuite Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(P-256, SHA-256) ciphersuite.
 *
 * This ciphersuite uses:
 * - P-256 group (NIST P-256 / secp256r1) for group operations
 * - SHA-256 for hashing
 * - 32-byte scalars (big-endian)
 * - 33-byte SEC1 compressed points
 *
 * The ciphersuite follows RFC 9591 Section 6.4 specification.
 */
class P256Sha256Impl implements RandomizedCiphersuite {
  readonly ID = CONTEXT_STRING;
  readonly group: P256GroupImpl;

  // Type brand properties
  Scalar!: P256Scalar;
  Element!: P256Point;
  VerifyingKey!: VerifyingKey<P256Sha256Impl>;
  SigningKey!: SigningKey<P256Sha256Impl>;

  constructor() {
    this.group = new P256GroupImpl();
  }

  // ---------------------------------------------------------------------------
  // Field Operations (flattened)
  // ---------------------------------------------------------------------------

  scalarZero(): P256Scalar {
    return this.group.field.zero();
  }

  scalarOne(): P256Scalar {
    return this.group.field.one();
  }

  scalarInvert(scalar: P256Scalar): P256Scalar {
    return this.group.field.invert(scalar);
  }

  scalarRandom(rng: { fill(array: Uint8Array): void }): P256Scalar {
    return this.group.field.random(rng as CryptoRng);
  }

  serializeScalar(scalar: P256Scalar): Uint8Array {
    return this.group.field.serialize(scalar);
  }

  deserializeScalar(bytes: Uint8Array): P256Scalar {
    return this.group.field.deserialize(bytes);
  }

  scalarAdd(a: P256Scalar, b: P256Scalar): P256Scalar {
    return this.group.field.add(a, b);
  }

  scalarSub(a: P256Scalar, b: P256Scalar): P256Scalar {
    return this.group.field.sub(a, b);
  }

  scalarMul(a: P256Scalar, b: P256Scalar): P256Scalar {
    return this.group.field.mul(a, b);
  }

  scalarsEqual(a: P256Scalar, b: P256Scalar): boolean {
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

  cofactor(): P256Scalar {
    return this.group.cofactor();
  }

  identity(): P256Point {
    return this.group.identity();
  }

  generator(): P256Point {
    return this.group.generator();
  }

  serializeElement(element: P256Point): Uint8Array {
    return this.group.serialize(element);
  }

  deserializeElement(bytes: Uint8Array): P256Point {
    return this.group.deserialize(bytes);
  }

  elementAdd(a: P256Point, b: P256Point): P256Point {
    return this.group.add(a, b);
  }

  elementSub(a: P256Point, b: P256Point): P256Point {
    return this.group.sub(a, b);
  }

  elementMul(element: P256Point, scalar: P256Scalar): P256Point {
    return this.group.scalarMul(element, scalar);
  }

  scalarBaseMult(scalar: P256Scalar): P256Point {
    return this.group.scalarBaseMul(scalar);
  }

  elementsEqual(a: P256Point, b: P256Point): boolean {
    return this.group.eq(a, b);
  }

  isIdentity(element: P256Point): boolean {
    return this.group.isIdentity(element);
  }

  // ---------------------------------------------------------------------------
  // Hash Functions (RFC 9591 Section 6.4)
  // ---------------------------------------------------------------------------

  /**
   * H1 for FROST(P-256, SHA-256)
   *
   * H1(m) = hash_to_field(m, "FROST-P256-SHA256-v1" || "rho")
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.4-2.4.2.2
   */
  H1(m: Uint8Array): P256Scalar {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("rho")],
      m,
    );
  }

  /**
   * H2 for FROST(P-256, SHA-256)
   *
   * H2(m) = hash_to_field(m, "FROST-P256-SHA256-v1" || "chal")
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.4-2.4.2.4
   */
  H2(m: Uint8Array): P256Scalar {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("chal")],
      m,
    );
  }

  /**
   * H3 for FROST(P-256, SHA-256)
   *
   * H3(m) = hash_to_field(m, "FROST-P256-SHA256-v1" || "nonce")
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.4-2.4.2.6
   */
  H3(m: Uint8Array): P256Scalar {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("nonce")],
      m,
    );
  }

  /**
   * H4 for FROST(P-256, SHA-256)
   *
   * H4(m) = SHA-256("FROST-P256-SHA256-v1" || "msg" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.4-2.4.2.8
   */
  H4(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("msg"),
      m,
    ]);
  }

  /**
   * H5 for FROST(P-256, SHA-256)
   *
   * H5(m) = SHA-256("FROST-P256-SHA256-v1" || "com" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.4-2.4.2.10
   */
  H5(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("com"),
      m,
    ]);
  }

  /**
   * HDKG for FROST(P-256, SHA-256)
   *
   * HDKG(m) = hash_to_field(m, "FROST-P256-SHA256-v1" || "dkg")
   *
   * Used for distributed key generation.
   */
  HDKG(m: Uint8Array): P256Scalar | null {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("dkg")],
      m,
    );
  }

  /**
   * HID for FROST(P-256, SHA-256)
   *
   * HID(m) = hash_to_field(m, "FROST-P256-SHA256-v1" || "id")
   *
   * Used for deriving identifiers from arbitrary byte strings.
   */
  HID(m: Uint8Array): P256Scalar | null {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("id")],
      m,
    );
  }

  /**
   * hashRandomizer for RandomizedCiphersuite
   *
   * hashRandomizer(m) = hash_to_field(m, "FROST-P256-SHA256-v1" || "randomizer")
   *
   * Used for re-randomized FROST signatures.
   */
  hashRandomizer(m: Uint8Array): P256Scalar | null {
    return hashToScalar(
      [new TextEncoder().encode(CONTEXT_STRING), new TextEncoder().encode("randomizer")],
      m,
    );
  }

  // ---------------------------------------------------------------------------
  // Signature Challenge Computation
  // ---------------------------------------------------------------------------

  /**
   * Compute the signature challenge.
   *
   * For P-256, this follows the FROST challenge computation
   * from RFC 9591 Section 6.4.
   */
  challenge(
    R: P256Point,
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
      pkBytes = (verifyingKey as VerifyingKey<P256Sha256Impl>).serialize();
    } else {
      pkBytes = this.group.serialize(verifyingKey as P256Point);
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
    // Handle both VerifyingKey objects and raw elements (P256 points)
    let vkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof (verifyingKey as { serialize: unknown }).serialize === "function"
    ) {
      vkBytes = (verifyingKey as VerifyingKey<P256Sha256Impl>).serialize();
    } else {
      // It's a raw element, serialize it directly
      vkBytes = this.group.serialize(verifyingKey as P256Point);
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
      const hidingElement = commitment.hiding.toElement() as P256Point;
      const bindingElement = commitment.binding.toElement() as P256Point;
      const scaledBinding = this.elementMul(bindingElement, bindingFactor.toScalar() as P256Scalar);
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
  ): P256Scalar {
    const signerIds = [...signingPackage.signingCommitments.keys()] as { toScalar(): unknown }[];

    let numerator = this.scalarOne();
    let denominator = this.scalarOne();

    const xI = signerId.toScalar() as P256Scalar;
    const x = this.scalarZero(); // x = 0 for the shared secret

    for (const id of signerIds) {
      const xJ = id.toScalar() as P256Scalar;

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
 * The P256Sha256 ciphersuite instance.
 * This is a singleton that should be used for all P-256 FROST operations.
 */
export const P256Sha256: P256Sha256Impl = new P256Sha256Impl();

// Export the implementation class for type references
export type { P256Sha256Impl };

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/** A FROST(P-256, SHA-256) participant identifier */
export type P256Identifier = Identifier<P256Sha256Impl>;

/** An error from FROST(P-256, SHA-256) operations */
export type P256Error = ReturnType<typeof FrostError.invalidMinSigners>;

/** A FROST(P-256, SHA-256) signing package */
export type P256SigningPackage = SigningPackage<P256Sha256Impl>;

/** A FROST(P-256, SHA-256) signature */
export type P256Signature = Signature<P256Sha256Impl>;

/** A FROST(P-256, SHA-256) signing key */
export type P256SigningKey = SigningKey<P256Sha256Impl>;

/** A FROST(P-256, SHA-256) verifying key */
export type P256VerifyingKey = VerifyingKey<P256Sha256Impl>;

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

/** Comprised of FROST(P-256, SHA-256) hiding and binding nonces */
export type P256SigningNonces = CoreSigningNonces<P256Sha256Impl>;

/** Published by each participant in the first round of the signing protocol */
export type P256SigningCommitments = CoreSigningCommitments<P256Sha256Impl>;

/** A commitment to a signing nonce share */
export type P256NonceCommitment = CoreNonceCommitment<P256Sha256Impl>;

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
  secret: CoreSigningShare<P256Sha256Impl>,
  rng: RandomSource,
): [P256SigningNonces, P256SigningCommitments] {
  return coreCommit(P256Sha256, secret, rng);
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

/** A FROST(P-256, SHA-256) participant's signature share */
export type P256SignatureShare = CoreSignatureShare<P256Sha256Impl>;

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
  signingPackage: P256SigningPackage,
  signerNonces: CoreSigningNonces<P256Sha256Impl>,
  keyPackage: CoreKeyPackage<P256Sha256Impl>,
): P256SignatureShare {
  return coreSign(P256Sha256, signingPackage, signerNonces, keyPackage);
}

// ---------------------------------------------------------------------------
// Top-level Functions
// ---------------------------------------------------------------------------

/**
 * Verifies each FROST(P-256, SHA-256) participant's signature share, and if all are valid,
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
  signingPackage: P256SigningPackage,
  signatureShares: Map<P256Identifier, CoreSignatureShare<P256Sha256Impl>>,
  pubkeys: CorePublicKeyPackage<P256Sha256Impl>,
): P256Signature {
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
  signingPackage: P256SigningPackage,
  signatureShares: Map<P256Identifier, CoreSignatureShare<P256Sha256Impl>>,
  pubkeys: CorePublicKeyPackage<P256Sha256Impl>,
  cheaterDetection: CheaterDetection,
): P256Signature {
  return aggregateImpl(signingPackage, signatureShares, pubkeys, cheaterDetection === CheaterDetection.Full);
}

/**
 * Internal aggregate implementation.
 */
function aggregateImpl(
  signingPackage: P256SigningPackage,
  signatureShares: Map<P256Identifier, CoreSignatureShare<P256Sha256Impl>>,
  pubkeys: CorePublicKeyPackage<P256Sha256Impl>,
  verifySigShares: boolean,
): P256Signature {
  // Get the verifying key
  const verifyingKey = VerifyingKey.create(P256Sha256, pubkeys.verifyingKey);

  // Compute the binding factor list
  const bindingFactorList = P256Sha256.computeBindingFactorList(
    signingPackage,
    verifyingKey,
    new Uint8Array(0),
  );

  // Compute the group commitment
  const groupCommitment = P256Sha256.computeGroupCommitment(
    signingPackage,
    bindingFactorList,
  );

  // Compute the challenge
  const challenge = P256Sha256.challenge(
    groupCommitment.toElement(),
    verifyingKey,
    signingPackage.message,
  );

  // Aggregate the signature shares
  let z = P256Sha256.scalarZero();

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
      const scaledBinding = P256Sha256.elementMul(bindingElement, bindingFactor.toScalar());
      const commitmentShare = P256Sha256.elementAdd(hidingElement, scaledBinding);

      // Compute lambda_i (Lagrange coefficient)
      const lambdaI = P256Sha256.deriveInterpolatingValue(identifier, signingPackage);

      // Verify: z_i * G = R_i + (c * lambda_i) * Y_i
      const shareScalar = share.toScalar();
      const lhs = P256Sha256.scalarBaseMult(shareScalar);

      const challengeTimesLambda = P256Sha256.scalarMul(
        challenge.toScalar(),
        lambdaI,
      );
      const verifyingElement = verifyingShare.toElement();
      const scaledVerifyingShare = P256Sha256.elementMul(verifyingElement, challengeTimesLambda);
      const rhs = P256Sha256.elementAdd(commitmentShare, scaledVerifyingShare);

      if (!P256Sha256.elementsEqual(lhs, rhs)) {
        throw new Error(`Invalid signature share from participant ${identifier.toString()}`);
      }
    }

    // Add to aggregate
    z = P256Sha256.scalarAdd(z, share.toScalar());
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
