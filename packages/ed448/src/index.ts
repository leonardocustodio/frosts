/**
 * FROST(Ed448, SHAKE256) - A Schnorr signature scheme over Ed448 that supports FROST threshold signatures
 *
 * This module provides a complete implementation of the FROST ciphersuite for the Ed448
 * elliptic curve (Edwards 448-Goldilocks) with SHAKE256 as the hash function, following
 * RFC 9591 Section 6.3.
 *
 * @packageDocumentation
 * @module @frosts/ed448
 */

import { shake256 } from "@noble/hashes/sha3.js";
import { ed448 } from "@noble/curves/ed448.js";

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

/** Context string from the ciphersuite in the spec (RFC 9591 Section 6.3) */
const CONTEXT_STRING = "FROST-ED448-SHAKE256-v1";

/** Scalar size in bytes (57 bytes for Ed448) */
const SCALAR_SIZE = 57;

/** Element size in bytes (57 bytes for compressed Ed448 points) */
const ELEMENT_SIZE = 57;

/** Hash output size for SHAKE256 XOF (114 bytes = 912 bits) */
const HASH_OUTPUT_SIZE = 114;

// ---------------------------------------------------------------------------
// Type Definitions
// ---------------------------------------------------------------------------

/**
 * Ed448 scalar type - a 57-byte little-endian encoded value representing
 * an element of the scalar field GF(q) where q is the order of the Ed448 curve.
 */
type Ed448Scalar = Uint8Array;

/**
 * Ed448 point type - a 57-byte compressed Edwards point representation.
 * The compression format is the y-coordinate with the sign of x encoded in the MSB.
 */
type Ed448Point = Uint8Array;

// ---------------------------------------------------------------------------
// Field Operations for Ed448 Scalar Field
// ---------------------------------------------------------------------------

/**
 * The order of the Ed448 curve (subgroup order).
 * This is the number of points in the prime-order subgroup.
 * This value matches noble-curves ed448.CURVE.n
 *
 * n = 2^446 - 13818066809895115352007386748515426880336692926039124900827223412983559366852254106953
 */
const CURVE_ORDER = BigInt(
  "181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779",
);

/**
 * The multiplicative inverse of the cofactor (4) modulo the curve order.
 * Used for torsion-free checking: a point P is torsion-free iff P == (4*P) * COFACTOR_INVERSE
 *
 * Since n mod 4 = 3, we have 4^-1 = (n+1)/4 mod n
 */
const COFACTOR_INVERSE = (CURVE_ORDER + 1n) / 4n;

/** Zero scalar (additive identity) - 57 zero bytes */
const ZERO_SCALAR = new Uint8Array(SCALAR_SIZE);

/** One scalar (multiplicative identity) - encoded as [1, 0, 0, ...] in little-endian */
const _ONE_SCALAR = (() => {
  const s = new Uint8Array(SCALAR_SIZE);
  s[0] = 1;
  return s;
})();
// Reference to document this constant exists (used for potential future implementation)
void _ONE_SCALAR;

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
function isScalarZero(scalar: Ed448Scalar): boolean {
  return constantTimeEquals(scalar, ZERO_SCALAR);
}

/**
 * Add two scalars modulo the curve order
 */
function scalarAdd(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig + bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Subtract two scalars modulo the curve order
 */
function scalarSub(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
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
function scalarMul(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig * bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Negate a scalar modulo the curve order
 */
function scalarNegate(a: Ed448Scalar): Ed448Scalar {
  if (isScalarZero(a)) return new Uint8Array(a);
  const aBig = bytesToBigInt(a);
  const result = CURVE_ORDER - aBig;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Compute the multiplicative inverse of a scalar modulo the curve order.
 * Uses the extended Euclidean algorithm (Fermat's little theorem).
 */
function scalarInvert(a: Ed448Scalar): Ed448Scalar {
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
function randomScalar(rng: CryptoRng): Ed448Scalar {
  // Generate 114 random bytes (2x the scalar size) and reduce mod q
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
function deserializeScalar(bytes: Uint8Array): Ed448Scalar {
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
// Group Operations for Ed448 Curve
// ---------------------------------------------------------------------------

/**
 * The identity element (point at infinity) - encoded as all zeros with MSB set
 */
const _IDENTITY_POINT = (() => {
  const p = new Uint8Array(ELEMENT_SIZE);
  // In Ed448 the identity point encodes as (0, 1) in compressed form
  // which is 0x01 followed by zeros
  p[0] = 1;
  return p;
})();
// Reference to document this constant exists (used for potential future implementation)
void _IDENTITY_POINT;

/**
 * Check if a point is the identity element
 */
function isIdentityPoint(point: Ed448Point): boolean {
  // The identity (0, 1) has y = 1, x = 0, so compressed it's [0x01, 0, ..., 0]
  // But ed448.Point.ZERO.toBytes() gives us the proper encoding
  try {
    const decoded = ed448.Point.fromBytes(point);
    return decoded.equals(ed448.Point.ZERO);
  } catch {
    return false;
  }
}

/**
 * Add two points on the curve
 */
function pointAdd(a: Ed448Point, b: Ed448Point): Ed448Point {
  try {
    const aPoint = ed448.Point.fromBytes(a);
    const bPoint = ed448.Point.fromBytes(b);
    const result = aPoint.add(bPoint);
    return result.toBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Subtract two points on the curve
 */
function pointSub(a: Ed448Point, b: Ed448Point): Ed448Point {
  try {
    const aPoint = ed448.Point.fromBytes(a);
    const bPoint = ed448.Point.fromBytes(b);
    const result = aPoint.subtract(bPoint);
    return result.toBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Negate a point on the curve
 */
function pointNegate(a: Ed448Point): Ed448Point {
  try {
    const aPoint = ed448.Point.fromBytes(a);
    const result = aPoint.negate();
    return result.toBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Scalar multiplication: point * scalar
 */
function pointMul(point: Ed448Point, scalar: Ed448Scalar): Ed448Point {
  try {
    const p = ed448.Point.fromBytes(point);
    const s = bytesToBigInt(scalar);
    const result = p.multiply(s);
    return result.toBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Scalar base multiplication: generator * scalar
 *
 * Note: This handles zero scalar specially by returning the identity point.
 * This is required for FROST refresh operations which use zero-constant polynomials.
 */
function scalarBaseMul(scalar: Ed448Scalar): Ed448Point {
  try {
    const s = bytesToBigInt(scalar);
    // Handle zero scalar specially - return identity point
    // This is needed for FROST refresh which uses zero-constant polynomials
    if (s === 0n) {
      return ed448.Point.ZERO.toBytes();
    }
    const result = ed448.Point.BASE.multiply(s);
    return result.toBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Get the generator point
 */
function getGenerator(): Ed448Point {
  return ed448.Point.BASE.toBytes();
}

/**
 * Get the identity point
 */
function getIdentity(): Ed448Point {
  return ed448.Point.ZERO.toBytes();
}

/**
 * Check if two points are equal
 */
function pointsEqual(a: Ed448Point, b: Ed448Point): boolean {
  return constantTimeEquals(a, b);
}

/**
 * Serialize a point (already in compressed form)
 */
function serializePoint(point: Ed448Point): Uint8Array {
  // Check if point is identity - forbidden in FROST
  if (isIdentityPoint(point)) {
    throw GroupError.invalidIdentityElement();
  }
  return new Uint8Array(point);
}

/**
 * Check if a point is torsion-free (in the prime-order subgroup).
 *
 * For Ed448 with cofactor 4, a point P is torsion-free if and only if:
 * P == (4 * P) * (4^-1 mod n)
 *
 * This works because if P has a torsion component T (where T has order dividing 4):
 * - P = P_prime + T (where P_prime is in the prime subgroup)
 * - 4 * P = 4 * P_prime + 4 * T = 4 * P_prime (since 4*T = identity)
 * - (4 * P) * (4^-1) = P_prime
 * So if P has any torsion component, the recovered point won't equal P.
 *
 * This matches the is_torsion_free() check in the Rust ed448_goldilocks crate.
 */
function isTorsionFree(point: InstanceType<typeof ed448.Point>): boolean {
  // Multiply by cofactor (4) to clear any torsion component
  const clearedPoint = point.multiply(4n);

  // Multiply by cofactor inverse to recover a prime-subgroup point
  const recoveredPoint = clearedPoint.multiply(COFACTOR_INVERSE);

  // If original point equals recovered point, it was torsion-free
  return point.equals(recoveredPoint);
}

/**
 * Deserialize a point from bytes.
 *
 * This matches the Rust implementation's deserialize logic:
 * 1. Decompress the point
 * 2. Reject identity element
 * 3. Check if point is torsion-free (in prime-order subgroup)
 * 4. Verify canonical encoding by recompressing
 */
function deserializePoint(bytes: Uint8Array): Ed448Point {
  if (bytes.length !== ELEMENT_SIZE) {
    throw GroupError.malformedElement();
  }

  try {
    const point = ed448.Point.fromBytes(bytes);

    // Check for identity element
    if (point.equals(ed448.Point.ZERO)) {
      throw GroupError.invalidIdentityElement();
    }

    // Check that point is in the prime-order subgroup (torsion-free)
    // This matches Rust's: if point.is_torsion_free() { ... } else { Err(InvalidNonPrimeOrderElement) }
    if (!isTorsionFree(point)) {
      throw GroupError.invalidNonPrimeOrderElement();
    }

    // Verify canonical encoding by re-encoding and comparing
    // decompress() does not check for canonicality, so we check by recompressing
    const reencoded = point.toBytes();
    if (!constantTimeEquals(bytes, reencoded)) {
      throw GroupError.malformedElement();
    }

    return reencoded;
  } catch (e) {
    // Re-throw our specific errors
    if (e instanceof Error) {
      if (e.message.includes("identity")) {
        throw GroupError.invalidIdentityElement();
      }
      if (e.message.includes("prime order") || e.message.includes("non-prime")) {
        throw GroupError.invalidNonPrimeOrderElement();
      }
    }
    throw GroupError.malformedElement();
  }
}

// ---------------------------------------------------------------------------
// Ed448 Field Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(Ed448, SHAKE256) ciphersuite scalar field.
 */
class Ed448ScalarFieldImpl implements Field<Ed448Scalar, Uint8Array> {
  zero(): Ed448Scalar {
    return new Uint8Array(SCALAR_SIZE);
  }

  one(): Ed448Scalar {
    const s = new Uint8Array(SCALAR_SIZE);
    s[0] = 1;
    return s;
  }

  invert(scalar: Ed448Scalar): Ed448Scalar {
    return scalarInvert(scalar);
  }

  random(rng: CryptoRng): Ed448Scalar {
    return randomScalar(rng);
  }

  serialize(scalar: Ed448Scalar): Uint8Array {
    return new Uint8Array(scalar);
  }

  littleEndianSerialize(scalar: Ed448Scalar): Uint8Array {
    // Ed448 scalars are already in little-endian format (RFC 8032)
    return this.serialize(scalar);
  }

  deserialize(buf: Uint8Array): Ed448Scalar {
    return deserializeScalar(buf);
  }

  add(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
    return scalarAdd(a, b);
  }

  sub(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
    return scalarSub(a, b);
  }

  mul(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
    return scalarMul(a, b);
  }

  negate(scalar: Ed448Scalar): Ed448Scalar {
    return scalarNegate(scalar);
  }

  eq(a: Ed448Scalar, b: Ed448Scalar): boolean {
    return constantTimeEquals(a, b);
  }

  isZero(scalar: Ed448Scalar): boolean {
    return isScalarZero(scalar);
  }
}

// ---------------------------------------------------------------------------
// Ed448 Group Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(Ed448, SHAKE256) ciphersuite group.
 */
class Ed448GroupImpl implements Group<Ed448ScalarFieldImpl, Ed448Point, Uint8Array> {
  readonly field: Ed448ScalarFieldImpl;

  constructor() {
    this.field = new Ed448ScalarFieldImpl();
  }

  cofactor(): Ed448Scalar {
    // Ed448 uses a prime-order subgroup, so for FROST purposes cofactor is 1
    // (the actual curve cofactor is 4, but we work in the prime-order subgroup)
    return this.field.one();
  }

  identity(): Ed448Point {
    return getIdentity();
  }

  generator(): Ed448Point {
    return getGenerator();
  }

  serialize(element: Ed448Point): Uint8Array {
    return serializePoint(element);
  }

  deserialize(buf: Uint8Array): Ed448Point {
    return deserializePoint(buf);
  }

  add(a: Ed448Point, b: Ed448Point): Ed448Point {
    return pointAdd(a, b);
  }

  sub(a: Ed448Point, b: Ed448Point): Ed448Point {
    return pointSub(a, b);
  }

  scalarMul(element: Ed448Point, scalar: Ed448Scalar): Ed448Point {
    return pointMul(element, scalar);
  }

  scalarBaseMul(scalar: Ed448Scalar): Ed448Point {
    return scalarBaseMul(scalar);
  }

  negate(element: Ed448Point): Ed448Point {
    return pointNegate(element);
  }

  eq(a: Ed448Point, b: Ed448Point): boolean {
    return pointsEqual(a, b);
  }

  isIdentity(element: Ed448Point): boolean {
    return isIdentityPoint(element);
  }
}

// ---------------------------------------------------------------------------
// Hash Functions
// ---------------------------------------------------------------------------

/**
 * Hash arbitrary inputs to a 114-byte array using SHAKE256.
 * This is the internal hash function used by H1-H5 and HDKG/HID.
 *
 * @param inputs - Array of byte arrays to concatenate and hash
 * @returns 114-byte output from SHAKE256
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

  // Use SHAKE256 XOF to produce 114 bytes
  return shake256(concatenated, { dkLen: HASH_OUTPUT_SIZE });
}

/**
 * Hash arbitrary inputs to a scalar using SHAKE256.
 * Uses wide reduction from 114 bytes to ensure uniform distribution.
 *
 * @param inputs - Array of byte arrays to concatenate and hash
 * @returns A scalar in the Ed448 field
 */
function hashToScalar(inputs: Uint8Array[]): Ed448Scalar {
  const hashOutput = hashToArray(inputs);
  const bigValue = bytesToBigInt(hashOutput);
  const reduced = bigValue % CURVE_ORDER;
  return bigIntToBytes(reduced, SCALAR_SIZE);
}

// ---------------------------------------------------------------------------
// Ed448Shake256 Ciphersuite Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(Ed448, SHAKE256) ciphersuite.
 *
 * This ciphersuite uses:
 * - Ed448-Goldilocks curve for group operations
 * - SHAKE256 XOF for hashing
 * - 57-byte serialization for both scalars and points
 *
 * The ciphersuite follows RFC 9591 Section 6.3 specification.
 */
class Ed448Shake256Impl implements RandomizedCiphersuite {
  readonly ID = CONTEXT_STRING;
  readonly group: Ed448GroupImpl;

  // Type brand properties
  Scalar!: Ed448Scalar;
  Element!: Ed448Point;
  VerifyingKey!: VerifyingKey<Ed448Shake256Impl>;
  SigningKey!: SigningKey<Ed448Shake256Impl>;

  constructor() {
    this.group = new Ed448GroupImpl();
  }

  // ---------------------------------------------------------------------------
  // Field Operations (flattened)
  // ---------------------------------------------------------------------------

  scalarZero(): Ed448Scalar {
    return this.group.field.zero();
  }

  scalarOne(): Ed448Scalar {
    return this.group.field.one();
  }

  scalarInvert(scalar: Ed448Scalar): Ed448Scalar {
    return this.group.field.invert(scalar);
  }

  scalarRandom(rng: { fill(array: Uint8Array): void }): Ed448Scalar {
    return this.group.field.random(rng as CryptoRng);
  }

  serializeScalar(scalar: Ed448Scalar): Uint8Array {
    return this.group.field.serialize(scalar);
  }

  deserializeScalar(bytes: Uint8Array): Ed448Scalar {
    return this.group.field.deserialize(bytes);
  }

  scalarAdd(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
    return this.group.field.add(a, b);
  }

  scalarSub(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
    return this.group.field.sub(a, b);
  }

  scalarMul(a: Ed448Scalar, b: Ed448Scalar): Ed448Scalar {
    return this.group.field.mul(a, b);
  }

  scalarsEqual(a: Ed448Scalar, b: Ed448Scalar): boolean {
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

  cofactor(): Ed448Scalar {
    return this.group.cofactor();
  }

  identity(): Ed448Point {
    return this.group.identity();
  }

  generator(): Ed448Point {
    return this.group.generator();
  }

  serializeElement(element: Ed448Point): Uint8Array {
    return this.group.serialize(element);
  }

  deserializeElement(bytes: Uint8Array): Ed448Point {
    return this.group.deserialize(bytes);
  }

  elementAdd(a: Ed448Point, b: Ed448Point): Ed448Point {
    return this.group.add(a, b);
  }

  elementSub(a: Ed448Point, b: Ed448Point): Ed448Point {
    return this.group.sub(a, b);
  }

  elementMul(element: Ed448Point, scalar: Ed448Scalar): Ed448Point {
    return this.group.scalarMul(element, scalar);
  }

  scalarBaseMult(scalar: Ed448Scalar): Ed448Point {
    return this.group.scalarBaseMul(scalar);
  }

  elementsEqual(a: Ed448Point, b: Ed448Point): boolean {
    return this.group.eq(a, b);
  }

  isIdentity(element: Ed448Point): boolean {
    return this.group.isIdentity(element);
  }

  // ---------------------------------------------------------------------------
  // Hash Functions (RFC 9591 Section 6.3)
  // ---------------------------------------------------------------------------

  /**
   * H1 for FROST(Ed448, SHAKE256)
   *
   * H1(m) = SHAKE256("FROST-ED448-SHAKE256-v1" || "rho" || m, 114)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.3-2.4.2.2
   */
  H1(m: Uint8Array): Ed448Scalar {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("rho"),
      m,
    ]);
  }

  /**
   * H2 for FROST(Ed448, SHAKE256)
   *
   * H2(m) = SHAKE256("SigEd448" || 0x00 || 0x00 || m, 114)
   *
   * This matches the Ed448 signature challenge hash to ensure compatibility
   * with single-signer Ed448 signatures.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.3-2.4.2.4
   */
  H2(m: Uint8Array): Ed448Scalar {
    const prefix = new Uint8Array([
      0x53,
      0x69,
      0x67,
      0x45,
      0x64,
      0x34,
      0x34,
      0x38, // "SigEd448"
      0x00,
      0x00, // two null bytes for empty context
    ]);
    return hashToScalar([prefix, m]);
  }

  /**
   * H3 for FROST(Ed448, SHAKE256)
   *
   * H3(m) = SHAKE256("FROST-ED448-SHAKE256-v1" || "nonce" || m, 114)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.3-2.4.2.6
   */
  H3(m: Uint8Array): Ed448Scalar {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("nonce"),
      m,
    ]);
  }

  /**
   * H4 for FROST(Ed448, SHAKE256)
   *
   * H4(m) = SHAKE256("FROST-ED448-SHAKE256-v1" || "msg" || m, 114)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.3-2.4.2.8
   */
  H4(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("msg"),
      m,
    ]);
  }

  /**
   * H5 for FROST(Ed448, SHAKE256)
   *
   * H5(m) = SHAKE256("FROST-ED448-SHAKE256-v1" || "com" || m, 114)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.3-2.4.2.10
   */
  H5(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("com"),
      m,
    ]);
  }

  /**
   * HDKG for FROST(Ed448, SHAKE256)
   *
   * HDKG(m) = SHAKE256("FROST-ED448-SHAKE256-v1" || "dkg" || m, 114)
   *
   * Used for distributed key generation.
   */
  HDKG(m: Uint8Array): Ed448Scalar | null {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("dkg"),
      m,
    ]);
  }

  /**
   * HID for FROST(Ed448, SHAKE256)
   *
   * HID(m) = SHAKE256("FROST-ED448-SHAKE256-v1" || "id" || m, 114)
   *
   * Used for deriving identifiers from arbitrary byte strings.
   */
  HID(m: Uint8Array): Ed448Scalar | null {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("id"),
      m,
    ]);
  }

  /**
   * hashRandomizer for RandomizedCiphersuite
   *
   * hashRandomizer(m) = SHAKE256("FROST-ED448-SHAKE256-v1" || "randomizer" || m, 114)
   *
   * Used for re-randomized FROST signatures.
   */
  hashRandomizer(m: Uint8Array): Ed448Scalar | null {
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
   * For Ed448, this follows the standard Ed448 signature challenge computation
   * to ensure signatures are compatible with standard Ed448 verification.
   */
  challenge(R: Ed448Point, verifyingKey: unknown, message: Uint8Array): CoreChallenge<this> {
    // Build the preimage: R || verifying_key || message
    const rBytes = this.serializeElement(R);
    // Handle both VerifyingKey objects and raw elements
    let pkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof verifyingKey.serialize === "function"
    ) {
      pkBytes = (verifyingKey as VerifyingKey<Ed448Shake256Impl>).serialize();
    } else {
      pkBytes = this.group.serialize(verifyingKey as Ed448Point);
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
    // Handle both VerifyingKey objects and raw elements (Ed448 points)
    let vkBytes: Uint8Array;
    if (
      typeof verifyingKey === "object" &&
      verifyingKey !== null &&
      "serialize" in verifyingKey &&
      typeof verifyingKey.serialize === "function"
    ) {
      vkBytes = (verifyingKey as VerifyingKey<Ed448Shake256Impl>).serialize();
    } else {
      // It's a raw element, serialize it directly
      vkBytes = this.group.serialize(verifyingKey as Ed448Point);
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
      const hidingElement = commitment.hiding.toElement() as Ed448Point;
      const bindingElement = commitment.binding.toElement() as Ed448Point;
      const scaledBinding = this.elementMul(
        bindingElement,
        bindingFactor.toScalar() as Ed448Scalar,
      );
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
  ): Ed448Scalar {
    const signerIds = [...signingPackage.signingCommitments.keys()] as { toScalar(): unknown }[];

    let numerator = this.scalarOne();
    let denominator = this.scalarOne();

    const xI = signerId.toScalar() as Ed448Scalar;
    const x = this.scalarZero(); // x = 0 for the shared secret

    for (const id of signerIds) {
      const xJ = id.toScalar() as Ed448Scalar;

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
 * The Ed448Shake256 ciphersuite instance.
 * This is a singleton that should be used for all Ed448 FROST operations.
 */
export const Ed448Shake256: Ed448Shake256Impl = new Ed448Shake256Impl();

// Export the implementation class for type references
export type { Ed448Shake256Impl };

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/** A FROST(Ed448, SHAKE256) participant identifier */
export type Ed448Identifier = Identifier<Ed448Shake256Impl>;

/** An error from FROST(Ed448, SHAKE256) operations */
export type Ed448Error = ReturnType<typeof FrostError.invalidMinSigners>;

/** A FROST(Ed448, SHAKE256) signing package */
export type Ed448SigningPackage = SigningPackage<Ed448Shake256Impl>;

/** A FROST(Ed448, SHAKE256) signature */
export type Ed448Signature = Signature<Ed448Shake256Impl>;

/** A FROST(Ed448, SHAKE256) signing key */
export type Ed448SigningKey = SigningKey<Ed448Shake256Impl>;

/** A FROST(Ed448, SHAKE256) verifying key */
export type Ed448VerifyingKey = VerifyingKey<Ed448Shake256Impl>;

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

/** Comprised of FROST(Ed448, SHAKE256) hiding and binding nonces */
export type Ed448SigningNonces = CoreSigningNonces<Ed448Shake256Impl>;

/** Published by each participant in the first round of the signing protocol */
export type Ed448SigningCommitments = CoreSigningCommitments<Ed448Shake256Impl>;

/** A commitment to a signing nonce share */
export type Ed448NonceCommitment = CoreNonceCommitment<Ed448Shake256Impl>;

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
  secret: CoreSigningShare<Ed448Shake256Impl>,
  rng: RandomSource,
): [Ed448SigningNonces, Ed448SigningCommitments] {
  return coreCommit(Ed448Shake256, secret, rng);
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

/** A FROST(Ed448, SHAKE256) participant's signature share */
export type Ed448SignatureShare = CoreSignatureShare<Ed448Shake256Impl>;

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
  signingPackage: Ed448SigningPackage,
  signerNonces: CoreSigningNonces<Ed448Shake256Impl>,
  keyPackage: CoreKeyPackage<Ed448Shake256Impl>,
): Ed448SignatureShare {
  return coreSign(Ed448Shake256, signingPackage, signerNonces, keyPackage);
}

// ---------------------------------------------------------------------------
// Top-level Functions
// ---------------------------------------------------------------------------

/**
 * Verifies each FROST(Ed448, SHAKE256) participant's signature share, and if all are valid,
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
  signingPackage: Ed448SigningPackage,
  signatureShares: Map<Ed448Identifier, CoreSignatureShare<Ed448Shake256Impl>>,
  pubkeys: CorePublicKeyPackage<Ed448Shake256Impl>,
): Ed448Signature {
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
  signingPackage: Ed448SigningPackage,
  signatureShares: Map<Ed448Identifier, CoreSignatureShare<Ed448Shake256Impl>>,
  pubkeys: CorePublicKeyPackage<Ed448Shake256Impl>,
  cheaterDetection: CheaterDetection,
): Ed448Signature {
  return aggregateImpl(
    signingPackage,
    signatureShares,
    pubkeys,
    cheaterDetection === CheaterDetection.Full,
  );
}

/**
 * Internal aggregate implementation.
 */
function aggregateImpl(
  signingPackage: Ed448SigningPackage,
  signatureShares: Map<Ed448Identifier, CoreSignatureShare<Ed448Shake256Impl>>,
  pubkeys: CorePublicKeyPackage<Ed448Shake256Impl>,
  verifySigShares: boolean,
): Ed448Signature {
  // Get the verifying key
  const verifyingKey = VerifyingKey.create(Ed448Shake256, pubkeys.verifyingKey);

  // Compute the binding factor list
  const bindingFactorList = Ed448Shake256.computeBindingFactorList(
    signingPackage,
    verifyingKey,
    new Uint8Array(0),
  );

  // Compute the group commitment
  const groupCommitment = Ed448Shake256.computeGroupCommitment(signingPackage, bindingFactorList);

  // Compute the challenge
  const challenge = Ed448Shake256.challenge(
    groupCommitment.toElement(),
    verifyingKey,
    signingPackage.message,
  );

  // Aggregate the signature shares
  let z = Ed448Shake256.scalarZero();

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
      const scaledBinding = Ed448Shake256.elementMul(bindingElement, bindingFactor.toScalar());
      const commitmentShare = Ed448Shake256.elementAdd(hidingElement, scaledBinding);

      // Compute lambda_i (Lagrange coefficient)
      const lambdaI = Ed448Shake256.deriveInterpolatingValue(identifier, signingPackage);

      // Verify: z_i * G = R_i + (c * lambda_i) * Y_i
      const shareScalar = share.toScalar();
      const lhs = Ed448Shake256.scalarBaseMult(shareScalar);

      const challengeTimesLambda = Ed448Shake256.scalarMul(challenge.toScalar(), lambdaI);
      const verifyingElement = verifyingShare.toElement();
      const scaledVerifyingShare = Ed448Shake256.elementMul(verifyingElement, challengeTimesLambda);
      const rhs = Ed448Shake256.elementAdd(commitmentShare, scaledVerifyingShare);

      if (!Ed448Shake256.elementsEqual(lhs, rhs)) {
        throw new Error(`Invalid signature share from participant ${identifier.toString()}`);
      }
    }

    // Add to aggregate
    z = Ed448Shake256.scalarAdd(z, share.toScalar());
  }

  // Create the signature: (R, z)
  return new Signature(groupCommitment.toElement(), z);
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

// ---------------------------------------------------------------------------
// Serde submodule re-export
// ---------------------------------------------------------------------------

// Re-export the serde module for JSON serialization
export * as serde from "./serde.js";
