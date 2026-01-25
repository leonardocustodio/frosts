/**
 * FROST(Ed25519, SHA-512) - A Schnorr signature scheme over Ed25519 that supports FROST threshold signatures
 *
 * This module provides a complete implementation of the FROST ciphersuite for the Ed25519
 * group with SHA-512 as the hash function, following RFC 9591 Section 6.1.
 *
 * @packageDocumentation
 * @module @frost/ed25519
 */

import { sha512 } from "@noble/hashes/sha512";
import { ed25519 } from "@noble/curves/ed25519";

// Access ExtendedPoint from the ed25519 object
const ExtendedPoint = ed25519.ExtendedPoint;

import type {
  Ciphersuite,
  Field,
  Group,
  CryptoRng,
  SigningPackage,
  Challenge as CoreChallenge,
  BindingFactorList,
  GroupCommitment,
} from "@frost/core";

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
} from "@frost/core";

import type { RandomizedCiphersuite } from "@frost/rerandomized";

// Re-export core types and errors for convenience
export type { Ciphersuite, Field, Group } from "@frost/core";
export { FieldError, GroupError } from "@frost/core";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Context string from the ciphersuite in the spec (RFC 9591 Section 6.1) */
const CONTEXT_STRING = "FROST-ED25519-SHA512-v1";

/** Scalar size in bytes (32 bytes for Ed25519) */
const SCALAR_SIZE = 32;

/** Element size in bytes (32 bytes for compressed Edwards Y coordinates) */
const ELEMENT_SIZE = 32;

/** Hash output size for SHA-512 (64 bytes = 512 bits) */
const HASH_OUTPUT_SIZE = 64;

// ---------------------------------------------------------------------------
// Type Definitions
// ---------------------------------------------------------------------------

/**
 * Ed25519 scalar type - a 32-byte little-endian encoded value representing
 * an element of the scalar field.
 */
type Ed25519Scalar = Uint8Array;

/**
 * Ed25519 point type - a 32-byte compressed Edwards Y coordinate representation.
 */
type Ed25519Point = Uint8Array;

// ---------------------------------------------------------------------------
// Field Operations for Ed25519 Scalar Field
// ---------------------------------------------------------------------------

/**
 * The order of the Ed25519 group (same as ristretto255).
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
function isScalarZero(scalar: Ed25519Scalar): boolean {
  return constantTimeEquals(scalar, ZERO_SCALAR);
}

/**
 * Add two scalars modulo the curve order
 */
function scalarAdd(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig + bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Subtract two scalars modulo the curve order
 */
function scalarSub(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
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
function scalarMul(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const result = (aBig * bBig) % CURVE_ORDER;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Negate a scalar modulo the curve order
 */
function scalarNegate(a: Ed25519Scalar): Ed25519Scalar {
  if (isScalarZero(a)) return new Uint8Array(a);
  const aBig = bytesToBigInt(a);
  const result = CURVE_ORDER - aBig;
  return bigIntToBytes(result, SCALAR_SIZE);
}

/**
 * Compute the multiplicative inverse of a scalar modulo the curve order.
 * Uses the extended Euclidean algorithm (Fermat's little theorem).
 */
function scalarInvert(a: Ed25519Scalar): Ed25519Scalar {
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
function randomScalar(rng: CryptoRng): Ed25519Scalar {
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
function deserializeScalar(bytes: Uint8Array): Ed25519Scalar {
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
// Group Operations for Ed25519 Curve
// ---------------------------------------------------------------------------

/**
 * The cofactor of Ed25519 (h = 8)
 * Note: FROST treats the cofactor as 1 (uses prime-order subgroup)
 */
const _ED25519_COFACTOR = 8n;

/**
 * Check if a point is the identity element
 */
function isIdentityPoint(point: Ed25519Point): boolean {
  try {
    const decoded = ExtendedPoint.fromHex(point);
    return decoded.equals(ExtendedPoint.ZERO);
  } catch {
    return false;
  }
}

/**
 * Check if a point is torsion-free (in the prime-order subgroup)
 * A point is torsion-free if multiplying by the cofactor gives a valid non-identity point.
 */
function isTorsionFree(point: ExtendedPoint): boolean {
  // Multiply by cofactor (8) and check it's not identity
  // For points in the prime-order subgroup, this should give a valid point
  // For points with small-order components, this gives identity
  try {
    const multiplied = point.multiply(8n);
    return !multiplied.equals(ExtendedPoint.ZERO);
  } catch {
    return false;
  }
}

/**
 * Add two points on the curve
 */
function pointAdd(a: Ed25519Point, b: Ed25519Point): Ed25519Point {
  try {
    const aPoint = ExtendedPoint.fromHex(a);
    const bPoint = ExtendedPoint.fromHex(b);
    const result = aPoint.add(bPoint);
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Subtract two points on the curve
 */
function pointSub(a: Ed25519Point, b: Ed25519Point): Ed25519Point {
  try {
    const aPoint = ExtendedPoint.fromHex(a);
    const bPoint = ExtendedPoint.fromHex(b);
    const result = aPoint.subtract(bPoint);
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Negate a point on the curve
 */
function pointNegate(a: Ed25519Point): Ed25519Point {
  try {
    const aPoint = ExtendedPoint.fromHex(a);
    const result = aPoint.negate();
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Scalar multiplication: point * scalar
 */
function pointMul(point: Ed25519Point, scalar: Ed25519Scalar): Ed25519Point {
  try {
    const p = ExtendedPoint.fromHex(point);
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
function scalarBaseMulFn(scalar: Ed25519Scalar): Ed25519Point {
  try {
    const s = bytesToBigInt(scalar);
    const result = ExtendedPoint.BASE.multiply(s);
    return result.toRawBytes();
  } catch (_e) {
    throw GroupError.malformedElement();
  }
}

/**
 * Get the generator point (Ed25519 base point)
 */
function getGenerator(): Ed25519Point {
  return ExtendedPoint.BASE.toRawBytes();
}

/**
 * Get the identity point
 */
function getIdentity(): Ed25519Point {
  return ExtendedPoint.ZERO.toRawBytes();
}

/**
 * Check if two points are equal
 */
function pointsEqual(a: Ed25519Point, b: Ed25519Point): boolean {
  return constantTimeEquals(a, b);
}

/**
 * Serialize a point (already in compressed form)
 */
function serializePoint(point: Ed25519Point): Uint8Array {
  // Check if point is identity - forbidden in FROST
  if (isIdentityPoint(point)) {
    throw GroupError.invalidIdentityElement();
  }
  return new Uint8Array(point);
}

/**
 * Deserialize a point from bytes (CompressedEdwardsY format)
 */
function deserializePoint(bytes: Uint8Array): Ed25519Point {
  if (bytes.length !== ELEMENT_SIZE) {
    throw GroupError.malformedElement();
  }

  try {
    const point = ExtendedPoint.fromHex(bytes);

    // Check for identity element
    if (point.equals(ExtendedPoint.ZERO)) {
      throw GroupError.invalidIdentityElement();
    }

    // Check if point is torsion-free (in prime-order subgroup)
    // This is required by Ed25519 FROST to prevent attacks
    if (!isTorsionFree(point)) {
      throw GroupError.invalidNonPrimeOrderElement();
    }

    // Return the original bytes (they are already in canonical form if fromHex succeeded)
    return new Uint8Array(bytes);
  } catch (e) {
    if (e instanceof Error && (e.message.includes("identity") || e.message.includes("prime"))) {
      throw e;
    }
    throw GroupError.malformedElement();
  }
}

// ---------------------------------------------------------------------------
// Ed25519 Field Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(Ed25519, SHA-512) ciphersuite scalar field.
 */
class Ed25519ScalarFieldImpl implements Field<Ed25519Scalar, Uint8Array> {
  zero(): Ed25519Scalar {
    return new Uint8Array(SCALAR_SIZE);
  }

  one(): Ed25519Scalar {
    const s = new Uint8Array(SCALAR_SIZE);
    s[0] = 1;
    return s;
  }

  invert(scalar: Ed25519Scalar): Ed25519Scalar {
    return scalarInvert(scalar);
  }

  random(rng: CryptoRng): Ed25519Scalar {
    return randomScalar(rng);
  }

  serialize(scalar: Ed25519Scalar): Uint8Array {
    return new Uint8Array(scalar);
  }

  littleEndianSerialize(scalar: Ed25519Scalar): Uint8Array {
    // Ed25519 scalars are already in little-endian format
    return this.serialize(scalar);
  }

  deserialize(buf: Uint8Array): Ed25519Scalar {
    return deserializeScalar(buf);
  }

  add(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
    return scalarAdd(a, b);
  }

  sub(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
    return scalarSub(a, b);
  }

  mul(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
    return scalarMul(a, b);
  }

  negate(scalar: Ed25519Scalar): Ed25519Scalar {
    return scalarNegate(scalar);
  }

  eq(a: Ed25519Scalar, b: Ed25519Scalar): boolean {
    return constantTimeEquals(a, b);
  }

  isZero(scalar: Ed25519Scalar): boolean {
    return isScalarZero(scalar);
  }
}

// ---------------------------------------------------------------------------
// Ed25519 Group Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(Ed25519, SHA-512) ciphersuite group.
 */
class Ed25519GroupImpl implements Group<Ed25519ScalarFieldImpl, Ed25519Point, Uint8Array> {
  readonly field: Ed25519ScalarFieldImpl;

  constructor() {
    this.field = new Ed25519ScalarFieldImpl();
  }

  cofactor(): Ed25519Scalar {
    // FROST treats the cofactor as 1 for prime-order subgroup operations
    return this.field.one();
  }

  identity(): Ed25519Point {
    return getIdentity();
  }

  generator(): Ed25519Point {
    return getGenerator();
  }

  serialize(element: Ed25519Point): Uint8Array {
    return serializePoint(element);
  }

  deserialize(buf: Uint8Array): Ed25519Point {
    return deserializePoint(buf);
  }

  add(a: Ed25519Point, b: Ed25519Point): Ed25519Point {
    return pointAdd(a, b);
  }

  sub(a: Ed25519Point, b: Ed25519Point): Ed25519Point {
    return pointSub(a, b);
  }

  scalarMul(element: Ed25519Point, scalar: Ed25519Scalar): Ed25519Point {
    return pointMul(element, scalar);
  }

  scalarBaseMul(scalar: Ed25519Scalar): Ed25519Point {
    return scalarBaseMulFn(scalar);
  }

  negate(element: Ed25519Point): Ed25519Point {
    return pointNegate(element);
  }

  eq(a: Ed25519Point, b: Ed25519Point): boolean {
    return pointsEqual(a, b);
  }

  isIdentity(element: Ed25519Point): boolean {
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
 * @returns A scalar in the Ed25519 field
 */
function hashToScalar(inputs: Uint8Array[]): Ed25519Scalar {
  const hashOutput = hashToArray(inputs);
  const bigValue = bytesToBigInt(hashOutput);
  const reduced = bigValue % CURVE_ORDER;
  return bigIntToBytes(reduced, SCALAR_SIZE);
}

// ---------------------------------------------------------------------------
// Ed25519Sha512 Ciphersuite Implementation
// ---------------------------------------------------------------------------

/**
 * An implementation of the FROST(Ed25519, SHA-512) ciphersuite.
 *
 * This ciphersuite uses:
 * - Ed25519 group for group operations
 * - SHA-512 for hashing
 * - 32-byte serialization for both scalars and points
 *
 * The ciphersuite follows RFC 9591 Section 6.1 specification.
 */
class Ed25519Sha512Impl implements RandomizedCiphersuite {
  readonly ID = CONTEXT_STRING;
  readonly group: Ed25519GroupImpl;

  // Type brand properties
  Scalar!: Ed25519Scalar;
  Element!: Ed25519Point;
  VerifyingKey!: VerifyingKey<Ed25519Sha512Impl>;
  SigningKey!: SigningKey<Ed25519Sha512Impl>;

  constructor() {
    this.group = new Ed25519GroupImpl();
  }

  // ---------------------------------------------------------------------------
  // Field Operations (flattened)
  // ---------------------------------------------------------------------------

  scalarZero(): Ed25519Scalar {
    return this.group.field.zero();
  }

  scalarOne(): Ed25519Scalar {
    return this.group.field.one();
  }

  scalarInvert(scalar: Ed25519Scalar): Ed25519Scalar {
    return this.group.field.invert(scalar);
  }

  scalarRandom(rng: { fill(array: Uint8Array): void }): Ed25519Scalar {
    return this.group.field.random(rng as CryptoRng);
  }

  serializeScalar(scalar: Ed25519Scalar): Uint8Array {
    return this.group.field.serialize(scalar);
  }

  deserializeScalar(bytes: Uint8Array): Ed25519Scalar {
    return this.group.field.deserialize(bytes);
  }

  scalarAdd(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
    return this.group.field.add(a, b);
  }

  scalarSub(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
    return this.group.field.sub(a, b);
  }

  scalarMul(a: Ed25519Scalar, b: Ed25519Scalar): Ed25519Scalar {
    return this.group.field.mul(a, b);
  }

  scalarsEqual(a: Ed25519Scalar, b: Ed25519Scalar): boolean {
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

  cofactor(): Ed25519Scalar {
    return this.group.cofactor();
  }

  identity(): Ed25519Point {
    return this.group.identity();
  }

  generator(): Ed25519Point {
    return this.group.generator();
  }

  serializeElement(element: Ed25519Point): Uint8Array {
    return this.group.serialize(element);
  }

  deserializeElement(bytes: Uint8Array): Ed25519Point {
    return this.group.deserialize(bytes);
  }

  elementAdd(a: Ed25519Point, b: Ed25519Point): Ed25519Point {
    return this.group.add(a, b);
  }

  elementSub(a: Ed25519Point, b: Ed25519Point): Ed25519Point {
    return this.group.sub(a, b);
  }

  elementMul(element: Ed25519Point, scalar: Ed25519Scalar): Ed25519Point {
    return this.group.scalarMul(element, scalar);
  }

  scalarBaseMult(scalar: Ed25519Scalar): Ed25519Point {
    return this.group.scalarBaseMul(scalar);
  }

  elementsEqual(a: Ed25519Point, b: Ed25519Point): boolean {
    return this.group.eq(a, b);
  }

  isIdentity(element: Ed25519Point): boolean {
    return this.group.isIdentity(element);
  }

  // ---------------------------------------------------------------------------
  // Hash Functions (RFC 9591 Section 6.1)
  // ---------------------------------------------------------------------------

  /**
   * H1 for FROST(Ed25519, SHA-512)
   *
   * H1(m) = SHA-512("FROST-ED25519-SHA512-v1" || "rho" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.1-2.4.2.2
   */
  H1(m: Uint8Array): Ed25519Scalar {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("rho"),
      m,
    ]);
  }

  /**
   * H2 for FROST(Ed25519, SHA-512)
   *
   * H2(m) = SHA-512(m)
   *
   * Note: Unlike other hash functions, H2 for Ed25519 does NOT include
   * the context string or any domain separator. This matches the Rust
   * implementation and RFC 9591 Section 6.1.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.1-2.4.2.4
   */
  H2(m: Uint8Array): Ed25519Scalar {
    return hashToScalar([m]);
  }

  /**
   * H3 for FROST(Ed25519, SHA-512)
   *
   * H3(m) = SHA-512("FROST-ED25519-SHA512-v1" || "nonce" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.1-2.4.2.6
   */
  H3(m: Uint8Array): Ed25519Scalar {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("nonce"),
      m,
    ]);
  }

  /**
   * H4 for FROST(Ed25519, SHA-512)
   *
   * H4(m) = SHA-512("FROST-ED25519-SHA512-v1" || "msg" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.1-2.4.2.8
   */
  H4(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("msg"),
      m,
    ]);
  }

  /**
   * H5 for FROST(Ed25519, SHA-512)
   *
   * H5(m) = SHA-512("FROST-ED25519-SHA512-v1" || "com" || m)
   *
   * @see https://datatracker.ietf.org/doc/html/rfc9591#section-6.1-2.4.2.10
   */
  H5(m: Uint8Array): Uint8Array {
    return hashToArray([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("com"),
      m,
    ]);
  }

  /**
   * HDKG for FROST(Ed25519, SHA-512)
   *
   * HDKG(m) = SHA-512("FROST-ED25519-SHA512-v1" || "dkg" || m)
   *
   * Used for distributed key generation.
   */
  HDKG(m: Uint8Array): Ed25519Scalar | null {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("dkg"),
      m,
    ]);
  }

  /**
   * HID for FROST(Ed25519, SHA-512)
   *
   * HID(m) = SHA-512("FROST-ED25519-SHA512-v1" || "id" || m)
   *
   * Used for deriving identifiers from arbitrary byte strings.
   */
  HID(m: Uint8Array): Ed25519Scalar | null {
    return hashToScalar([
      new TextEncoder().encode(CONTEXT_STRING),
      new TextEncoder().encode("id"),
      m,
    ]);
  }

  /**
   * hashRandomizer for RandomizedCiphersuite
   *
   * hashRandomizer(m) = SHA-512("FROST-ED25519-SHA512-v1" || "randomizer" || m)
   *
   * Used for re-randomized FROST signatures.
   */
  hashRandomizer(m: Uint8Array): Ed25519Scalar | null {
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
   * For Ed25519, this follows the FROST challenge computation
   * from RFC 9591 Section 6.1.
   */
  challenge(
    R: Ed25519Point,
    verifyingKey: VerifyingKey<Ed25519Sha512Impl>,
    message: Uint8Array,
  ): CoreChallenge<this> {
    // Build the preimage: R || verifying_key || message
    const rBytes = this.serializeElement(R);
    const pkBytes = verifyingKey.serialize();

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
    // Serialize verifying key
    const vkBytes = (verifyingKey as VerifyingKey<Ed25519Sha512Impl>).serialize();

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
      const hidingElement = commitment.hiding.toElement() as Ed25519Point;
      const bindingElement = commitment.binding.toElement() as Ed25519Point;
      const scaledBinding = this.elementMul(bindingElement, bindingFactor.toScalar() as Ed25519Scalar);
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
  ): Ed25519Scalar {
    const signerIds = [...signingPackage.signingCommitments.keys()] as { toScalar(): unknown }[];

    let numerator = this.scalarOne();
    let denominator = this.scalarOne();

    const xI = signerId.toScalar() as Ed25519Scalar;
    const x = this.scalarZero(); // x = 0 for the shared secret

    for (const id of signerIds) {
      const xJ = id.toScalar() as Ed25519Scalar;

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
 * The Ed25519Sha512 ciphersuite instance.
 * This is a singleton that should be used for all Ed25519 FROST operations.
 */
export const Ed25519Sha512: Ed25519Sha512Impl = new Ed25519Sha512Impl();

// Export the implementation class for type references
export type { Ed25519Sha512Impl };

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/** A FROST(Ed25519, SHA-512) participant identifier */
export type Ed25519Identifier = Identifier<Ed25519Sha512Impl>;

/** An error from FROST(Ed25519, SHA-512) operations */
export type Ed25519Error = ReturnType<typeof FrostError.invalidMinSigners>;

/** A FROST(Ed25519, SHA-512) signing package */
export type Ed25519SigningPackage = SigningPackage<Ed25519Sha512Impl>;

/** A FROST(Ed25519, SHA-512) signature */
export type Ed25519Signature = Signature<Ed25519Sha512Impl>;

/** A FROST(Ed25519, SHA-512) signing key */
export type Ed25519SigningKey = SigningKey<Ed25519Sha512Impl>;

/** A FROST(Ed25519, SHA-512) verifying key */
export type Ed25519VerifyingKey = VerifyingKey<Ed25519Sha512Impl>;

/** Cheater detection mode for aggregation */
export enum CheaterDetection {
  /** No cheater detection, faster but less secure */
  None = "none",
  /** Full cheater detection, identifies malicious signers */
  Full = "full",
}

// ---------------------------------------------------------------------------
// Re-exports from @frost/core for keys module
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
} from "@frost/core";

export type { IdentifierList } from "@frost/core";

// Round 1 exports
export {
  SigningNonces,
  SigningCommitments,
  NonceCommitment,
  Nonce,
  GroupCommitmentShare,
  commit,
  preprocess,
} from "@frost/core";

// Round 2 exports
export { SignatureShare, sign, computeSignatureShare } from "@frost/core";

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
} from "@frost/core";

/** Comprised of FROST(Ed25519, SHA-512) hiding and binding nonces */
export type Ed25519SigningNonces = CoreSigningNonces<Ed25519Sha512Impl>;

/** Published by each participant in the first round of the signing protocol */
export type Ed25519SigningCommitments = CoreSigningCommitments<Ed25519Sha512Impl>;

/** A commitment to a signing nonce share */
export type Ed25519NonceCommitment = CoreNonceCommitment<Ed25519Sha512Impl>;

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
  secret: CoreSigningShare<Ed25519Sha512Impl>,
  rng: RandomSource,
): [Ed25519SigningNonces, Ed25519SigningCommitments] {
  return coreCommit(Ed25519Sha512, secret, rng);
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
} from "@frost/core";

/** A FROST(Ed25519, SHA-512) participant's signature share */
export type Ed25519SignatureShare = CoreSignatureShare<Ed25519Sha512Impl>;

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
  signingPackage: Ed25519SigningPackage,
  signerNonces: CoreSigningNonces<Ed25519Sha512Impl>,
  keyPackage: CoreKeyPackage<Ed25519Sha512Impl>,
): Ed25519SignatureShare {
  return coreSign(Ed25519Sha512, signingPackage, signerNonces, keyPackage);
}

// ---------------------------------------------------------------------------
// Top-level Functions
// ---------------------------------------------------------------------------

/**
 * Verifies each FROST(Ed25519, SHA-512) participant's signature share, and if all are valid,
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
  signingPackage: Ed25519SigningPackage,
  signatureShares: Map<Ed25519Identifier, CoreSignatureShare<Ed25519Sha512Impl>>,
  pubkeys: CorePublicKeyPackage<Ed25519Sha512Impl>,
): Ed25519Signature {
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
  signingPackage: Ed25519SigningPackage,
  signatureShares: Map<Ed25519Identifier, CoreSignatureShare<Ed25519Sha512Impl>>,
  pubkeys: CorePublicKeyPackage<Ed25519Sha512Impl>,
  cheaterDetection: CheaterDetection,
): Ed25519Signature {
  return aggregateImpl(signingPackage, signatureShares, pubkeys, cheaterDetection === CheaterDetection.Full);
}

/**
 * Internal aggregate implementation.
 */
function aggregateImpl(
  signingPackage: Ed25519SigningPackage,
  signatureShares: Map<Ed25519Identifier, CoreSignatureShare<Ed25519Sha512Impl>>,
  pubkeys: CorePublicKeyPackage<Ed25519Sha512Impl>,
  verifySigShares: boolean,
): Ed25519Signature {
  // Get the verifying key
  const verifyingKey = VerifyingKey.create(Ed25519Sha512, pubkeys.verifyingKey);

  // Compute the binding factor list
  const bindingFactorList = Ed25519Sha512.computeBindingFactorList(
    signingPackage,
    verifyingKey,
    new Uint8Array(0),
  );

  // Compute the group commitment
  const groupCommitment = Ed25519Sha512.computeGroupCommitment(
    signingPackage,
    bindingFactorList,
  );

  // Compute the challenge
  const challenge = Ed25519Sha512.challenge(
    groupCommitment.toElement(),
    verifyingKey,
    signingPackage.message,
  );

  // Aggregate the signature shares
  let z = Ed25519Sha512.scalarZero();

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
      const scaledBinding = Ed25519Sha512.elementMul(bindingElement, bindingFactor.toScalar());
      const commitmentShare = Ed25519Sha512.elementAdd(hidingElement, scaledBinding);

      // Compute lambda_i (Lagrange coefficient)
      const lambdaI = Ed25519Sha512.deriveInterpolatingValue(identifier, signingPackage);

      // Verify: z_i * G = R_i + (c * lambda_i) * Y_i
      const shareScalar = share.toScalar();
      const lhs = Ed25519Sha512.scalarBaseMult(shareScalar);

      const challengeTimesLambda = Ed25519Sha512.scalarMul(
        challenge.toScalar(),
        lambdaI,
      );
      const verifyingElement = verifyingShare.toElement();
      const scaledVerifyingShare = Ed25519Sha512.elementMul(verifyingElement, challengeTimesLambda);
      const rhs = Ed25519Sha512.elementAdd(commitmentShare, scaledVerifyingShare);

      if (!Ed25519Sha512.elementsEqual(lhs, rhs)) {
        throw new Error(`Invalid signature share from participant ${identifier.toString()}`);
      }
    }

    // Add to aggregate
    z = Ed25519Sha512.scalarAdd(z, share.toScalar());
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
