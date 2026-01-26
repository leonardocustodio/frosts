/**
 * Non-adjacent form (NAF) implementations for fast batch scalar multiplication.
 *
 * This module provides variable-time multiscalar multiplication using the
 * Non-Adjacent Form (NAF) representation of scalars. This is used internally
 * for batch signature verification.
 *
 * @module scalar_mul
 */

import type { Ciphersuite, Element, Scalar } from "./types";

/**
 * A trait for transforming a scalar generic over a ciphersuite to a non-adjacent form (NAF).
 */
export interface NonAdjacentForm<_C extends Ciphersuite> {
  /**
   * Computes a width-(w) "Non-Adjacent Form" of this scalar.
   *
   * Thanks to curve25519-dalek for the original implementation that informed this one.
   *
   * # Safety
   *
   * The full scalar field MUST fit in 256 bits in this implementation.
   *
   * @param w - The window width (must be >= 2 and <= 8)
   * @returns The NAF representation as an array of signed bytes
   */
  nonAdjacentForm(w: number): Int8Array;
}

/**
 * Computes a width-(w) "Non-Adjacent Form" of a scalar.
 *
 * Thanks to curve25519-dalek for the original implementation that informed this one.
 *
 * # Safety
 *
 * The full scalar field MUST fit in 256 bits in this implementation.
 *
 * @param ciphersuite - The ciphersuite providing field operations
 * @param scalar - The scalar to convert
 * @param w - The window width (must be >= 2 and <= 8)
 * @returns The NAF representation as an array of signed bytes
 */
export function computeNonAdjacentForm<C extends Ciphersuite>(
  ciphersuite: C,
  scalar: Scalar<C>,
  w: number,
): Int8Array {
  // required by the NAF definition
  if (w < 2) {
    throw new Error("NAF window width must be >= 2");
  }
  // required so that the NAF digits fit in i8
  if (w > 8) {
    throw new Error("NAF window width must be <= 8");
  }

  const serializedScalar = ciphersuite.group.field.littleEndianSerialize(scalar);
  // The canonical serialization length of this Scalar in bytes
  const serializationLen = serializedScalar.length;

  // Compute the size of the non-adjacent form from the number of bytes needed to serialize
  // Scalars, plus 1 bit.
  //
  // The length of the NAF is at most one more than the bit length.
  const nafLength = serializationLen * 8 + 1;

  const naf = new Int8Array(nafLength);

  // Get the number of 64-bit limbs we need (using BigInt for 64-bit arithmetic)
  const numLimbs = Math.ceil(nafLength / 64);

  // Convert serialized bytes to 64-bit limbs (little-endian)
  const x_u64: bigint[] = Array.from({ length: numLimbs }, () => 0n);

  // Pad the serialized scalar to numLimbs * 8 bytes
  const paddedLeSerialized = new Uint8Array(numLimbs * 8);
  paddedLeSerialized.set(serializedScalar);

  // Read as 64-bit little-endian values
  for (let i = 0; i < numLimbs; i++) {
    let value = 0n;
    for (let j = 0; j < 8; j++) {
      value |= BigInt(paddedLeSerialized[i * 8 + j]) << BigInt(j * 8);
    }
    x_u64[i] = value;
  }

  const width = 1 << w;
  const windowMask = BigInt(width - 1);

  let pos = 0;
  let carry = 0n;

  while (pos < nafLength) {
    // Construct a buffer of bits of the scalar, starting at bit `pos`
    const u64Idx = Math.floor(pos / 64);
    const bitIdx = pos % 64;

    let bitBuf: bigint;
    if (bitIdx < 64 - w) {
      // This window's bits are contained in a single u64
      bitBuf = x_u64[u64Idx] >> BigInt(bitIdx);
    } else {
      // Combine the current u64's bits with the bits from the next u64
      bitBuf =
        (x_u64[u64Idx] >> BigInt(bitIdx)) |
        ((u64Idx + 1 < numLimbs ? x_u64[u64Idx + 1] : 0n) << BigInt(64 - bitIdx));
    }

    // Add the carry into the current window
    const window = carry + (bitBuf & windowMask);

    if ((window & 1n) === 0n) {
      // If the window value is even, preserve the carry and continue.
      // Why is the carry preserved?
      // If carry == 0 and window & 1 == 0, then the next carry should be 0
      // If carry == 1 and window & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
      pos += 1;
      continue;
    }

    if (window < BigInt(width / 2)) {
      carry = 0n;
      naf[pos] = Number(window);
    } else {
      carry = 1n;
      // Equivalent to (window as i8).wrapping_sub(width as i8)
      naf[pos] = Number(window) - width;
    }

    pos += w;
  }

  return naf;
}

/**
 * Holds odd multiples 1A, 3A, ..., 15A of a point A.
 */
export class LookupTable5<C extends Ciphersuite> {
  private readonly bytes: Element<C>[];

  constructor(bytes: Element<C>[]) {
    if (bytes.length !== 8) {
      throw new Error("LookupTable5 must have exactly 8 elements");
    }
    this.bytes = bytes;
  }

  /**
   * Given public, odd x with 0 < x < 2^4, return xA.
   */
  select(x: number): Element<C> {
    if ((x & 1) !== 1) {
      throw new Error("x must be odd");
    }
    if (x >= 16) {
      throw new Error("x must be < 16");
    }
    return this.bytes[Math.floor(x / 2)];
  }

  /**
   * Create a lookup table from a group element A.
   * The table contains [A, 3A, 5A, 7A, 9A, 11A, 13A, 15A].
   */
  static from<C extends Ciphersuite>(ciphersuite: C, A: Element<C>): LookupTable5<C> {
    const Ai: Element<C>[] = [];
    Ai[0] = A;
    const A2 = ciphersuite.group.add(A, A);
    for (let i = 0; i < 7; i++) {
      Ai[i + 1] = ciphersuite.group.add(A2, Ai[i]);
    }
    // Now Ai = [A, 3A, 5A, 7A, 9A, 11A, 13A, 15A]
    return new LookupTable5(Ai);
  }

  toString(): string {
    return `LookupTable5([${this.bytes.map((b) => String(b)).join(", ")}])`;
  }
}

/**
 * A trait for variable-time multiscalar multiplication without precomputation.
 *
 * Implement for a group element.
 */
export interface VartimeMultiscalarMul<C extends Ciphersuite> {
  /**
   * Given an iterator of public scalars and an iterator of
   * Options of group elements, compute either Some(Q), where
   * Q = c_1 * E_1 + ... + c_n * E_n,
   * if all points were Some(E_i), or else return undefined.
   */
  optionalMultiscalarMul(
    scalars: Scalar<C>[],
    elements: (Element<C> | undefined)[],
  ): Element<C> | undefined;

  /**
   * Given an iterator of public scalars and an iterator of
   * public group elements, compute
   * Q = c_1 * E_1 + ... + c_n * E_n,
   * using variable-time operations.
   *
   * It is an error to call this function with two iterators of different lengths.
   */
  vartimeMultiscalarMul(scalars: Scalar<C>[], elements: Element<C>[]): Element<C>;
}

/**
 * Performs variable-time multiscalar multiplication.
 *
 * Given scalars [c_1, ..., c_n] and points [E_1, ..., E_n], computes:
 * Q = c_1 * E_1 + ... + c_n * E_n
 *
 * Uses a width-5 NAF (Non-Adjacent Form) with lookup tables for efficiency.
 */
export function vartimeMultiscalarMul<C extends Ciphersuite>(
  ciphersuite: C,
  scalars: Scalar<C>[],
  elements: Element<C>[],
): Element<C> {
  const result = optionalMultiscalarMul(
    ciphersuite,
    scalars,
    elements.map((e) => e),
  );
  if (result === undefined) {
    throw new Error("all elements should be Some");
  }
  return result;
}

/**
 * Given an iterator of public scalars and an iterator of
 * Options of group elements, compute either Some(Q), where
 * Q = c_1 * E_1 + ... + c_n * E_n,
 * if all points were Some(E_i), or else return undefined.
 */
export function optionalMultiscalarMul<C extends Ciphersuite>(
  ciphersuite: C,
  scalars: Scalar<C>[],
  elements: (Element<C> | undefined)[],
): Element<C> | undefined {
  // Compute NAFs for all scalars
  const nafs = scalars.map((c) => computeNonAdjacentForm(ciphersuite, c, 5));

  // Build lookup tables for all elements
  const lookupTables: LookupTable5<C>[] = [];
  for (const P_opt of elements) {
    if (P_opt === undefined) {
      return undefined;
    }
    lookupTables.push(LookupTable5.from(ciphersuite, P_opt));
  }

  if (nafs.length !== lookupTables.length) {
    return undefined;
  }

  let r = ciphersuite.group.identity();

  // All NAFs will have the same size, so get it from the first
  if (nafs.length === 0) {
    return r;
  }
  const nafLength = nafs[0].length;

  for (let i = nafLength - 1; i >= 0; i--) {
    let t = ciphersuite.group.add(r, r);

    for (let j = 0; j < nafs.length; j++) {
      const naf = nafs[j];
      const lookupTable = lookupTables[j];

      if (naf[i] > 0) {
        t = ciphersuite.group.add(t, lookupTable.select(naf[i]));
      } else if (naf[i] < 0) {
        t = ciphersuite.group.sub(t, lookupTable.select(-naf[i]));
      }
    }

    r = t;
  }

  return r;
}

export const ScalarMul = {
  computeNonAdjacentForm,
  LookupTable5,
  vartimeMultiscalarMul,
  optionalMultiscalarMul,
};
