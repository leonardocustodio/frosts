/**
 * Serialization support.
 *
 * This module provides serialization and deserialization utilities for FROST types,
 * including scalars, elements, and ciphersuite identifiers.
 *
 * @module serialization
 */

import type { Ciphersuite, Element, Scalar } from "./types";
import { FrostError } from "./error";

/**
 * Helper class to serialize a Scalar.
 */
export class SerializableScalar<C extends Ciphersuite> {
  readonly value: Scalar<C>;
  private readonly ciphersuite: C;

  constructor(ciphersuite: C, value: Scalar<C>) {
    this.ciphersuite = ciphersuite;
    this.value = value;
  }

  /**
   * Serialize a Scalar to bytes.
   */
  serialize(): Uint8Array {
    return this.ciphersuite.group.field.serialize(this.value);
  }

  /**
   * Deserialize a Scalar from a serialized buffer.
   *
   * @param ciphersuite - The ciphersuite providing deserialization
   * @param bytes - The bytes to deserialize
   * @returns A new SerializableScalar
   * @throws FieldError if deserialization fails
   */
  static deserialize<C extends Ciphersuite>(
    ciphersuite: C,
    bytes: Uint8Array,
  ): SerializableScalar<C> {
    const scalar = ciphersuite.group.field.deserialize(bytes);
    return new SerializableScalar(ciphersuite, scalar);
  }

  /**
   * Zeroize the scalar value by replacing it with zero.
   * Note: In TypeScript, we can't truly zeroize memory, but we return a new zeroed instance.
   */
  zeroize(): SerializableScalar<C> {
    return new SerializableScalar(this.ciphersuite, this.ciphersuite.group.field.zero());
  }

  /**
   * Clone this SerializableScalar.
   */
  clone(): SerializableScalar<C> {
    return new SerializableScalar(this.ciphersuite, this.value);
  }

  /**
   * Check equality with another SerializableScalar.
   */
  equals(other: SerializableScalar<C>): boolean {
    return this.ciphersuite.group.field.eq(this.value, other.value);
  }
}

/**
 * Helper class to serialize an Element.
 */
export class SerializableElement<C extends Ciphersuite> {
  readonly value: Element<C>;
  private readonly ciphersuite: C;

  constructor(ciphersuite: C, value: Element<C>) {
    this.ciphersuite = ciphersuite;
    this.value = value;
  }

  /**
   * Serialize an Element. Throws an error if it's the identity.
   */
  serialize(): Uint8Array {
    return this.ciphersuite.group.serialize(this.value);
  }

  /**
   * Deserialize an Element. Throws an error if it's malformed or is the identity.
   *
   * @param ciphersuite - The ciphersuite providing deserialization
   * @param bytes - The bytes to deserialize
   * @returns A new SerializableElement
   * @throws GroupError if deserialization fails
   */
  static deserialize<C extends Ciphersuite>(
    ciphersuite: C,
    bytes: Uint8Array,
  ): SerializableElement<C> {
    const element = ciphersuite.group.deserialize(bytes);
    return new SerializableElement(ciphersuite, element);
  }

  /**
   * Clone this SerializableElement.
   */
  clone(): SerializableElement<C> {
    return new SerializableElement(this.ciphersuite, this.value);
  }

  /**
   * Check equality with another SerializableElement.
   */
  equals(other: SerializableElement<C>): boolean {
    return this.ciphersuite.group.eq(this.value, other.value);
  }
}

/**
 * Compute the short 4-byte ID derived as the CRC-32 of the UTF-8
 * encoded ID in big endian format.
 */
export function shortId<C extends Ciphersuite>(ciphersuite: C): Uint8Array {
  const crc = crc32(new TextEncoder().encode(ciphersuite.ID));
  const result = new Uint8Array(4);
  result[0] = (crc >>> 24) & 0xff;
  result[1] = (crc >>> 16) & 0xff;
  result[2] = (crc >>> 8) & 0xff;
  result[3] = crc & 0xff;
  return result;
}

/**
 * CRC-32 implementation (IEEE 802.3 polynomial).
 */
function crc32(data: Uint8Array): number {
  const polynomial = 0xedb88320;
  let crc = 0xffffffff;

  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      if ((crc & 1) !== 0) {
        crc = (crc >>> 1) ^ polynomial;
      } else {
        crc >>>= 1;
      }
    }
  }

  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Serialize a ciphersuite identifier.
 * For human-readable format, returns the ID string.
 * For binary format, returns the short 4-byte CRC-32.
 *
 * @param ciphersuite - The ciphersuite to serialize
 * @param humanReadable - Whether to use human-readable format
 * @returns The serialized ciphersuite identifier
 */
export function serializeCiphersuite<C extends Ciphersuite>(
  ciphersuite: C,
  humanReadable: boolean,
): Uint8Array | string {
  if (humanReadable) {
    return ciphersuite.ID;
  } else {
    return shortId(ciphersuite);
  }
}

/**
 * Deserialize and validate a ciphersuite identifier.
 *
 * @param ciphersuite - The expected ciphersuite
 * @param data - The data to deserialize (string for human-readable, Uint8Array for binary)
 * @param humanReadable - Whether data is in human-readable format
 * @throws FrostError if the ciphersuite doesn't match
 */
export function deserializeCiphersuite<C extends Ciphersuite>(
  ciphersuite: C,
  data: Uint8Array | string,
  humanReadable: boolean,
): void {
  if (humanReadable) {
    if (typeof data !== "string") {
      throw FrostError.deserializationError();
    }
    if (data !== ciphersuite.ID) {
      throw FrostError.deserializationError();
    }
  } else {
    if (!(data instanceof Uint8Array)) {
      throw FrostError.deserializationError();
    }
    const expected = shortId(ciphersuite);
    if (data.length !== 4) {
      throw FrostError.deserializationError();
    }
    for (let i = 0; i < 4; i++) {
      if (data[i] !== expected[i]) {
        throw FrostError.deserializationError();
      }
    }
  }
}

/**
 * Deserialize a version. For now, since there is a single version 0,
 * simply validate if it's 0.
 *
 * @param version - The version byte to validate
 * @throws FrostError if the version is not 0
 */
export function deserializeVersion(version: number): number {
  if (version !== 0) {
    throw FrostError.deserializationError();
  }
  return version;
}

/**
 * Header for serialized FROST structures.
 */
export interface Header<C extends Ciphersuite> {
  /** Format version (currently only 0 is supported) */
  version: number;
  /** Ciphersuite identifier (placeholder for the actual ciphersuite) */
  ciphersuite: C;
}

/**
 * Create a default header for a ciphersuite.
 */
export function defaultHeader<C extends Ciphersuite>(ciphersuite: C): Header<C> {
  return {
    version: 0,
    ciphersuite,
  };
}

/**
 * Serialize a header to bytes.
 *
 * @param header - The header to serialize
 * @param humanReadable - Whether to use human-readable format
 * @returns The serialized header
 */
export function serializeHeader<C extends Ciphersuite>(
  header: Header<C>,
  humanReadable: boolean,
): Uint8Array {
  const ciphersuiteData = serializeCiphersuite(header.ciphersuite, humanReadable);

  if (humanReadable) {
    // For human-readable: version byte + ciphersuite string length + ciphersuite string
    const ciphersuiteBytes = new TextEncoder().encode(ciphersuiteData as string);
    const result = new Uint8Array(1 + 4 + ciphersuiteBytes.length);
    result[0] = header.version;
    // Length as 4-byte big-endian
    const len = ciphersuiteBytes.length;
    result[1] = (len >>> 24) & 0xff;
    result[2] = (len >>> 16) & 0xff;
    result[3] = (len >>> 8) & 0xff;
    result[4] = len & 0xff;
    result.set(ciphersuiteBytes, 5);
    return result;
  } else {
    // For binary: version byte + 4-byte CRC-32
    const result = new Uint8Array(5);
    result[0] = header.version;
    result.set(ciphersuiteData as Uint8Array, 1);
    return result;
  }
}

/**
 * Deserialize a header from bytes.
 *
 * @param ciphersuite - The expected ciphersuite
 * @param bytes - The bytes to deserialize
 * @param humanReadable - Whether data is in human-readable format
 * @returns A tuple of [header, remainingBytes]
 * @throws FrostError if deserialization fails
 */
export function deserializeHeader<C extends Ciphersuite>(
  ciphersuite: C,
  bytes: Uint8Array,
  humanReadable: boolean,
): [Header<C>, Uint8Array] {
  if (bytes.length < 1) {
    throw FrostError.deserializationError();
  }

  const version = deserializeVersion(bytes[0]);

  if (humanReadable) {
    if (bytes.length < 5) {
      throw FrostError.deserializationError();
    }
    const len = (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
    if (bytes.length < 5 + len) {
      throw FrostError.deserializationError();
    }
    const ciphersuiteStr = new TextDecoder().decode(bytes.slice(5, 5 + len));
    deserializeCiphersuite(ciphersuite, ciphersuiteStr, humanReadable);
    return [{ version, ciphersuite }, bytes.slice(5 + len)];
  } else {
    if (bytes.length < 5) {
      throw FrostError.deserializationError();
    }
    deserializeCiphersuite(ciphersuite, bytes.slice(1, 5), humanReadable);
    return [{ version, ciphersuite }, bytes.slice(5)];
  }
}

/**
 * Trait for types that can be serialized to bytes.
 */
export interface Serialize<_C extends Ciphersuite> {
  /**
   * Serialize the struct into a Uint8Array.
   */
  serialize(): Uint8Array;
}

/**
 * Trait for types that can be deserialized from bytes.
 */
export interface Deserialize<T, C extends Ciphersuite> {
  /**
   * Deserialize the struct from a slice of bytes.
   */
  deserialize(ciphersuite: C, bytes: Uint8Array): T;
}

/**
 * Encode bytes to hex string (lowercase).
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decode hex string to bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw FrostError.deserializationError();
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(hex.substr(i * 2, 2), 16);
    if (isNaN(byte)) {
      throw FrostError.deserializationError();
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Concatenate multiple Uint8Arrays into one.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Encode a variable-length integer (varint) for compact serialization.
 * Uses a simple length-prefixed encoding.
 */
export function encodeVarint(value: number): Uint8Array {
  if (value < 0) {
    throw FrostError.serializationError();
  }
  if (value < 0x80) {
    return new Uint8Array([value]);
  } else if (value < 0x4000) {
    return new Uint8Array([0x80 | (value & 0x7f), value >>> 7]);
  } else if (value < 0x200000) {
    return new Uint8Array([0x80 | (value & 0x7f), 0x80 | ((value >>> 7) & 0x7f), value >>> 14]);
  } else if (value < 0x10000000) {
    return new Uint8Array([
      0x80 | (value & 0x7f),
      0x80 | ((value >>> 7) & 0x7f),
      0x80 | ((value >>> 14) & 0x7f),
      value >>> 21,
    ]);
  } else {
    return new Uint8Array([
      0x80 | (value & 0x7f),
      0x80 | ((value >>> 7) & 0x7f),
      0x80 | ((value >>> 14) & 0x7f),
      0x80 | ((value >>> 21) & 0x7f),
      value >>> 28,
    ]);
  }
}

/**
 * Decode a variable-length integer (varint).
 * Returns [value, bytesConsumed].
 */
export function decodeVarint(bytes: Uint8Array): [number, number] {
  let value = 0;
  let shift = 0;
  let bytesConsumed = 0;

  for (let i = 0; i < bytes.length && i < 5; i++) {
    const byte = bytes[i];
    bytesConsumed++;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return [value, bytesConsumed];
    }
    shift += 7;
  }

  throw FrostError.deserializationError();
}

/**
 * Encode a length-prefixed byte array.
 */
export function encodeLengthPrefixed(data: Uint8Array): Uint8Array {
  const lengthBytes = encodeVarint(data.length);
  return concatBytes(lengthBytes, data);
}

/**
 * Decode a length-prefixed byte array.
 * Returns [data, bytesConsumed].
 */
export function decodeLengthPrefixed(bytes: Uint8Array): [Uint8Array, number] {
  const [length, lengthBytesConsumed] = decodeVarint(bytes);
  const totalBytesConsumed = lengthBytesConsumed + length;

  if (bytes.length < totalBytesConsumed) {
    throw FrostError.deserializationError();
  }

  return [bytes.slice(lengthBytesConsumed, totalBytesConsumed), totalBytesConsumed];
}

/**
 * Encode a 16-bit unsigned integer in big-endian format.
 */
export function encodeU16BE(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

/**
 * Decode a 16-bit unsigned integer from big-endian format.
 */
export function decodeU16BE(bytes: Uint8Array): number {
  if (bytes.length < 2) {
    throw FrostError.deserializationError();
  }
  return (bytes[0] << 8) | bytes[1];
}

/**
 * Encode a 32-bit unsigned integer in big-endian format.
 */
export function encodeU32BE(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

/**
 * Decode a 32-bit unsigned integer from big-endian format.
 */
export function decodeU32BE(bytes: Uint8Array): number {
  if (bytes.length < 4) {
    throw FrostError.deserializationError();
  }
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
}

/**
 * Encode a 64-bit unsigned integer in big-endian format.
 */
export function encodeU64BE(value: bigint): Uint8Array {
  const result = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    result[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return result;
}

/**
 * Decode a 64-bit unsigned integer from big-endian format.
 */
export function decodeU64BE(bytes: Uint8Array): bigint {
  if (bytes.length < 8) {
    throw FrostError.deserializationError();
  }
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

export const Serialization = {
  SerializableScalar,
  SerializableElement,
  shortId,
  serializeCiphersuite,
  deserializeCiphersuite,
  deserializeVersion,
  defaultHeader,
  serializeHeader,
  deserializeHeader,
  bytesToHex,
  hexToBytes,
  concatBytes,
  encodeVarint,
  decodeVarint,
  encodeLengthPrefixed,
  decodeLengthPrefixed,
  encodeU16BE,
  decodeU16BE,
  encodeU32BE,
  decodeU32BE,
  encodeU64BE,
  decodeU64BE,
};
