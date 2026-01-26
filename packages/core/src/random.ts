/**
 * Random number generation interfaces for FROST
 *
 * This module defines the interfaces for cryptographically secure random
 * number generation used throughout the FROST implementation.
 *
 * @module random
 */

/**
 * Interface for a cryptographically secure random number generator.
 *
 * This is analogous to Rust's `CryptoRng + RngCore` trait bounds.
 */
export interface RandomSource {
  /**
   * Fill the provided array with cryptographically secure random bytes.
   *
   * @param array - The byte array to fill with random data
   */
  fill(array: Uint8Array): void;
}

/**
 * A RandomSource implementation that uses the Web Crypto API.
 *
 * This is the recommended source for production use.
 */
export class WebCryptoRandomSource implements RandomSource {
  fill(array: Uint8Array): void {
    if (globalThis.crypto?.getRandomValues !== undefined) {
      globalThis.crypto.getRandomValues(array);
    } else {
      throw new Error("Web Crypto API not available");
    }
  }
}

/**
 * A RandomSource implementation that uses Node.js crypto module.
 *
 * This is useful for Node.js environments.
 */
export class NodeCryptoRandomSource implements RandomSource {
  private crypto: { randomFillSync: (buffer: Uint8Array) => void } | null = null;
  private readonly initPromise: Promise<void> | null = null;

  constructor() {
    // Initialize synchronously using dynamic import
    this.initPromise = this.init();
  }

  private async init(): Promise<void> {
    // Dynamic import to avoid issues in browser environments
    // @ts-expect-error - node:crypto is a built-in module but types may not be available
    const cryptoModule = (await import("node:crypto")) as {
      randomFillSync: (buffer: Uint8Array) => void;
    };
    this.crypto = cryptoModule;
  }

  fill(array: Uint8Array): void {
    if (this.crypto === null) {
      throw new Error(
        "NodeCryptoRandomSource not initialized. Use NodeCryptoRandomSource.create() instead.",
      );
    }
    this.crypto.randomFillSync(array);
  }

  /**
   * Create a NodeCryptoRandomSource asynchronously.
   * This is the recommended way to create an instance.
   */
  static async create(): Promise<NodeCryptoRandomSource> {
    const source = new NodeCryptoRandomSource();
    await source.initPromise;
    return source;
  }
}

/**
 * A seeded random source for deterministic testing.
 *
 * WARNING: This is NOT cryptographically secure and should ONLY be used for testing!
 *
 * Uses a simple xorshift128+ algorithm seeded from the provided seed.
 */
export class SeededRandomSource implements RandomSource {
  private state0: bigint;
  private state1: bigint;

  /**
   * Create a new SeededRandomSource with the given seed.
   *
   * @param seed - A 32-byte seed
   * @throws Error if the seed is not exactly 32 bytes
   */
  constructor(seed: Uint8Array) {
    if (seed.length !== 32) {
      throw new Error("Seed must be exactly 32 bytes");
    }

    // Initialize state from seed (first 8 bytes as state0, next 8 as state1)
    this.state0 = 0n;
    this.state1 = 0n;

    for (let i = 0; i < 8; i++) {
      this.state0 |= BigInt(seed[i]) << BigInt(i * 8);
      this.state1 |= BigInt(seed[8 + i]) << BigInt(i * 8);
    }

    // Ensure non-zero state
    if (this.state0 === 0n && this.state1 === 0n) {
      this.state0 = 1n;
    }
  }

  /**
   * Create a SeededRandomSource from a hex string.
   *
   * @param hex - A 64-character hex string (32 bytes)
   * @returns A new SeededRandomSource
   */
  static fromHex(hex: string): SeededRandomSource {
    if (hex.length !== 64) {
      throw new Error("Hex string must be exactly 64 characters (32 bytes)");
    }
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return new SeededRandomSource(seed);
  }

  fill(array: Uint8Array): void {
    for (let i = 0; i < array.length; i++) {
      if (i % 8 === 0) {
        this.next();
      }
      array[i] = Number((this.state0 >> BigInt((i % 8) * 8)) & 0xffn);
    }
  }

  private next(): void {
    // xorshift128+ algorithm
    const mask64 = (1n << 64n) - 1n;

    let s1 = this.state0;
    const s0 = this.state1;
    this.state0 = s0;

    s1 ^= (s1 << 23n) & mask64;
    s1 ^= s1 >> 17n;
    s1 ^= s0;
    s1 ^= s0 >> 26n;

    this.state1 = s1 & mask64;
  }
}

/**
 * Get the default RandomSource for the current environment.
 *
 * Prefers Web Crypto API, falls back to Node.js crypto.
 *
 * @returns A RandomSource appropriate for the current environment
 * @throws Error if no secure random source is available
 */
export function getDefaultRandomSource(): RandomSource {
  if (globalThis.crypto?.getRandomValues !== undefined) {
    return new WebCryptoRandomSource();
  }

  try {
    return new NodeCryptoRandomSource();
  } catch {
    throw new Error("No secure random source available");
  }
}
