/**
 * Dynamic ciphersuite loader for tests.
 *
 * This module provides a way to dynamically load a ciphersuite at test time,
 * avoiding circular dependency issues at build time.
 *
 * The Ed25519 package is imported dynamically only when tests run.
 * Since tests run after all packages are built, Ed25519 will be available.
 */

import type { Ciphersuite } from "../../src/index.js";

// Cached ciphersuite instance (using any to avoid private property incompatibility between
// Ed25519Sha512Impl's Challenge<Ed25519Sha512Impl> and Ciphersuite's Challenge<Ciphersuite>)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let cachedCiphersuite: any = null;

/**
 * Get the Ed25519Sha512 ciphersuite for testing.
 * This uses dynamic import to avoid circular dependency at build time.
 *
 * @throws Error if @frosts/ed25519 is not available
 * @returns The Ed25519Sha512 ciphersuite instance
 */
export async function getTestCiphersuite(): Promise<Ciphersuite> {
  if (cachedCiphersuite !== null) {
    return cachedCiphersuite as Ciphersuite;
  }

  try {
    // Dynamic import of ed25519 - only happens at test time
    const ed25519 = await import("@frosts/ed25519");
    cachedCiphersuite = ed25519.Ed25519Sha512;
    return cachedCiphersuite as Ciphersuite;
  } catch (error) {
    throw new Error(
      "Failed to load @frosts/ed25519 for testing. " +
        "Make sure the ed25519 package is built before running core tests. " +
        `Original error: ${error}`,
    );
  }
}

/**
 * Synchronous getter that throws if ciphersuite not loaded.
 * Call getTestCiphersuite() first to initialize.
 */
export function getCachedCiphersuite(): Ciphersuite {
  if (cachedCiphersuite === null) {
    throw new Error(
      "Test ciphersuite not loaded. Call getTestCiphersuite() first in a beforeAll hook.",
    );
  }
  return cachedCiphersuite as Ciphersuite;
}

/**
 * Check if the test ciphersuite is available.
 * Useful for conditionally skipping tests.
 */
export async function isTestCiphersuiteAvailable(): Promise<boolean> {
  try {
    await getTestCiphersuite();
    return true;
  } catch {
    return false;
  }
}
