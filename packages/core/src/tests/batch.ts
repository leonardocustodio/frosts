/**
 * Ciphersuite-generic batch verification test functions.
 *
 * These are generic test functions that can be used by ciphersuite-specific
 * packages to test their batch verification implementations. The pattern
 * follows Rust's frost-core `test-impl` feature.
 *
 * Ported from frost-core/src/tests/batch.rs
 *
 * @module @frosts/core/tests/batch
 */

import type { Ciphersuite, CryptoRng, Scalar } from "../types.js";
import { SigningKey } from "../signing_key.js";
import { VerifyingKey } from "../verifying_key.js";
import { Item, Verifier } from "../batch.js";
import { FrostError, FrostErrorType } from "../error.js";

/**
 * Test batch verification with a Ciphersuite.
 *
 * Creates a signature and verifies it both individually and in a batch.
 * This ensures batch verification produces the same result as individual verification.
 *
 * Ported from: frost-core/src/tests/batch.rs batch_verify
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export function checkBatchVerify<C extends Ciphersuite>(ciphersuite: C, rng: CryptoRng): void {
  const batch = new Verifier(ciphersuite);

  // Generate a signing key and derive the verifying key
  const sk = SigningKey.generate(ciphersuite, rng);
  const vk = VerifyingKey.fromSigningKey(ciphersuite, sk);

  // Sign a message
  const msg = new TextEncoder().encode("BatchVerifyTest");
  const sig = sk.sign(rng, msg);

  // Verify the signature individually first
  vk.verify(msg, sig);

  // Queue the item for batch verification
  const item = Item.create(ciphersuite, vk, sig, msg);
  batch.queue(item);

  // Create RNG function that generates random scalars for blinding
  const rngFn = (): Scalar<C> => ciphersuite.group.field.random(rng);

  // Verify the batch - should not throw
  batch.verify(rngFn);
}

/**
 * Test failure case of batch verification with a Ciphersuite.
 *
 * Creates 32 signatures where one (at index 4) is invalid (signed with wrong message).
 * Batch verification should fail, and individual verification should identify
 * the bad signature.
 *
 * Ported from: frost-core/src/tests/batch.rs bad_batch_verify
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export function checkBadBatchVerify<C extends Ciphersuite>(ciphersuite: C, rng: CryptoRng): void {
  const badIndex = 4; // must be even (matching Rust test)
  const batch = new Verifier(ciphersuite);
  const items: Item<C>[] = [];

  for (let i = 0; i < 32; i++) {
    let item: Item<C>;

    if (i % 2 === 0) {
      // Even indices: create signatures
      // At badIndex, sign with wrong message to create invalid signature
      const sk = SigningKey.generate(ciphersuite, rng);
      const vk = VerifyingKey.fromSigningKey(ciphersuite, sk);
      const msg = new TextEncoder().encode("BatchVerifyTest");

      let sig;
      if (i !== badIndex) {
        sig = sk.sign(rng, msg);
      } else {
        // Sign wrong message to create invalid signature
        sig = sk.sign(rng, new TextEncoder().encode("bad"));
      }

      item = Item.create(ciphersuite, vk, sig, msg);
    } else {
      // Odd indices: create valid signatures
      const sk = SigningKey.generate(ciphersuite, rng);
      const vk = VerifyingKey.fromSigningKey(ciphersuite, sk);
      const msg = new TextEncoder().encode("BatchVerifyTest");
      const sig = sk.sign(rng, msg);

      item = Item.create(ciphersuite, vk, sig, msg);
    }

    items.push(item.clone());
    batch.queue(item);
  }

  // Create RNG function for batch verification
  const rngFn = (): Scalar<C> => ciphersuite.group.field.random(rng);

  // Batch verification should fail due to the bad signature
  let batchFailed = false;
  try {
    batch.verify(rngFn);
  } catch (error) {
    if (error instanceof FrostError && error.type === FrostErrorType.InvalidSignature) {
      batchFailed = true;
    } else {
      throw error;
    }
  }

  if (!batchFailed) {
    throw new Error("Batch verification should have failed due to invalid signature");
  }

  // Verify individual items - only the bad one should fail
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (i !== badIndex) {
      // Should succeed
      item.verifySingle();
    } else {
      // Should fail
      let singleFailed = false;
      try {
        item.verifySingle();
      } catch (error) {
        if (error instanceof FrostError && error.type === FrostErrorType.InvalidSignature) {
          singleFailed = true;
        } else {
          throw error;
        }
      }

      if (!singleFailed) {
        throw new Error(`Individual verification of item ${i} should have failed`);
      }
    }
  }
}

/**
 * Test that an empty batch fails to validate.
 *
 * This is a test case from the NCC audit - an empty batch should not
 * trivially pass verification.
 *
 * Ported from: frost-core/src/tests/batch.rs empty_batch_verify
 *
 * @param ciphersuite - The ciphersuite to test
 * @param rng - A cryptographically secure random number generator
 */
export function checkEmptyBatchVerify<C extends Ciphersuite>(ciphersuite: C, rng: CryptoRng): void {
  const batch = new Verifier(ciphersuite);

  // Create RNG function for batch verification
  const rngFn = (): Scalar<C> => ciphersuite.group.field.random(rng);

  // Empty batch should fail
  let emptyFailed = false;
  try {
    batch.verify(rngFn);
  } catch (error) {
    if (error instanceof FrostError && error.type === FrostErrorType.InvalidSignature) {
      emptyFailed = true;
    } else {
      throw error;
    }
  }

  if (!emptyFailed) {
    throw new Error("Empty batch verification should have failed");
  }
}
