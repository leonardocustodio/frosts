/**
 * Performs batch Schnorr signature verification.
 *
 * Batch verification asks whether *all* signatures in some set are valid,
 * rather than asking whether *each* of them is valid. This allows sharing
 * computations among all signature verifications, performing less work overall
 * at the cost of higher latency (the entire batch must complete), complexity
 * of caller code (which must assemble a batch of signatures across
 * work-items), and loss of the ability to easily pinpoint failing signatures.
 *
 * @module batch
 */

import type { Ciphersuite, Element, Scalar } from "./types";
import type { VerifyingKey } from "./verifying_key";
import type { Signature } from "./signature";
import type { Challenge } from "./types";
import { vartimeMultiscalarMul } from "./scalar_mul";
import { FrostError } from "./error";

/**
 * A batch verification item.
 *
 * This struct exists to allow batch processing to be decoupled from the
 * lifetime of the message. This is useful when using the batch verification
 * API in an async context.
 */
export class Item<C extends Ciphersuite> {
  readonly vk: VerifyingKey<C>;
  readonly sig: Signature<C>;
  readonly c: Challenge<C>;

  private constructor(vk: VerifyingKey<C>, sig: Signature<C>, c: Challenge<C>) {
    this.vk = vk;
    this.sig = sig;
    this.c = c;
  }

  /**
   * Create a new batch Item from a VerifyingKey, Signature
   * and a message to be verified.
   *
   * @param ciphersuite - The ciphersuite to use
   * @param vk - The verifying key
   * @param sig - The signature
   * @param msg - The message to be verified
   * @returns A new batch Item
   * @throws FrostError if pre-verification or challenge computation fails
   */
  static create<C extends Ciphersuite>(
    ciphersuite: C,
    vk: VerifyingKey<C>,
    sig: Signature<C>,
    msg: Uint8Array,
  ): Item<C> {
    // Type assertion for ciphersuite with optional preVerify method
    // preVerify is an optional method that allows pre-processing before verification
    // The default behavior is to return inputs unchanged
    type PreVerifyResult = [Uint8Array, Signature<C>, VerifyingKey<C>];
    const cs = ciphersuite as C & {
      preVerify?(msg: Uint8Array, sig: Signature<C>, vk: VerifyingKey<C>): PreVerifyResult;
      challenge(R: Element<C>, vk: VerifyingKey<C>, msg: Uint8Array): Challenge<C>;
    };

    // Use preVerify if available, otherwise use inputs unchanged (default behavior)
    let processedMsg: Uint8Array;
    let processedSig: Signature<C>;
    let processedVk: VerifyingKey<C>;

    if (cs.preVerify !== undefined) {
      [processedMsg, processedSig, processedVk] = cs.preVerify(msg, sig, vk);
    } else {
      // Default: return inputs unchanged
      processedMsg = msg;
      processedSig = sig;
      processedVk = vk;
    }

    const c = cs.challenge(processedSig.R, processedVk, processedMsg);

    return new Item(processedVk, processedSig, c);
  }

  /**
   * Perform non-batched verification of this Item.
   *
   * This is useful (in combination with cloning) for implementing
   * fallback logic when batch verification fails. In contrast to
   * VerifyingKey.verify(), which requires the message data, the Item
   * type is unlinked from the message.
   *
   * @throws FrostError if verification fails
   */
  verifySingle(): void {
    this.vk.verifyPrehashed(this.c, this.sig);
  }

  /**
   * Clone this item.
   */
  clone(): Item<C> {
    return new Item(this.vk, this.sig, this.c);
  }
}

/**
 * A batch verification context.
 */
export class Verifier<C extends Ciphersuite> {
  private readonly ciphersuite: C;
  /** Signature data queued for verification. */
  private readonly signatures: Item<C>[];

  /**
   * Constructs a new batch verifier.
   *
   * @param ciphersuite - The ciphersuite to use for verification
   */
  constructor(ciphersuite: C) {
    this.ciphersuite = ciphersuite;
    this.signatures = [];
  }

  /**
   * Queues an Item for verification.
   *
   * @param item - The item to queue for verification
   */
  queue(item: Item<C>): void {
    this.signatures.push(item);
  }

  /**
   * Performs batch verification, returning nothing if all signatures were
   * valid and throwing an error otherwise, or if the batch is empty.
   *
   * The batch verification equation is:
   *
   * h_G * -[sum(z_i * s_i)]P_G + sum([z_i]R_i + [z_i * c_i]VK_i) = 0_G
   *
   * which we split out into:
   *
   * h_G * -[sum(z_i * s_i)]P_G + sum([z_i]R_i) + sum([z_i * c_i]VK_i) = 0_G
   *
   * so that we can use multiscalar multiplication speedups.
   *
   * where for each signature i,
   * - VK_i is the verification key;
   * - R_i is the signature's R value;
   * - s_i is the signature's s value;
   * - c_i is the hash of the message and other data;
   * - z_i is a random 128-bit Scalar;
   * - h_G is the cofactor of the group;
   * - P_G is the generator of the subgroup;
   *
   * As follows elliptic curve scalar multiplication convention,
   * scalar variables are lowercase and group point variables
   * are uppercase. This does not exactly match the RedDSA
   * notation in the [protocol specification section B.1](https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify).
   *
   * @param rng - A random number generator function that returns random scalars
   * @throws FrostError if the batch is empty or if verification fails
   */
  verify(rng: () => Scalar<C>): void {
    const n = this.signatures.length;

    if (n === 0) {
      throw FrostError.invalidSignature();
    }

    const field = this.ciphersuite.group.field;
    const group = this.ciphersuite.group;

    const VK_coeffs: Scalar<C>[] = [];
    const VKs: Element<C>[] = [];
    const R_coeffs: Scalar<C>[] = [];
    const Rs: Element<C>[] = [];
    let P_coeff_acc = field.zero();

    for (const item of this.signatures) {
      const z = item.sig.z;
      const R = item.sig.R;

      const blind = rng();

      const P_coeff = field.mul(blind, z);
      P_coeff_acc = field.sub(P_coeff_acc, P_coeff);

      R_coeffs.push(blind);
      Rs.push(R);

      // VK_coeffs.push(zero + (blind * item.c.0))
      const vkCoeff = field.mul(blind, item.c.toScalar());
      VK_coeffs.push(vkCoeff);
      VKs.push(item.vk.toElement());
    }

    // Collect all scalars: [P_coeff_acc, ...VK_coeffs, ...R_coeffs]
    const scalars: Scalar<C>[] = [P_coeff_acc, ...VK_coeffs, ...R_coeffs];

    // Collect all points: [generator, ...VKs, ...Rs]
    const points: Element<C>[] = [group.generator(), ...VKs, ...Rs];

    // Perform the multiscalar multiplication
    const check = vartimeMultiscalarMul(this.ciphersuite, scalars, points);

    // Multiply by cofactor and check if result is identity
    const cofactor = group.cofactor();
    const result = group.scalarMul(check, cofactor);

    if (!group.eq(result, group.identity())) {
      throw FrostError.invalidSignature();
    }
  }
}

export const Batch = {
  Item,
  Verifier,
};
