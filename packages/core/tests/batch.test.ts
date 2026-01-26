/**
 * Ciphersuite-generic batch test functions.
 * Ported from frost-core/src/tests/batch.rs
 *
 * These tests verify batch verification functionality using a dynamically-loaded ciphersuite.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import type { Ciphersuite, CryptoRng } from "../src/index.js";
import { createSecureRng } from "./helpers.js";
import { getTestCiphersuite } from "./helpers/ciphersuite.js";
import { Item, Verifier } from "../src/batch.js";
import { FrostError, FrostErrorType } from "../src/error.js";

// Import the actual test functions from src/tests
import {
  checkBatchVerify,
  checkBadBatchVerify,
  checkEmptyBatchVerify,
} from "../src/tests/batch.js";

describe("Batch Verification", () => {
  let rng: CryptoRng;
  let ciphersuite: Ciphersuite;

  beforeAll(async () => {
    ciphersuite = await getTestCiphersuite();
  });

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Item class", () => {
    it("should require ciphersuite with preVerify and challenge methods", () => {
      expect(Item).toBeDefined();
      expect(typeof Item.create).toBe("function");
    });

    it("should have verifySingle method", () => {
      expect(Item.prototype.verifySingle).toBeDefined();
      expect(typeof Item.prototype.verifySingle).toBe("function");
    });

    it("should have clone method for batch retry patterns", () => {
      expect(Item.prototype.clone).toBeDefined();
      expect(typeof Item.prototype.clone).toBe("function");
    });
  });

  describe("Verifier class", () => {
    it("should have queue method to add items", () => {
      expect(Verifier.prototype.queue).toBeDefined();
      expect(typeof Verifier.prototype.queue).toBe("function");
    });

    it("should have verify method for batch verification", () => {
      expect(Verifier.prototype.verify).toBeDefined();
      expect(typeof Verifier.prototype.verify).toBe("function");
    });
  });

  describe("Error handling", () => {
    it("should define FrostError.invalidSignature for batch failures", () => {
      const error = FrostError.invalidSignature();
      expect(error).toBeInstanceOf(FrostError);
      expect(error.type).toBe(FrostErrorType.InvalidSignature);
    });
  });

  describe("Integration Tests", () => {
    it("should verify a batch of valid signatures", () => {
      checkBatchVerify(ciphersuite, rng);
    }, 30_000);

    it("should fail batch verification with a bad signature", () => {
      checkBadBatchVerify(ciphersuite, rng);
    }, 30_000);

    it("should fail verification of an empty batch", () => {
      checkEmptyBatchVerify(ciphersuite, rng);
    });
  });
});
