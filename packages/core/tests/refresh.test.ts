/**
 * Test for Refreshing shares.
 * Ported from frost-core/src/tests/refresh.rs
 *
 * This module tests share refresh functionality that allows participants
 * to update their shares while maintaining the same group public key.
 */

import { describe, it, beforeAll, beforeEach } from "vitest";
import type { Ciphersuite, CryptoRng } from "../src/index.js";
import { createSecureRng } from "./helpers.js";
import { getTestCiphersuite } from "./helpers/ciphersuite.js";

// Import the actual test functions from src/tests
import {
  checkRefreshSharesWithDealer,
  checkRefreshSharesWithDealerSerialisation,
  checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage,
  checkRefreshSharesWithDkg,
  checkRefreshSharesWithDkgSmallerThreshold,
} from "../src/tests/refresh.js";

describe("Share Refresh", () => {
  let rng: CryptoRng;
  let ciphersuite: Ciphersuite;

  beforeAll(async () => {
    ciphersuite = await getTestCiphersuite();
  });

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Refresh with Trusted Dealer", () => {
    it("should refresh shares and maintain valid signing", async () => {
      await checkRefreshSharesWithDealer(ciphersuite, rng);
    });

    it("should serialize and deserialize refresh data correctly", async () => {
      await checkRefreshSharesWithDealerSerialisation(ciphersuite, rng);
    });
  });

  describe("Refresh with DKG", () => {
    it("should complete refresh flow using DKG protocol", async () => {
      await checkRefreshSharesWithDkg(ciphersuite, rng);
    });

    it("should fail when using smaller threshold than original", async () => {
      await checkRefreshSharesWithDkgSmallerThreshold(ciphersuite, rng);
    });
  });

  describe("Error Cases", () => {
    it("should fail with unknown identifier", async () => {
      await checkRefreshSharesWithDealerFailsWithInvalidPublicKeyPackage(ciphersuite, rng);
    });
  });
});
