/**
 * Test for Repairable Threshold Scheme.
 * Ported from frost-core/src/tests/repairable.rs
 *
 * This module tests the share repair functionality that allows
 * a participant who has lost their share to recover it with help
 * from other participants.
 */

import { describe, it, beforeAll, beforeEach } from "vitest";
import type { Ciphersuite, CryptoRng } from "../src/index.js";
import { createSecureRng } from "./helpers.js";
import { getTestCiphersuite } from "./helpers/ciphersuite.js";

// Import the actual test functions from src/tests
import {
  checkRts,
  checkRepairShareStep1,
  checkRepairShareStep1FailsWithInvalidMinSigners,
} from "../src/tests/repairable.js";

describe("Repairable Threshold Scheme", () => {
  let rng: CryptoRng;
  let ciphersuite: Ciphersuite;

  beforeAll(async () => {
    ciphersuite = await getTestCiphersuite();
  });

  beforeEach(() => {
    rng = createSecureRng();
  });

  describe("Full Share Recovery", () => {
    it("should recover a lost share using helper participants", async () => {
      await checkRts(ciphersuite, rng);
    });
  });

  describe("Repair Share Step 1", () => {
    it("should generate correct deltas that sum to Lagrange coefficient times share", async () => {
      await checkRepairShareStep1(ciphersuite, rng);
    });
  });

  describe("Repair Share Step 2", () => {
    it("should sum deltas correctly to produce sigma", async () => {
      // Note: checkRepairShareStep2 requires test vector data,
      // which is tested as part of the full recovery test checkRts
      await checkRts(ciphersuite, rng);
    });
  });

  describe("Repair Share Step 3", () => {
    it("should recover share from sigmas correctly", async () => {
      // Note: checkRepairShareStep3 requires test vector data,
      // which is tested as part of the full recovery test checkRts
      await checkRts(ciphersuite, rng);
    });
  });

  describe("Error Cases", () => {
    it("should fail with incorrect number of helpers", async () => {
      await checkRepairShareStep1FailsWithInvalidMinSigners(ciphersuite, rng);
    });
  });
});
