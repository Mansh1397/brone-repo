// ==========================================
// ENVIRONMENT ISOLATION GUARD HOOK
// Intercept module loading to prevent Jest from choking on raw React Native Flow types
const Module = require("module");
const originalRequire = Module.prototype.require;
Module.prototype.require = function (id: string) {
  if (id === "react-native") {
    return {
      NativeModules: {
        ExpoSecureStore: {
          setItemAsync: async () => {},
          getItemAsync: async () => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          deleteItemAsync: async () => {}
        }
      }
    };
  }
  return originalRequire.apply(this, arguments);
};
// ==========================================
// Virtually mock react-native to prevent missing module or syntax errors in Node Jest environment
jest.mock(
  "react-native",
  () => ({
    NativeModules: {
      ExpoSecureStore: {}
    }
  }),
  { virtual: true }
);

import { secureWalletManager } from "../secureWallet";
import { unblindSignedVoucher, verifyUnblindedVoucher, localPublicKeyRegistry } from "../voucherStripper";
import { redemptionService } from "../redemptionService";
import { modInverse, modPow } from "@brone/crypto-core";

// Mock global fetch for redemption testing
const mockFetch = jest.fn();
global["fetch"] = mockFetch;
global["fetch"] = mockFetch;

describe("Anonymous Wallet and Voucher Redemption Pipeline (Phase 6, Version 6.2)", () => {
  beforeEach(() => {
    secureWalletManager.resetLedger();
    redemptionService.clearAllPending();
    mockFetch.mockReset();
  });

  describe("Block 1: Secure Hardware-Bound Two-Phase Ledger State", () => {
    it("should initialize a 256-bit seed phrase and support key rotation", async () => {
      const seed1 = await secureWalletManager.initializeWallet();
      expect(seed1).toHaveLength(64); // 256-bit represented as 64 hex chars

      const seed2 = await secureWalletManager.initializeWallet();
      expect(seed2).toBe(seed1); // Idempotent check

      const seed3 = await secureWalletManager.rotateSeedPhrase();
      expect(seed3).toHaveLength(64);
      expect(seed3).not.toBe(seed1); // Verify rotation
    });

    it("should enforce a strict Two-Phase Lock (2PL) buffer for point balances", async () => {
      await secureWalletManager.initializeWallet();

      const voucherId = "voucher-test-01";
      const amount = 500;

      // 1. Initial State
      let balance = secureWalletManager.getWalletBalance();
      expect(balance.immutableBalance).toBe(0);
      expect(balance.committingTotal).toBe(0);

      // 2. Stage Voucher (Phase 1 Lock)
      secureWalletManager.stageVoucherReward(voucherId, amount);
      balance = secureWalletManager.getWalletBalance();
      expect(balance.immutableBalance).toBe(0);
      expect(balance.committingTotal).toBe(amount); // Locked in committing buffer

      // Attempting to stage same voucher ID again should throw
      expect(() => {
        secureWalletManager.stageVoucherReward(voucherId, amount);
      }).toThrow();

      // 3. Commit Voucher (Phase 2 Commit)
      secureWalletManager.commitVoucherReward(voucherId, "valid-receipt-signature");
      balance = secureWalletManager.getWalletBalance();
      expect(balance.immutableBalance).toBe(amount); // Merged into immutable balance
      expect(balance.committingTotal).toBe(0); // Released from buffer
    });

    it("should support rollback of staged vouchers under 2PL", () => {
      const voucherId = "voucher-test-02";
      secureWalletManager.stageVoucherReward(voucherId, 250);

      let balance = secureWalletManager.getWalletBalance();
      expect(balance.committingTotal).toBe(250);

      // Rollback
      secureWalletManager.rollbackVoucherReward(voucherId);
      balance = secureWalletManager.getWalletBalance();
      expect(balance.immutableBalance).toBe(0);
      expect(balance.committingTotal).toBe(0);
    });

    it("should throw error if committing with invalid receipt signature", () => {
      const voucherId = "voucher-test-03";
      secureWalletManager.stageVoucherReward(voucherId, 100);

      expect(() => {
        secureWalletManager.commitVoucherReward(voucherId, "invalid-signature");
      }).toThrow();

      // Balance remains in committing buffer
      const balance = secureWalletManager.getWalletBalance();
      expect(balance.immutableBalance).toBe(0);
      expect(balance.committingTotal).toBe(100);
    });
  });

  describe("Block 2: Key-Synced Blind-Signature Voucher Stripper Engine", () => {
    it("should strip the blinding factor and locally verify unblinded signatures", () => {
      // Simulate blinding and signing locally
      // RSA parameters from local registry key version 'v1'
      const keyVersionId = "v1";
      const config = localPublicKeyRegistry[keyVersionId];
      expect(config).toBeDefined();

      const n = config.n;
      const e = config.e;

      // Parameters: message x, blinding factor r, d (computed privately)
      const rawMessage = 42n;
      const blindFactorR = 7n;

      // Blinding math: messageBlinded = (rawMessage * r^e) mod n
      const rToE = modPow(blindFactorR, e, n);
      const messageBlinded = (rawMessage * rToE) % n;

      // Signing simulation (simulate private key operation: signature = blinded^d mod n)
      // For this test, we can compute d manually or check modular consistency
      // Let's verify that signature unblinding and validation behaves correctly:
      const p = 100000000003n;
      const q = 100000000019n;
      const phi = (p - 1n) * (q - 1n);
      const d = modInverse(e, phi);

      // Let's assert that (e * d) % phi === 1n
      expect((e * d) % phi).toBe(1n);

      const blindSignature = modPow(messageBlinded, d, n);

      // Now run our voucher stripper engine
      const unblindedSignature = unblindSignedVoucher(blindSignature, blindFactorR, keyVersionId);

      // Local signature verification: signature^e mod n === message
      const isSignatureValid = verifyUnblindedVoucher(unblindedSignature, rawMessage, keyVersionId);
      expect(isSignatureValid).toBe(true);

      // An invalid message should fail validation
      const isInvalidMsgValid = verifyUnblindedVoucher(unblindedSignature, 999n, keyVersionId);
      expect(isInvalidMsgValid).toBe(false);
    });
  });

  describe("Block 3: Anonymous Voucher Redemption Router with Forensic Envelope Guard", () => {
    it("should encrypt vouchers in pending state and decrypt them on retrieval", async () => {
      await secureWalletManager.initializeWallet();

      const voucherId = "voucher-forensic-01";
      const unblindedToken = "0x82f91a0c84bcde99a0ffde32131";
      const amount = 300;

      // Write to outbox (encrypts payload on disk)
      await redemptionService.writeVoucherToOutbox(voucherId, unblindedToken, amount);

      // Verify that outbox data contains only encrypted/isolated details (raw token is not plain readable)
      const serviceAny = redemptionService as any;
      const diskData = serviceAny.diskOutbox.get(voucherId);
      expect(diskData).toBeDefined();
      expect(diskData).not.toContain(unblindedToken); // Asserts forensic envelope security

      // Retrieve and decrypt
      const retrieved = await redemptionService.readVoucherFromOutbox(voucherId);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.voucherId).toBe(voucherId);
      expect(retrieved?.unblindedToken).toBe(unblindedToken);
      expect(retrieved?.amount).toBe(amount);
    });

    it("should push voucher payload over clean isolated execution path and commit on success", async () => {
      await secureWalletManager.initializeWallet();

      const voucherId = "voucher-network-01";
      const unblindedToken = "0x9b2a75d19c3e8a47";
      const amount = 150;

      await redemptionService.writeVoucherToOutbox(voucherId, unblindedToken, amount);

      // Mock success response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          receipt_signature: "valid-receipt-from-server"
        })
      });

      // Override delays for test execution
      redemptionService.minDelayMs = 0;
      redemptionService.maxDelayMs = 0;

      const success = await redemptionService.executeRedemption(voucherId, "http://localhost:3000");
      expect(success).toBe(true);

      // Headers verified to be isolated (Content-Type, Connection: close)
      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:3000/redeem-voucher",
        expect.objectContaining({
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Connection": "close"
          }
        })
      );

      // Verify 2PL transition to fully committed balance
      const balance = secureWalletManager.getWalletBalance();
      expect(balance.immutableBalance).toBe(amount);
      expect(balance.committingTotal).toBe(0);

      // Verify outbox record is removed on completion
      const retrieved = await redemptionService.readVoucherFromOutbox(voucherId);
      expect(retrieved).toBeNull();
    });

    it("should retain voucher locked in committing state on network failure", async () => {
      await secureWalletManager.initializeWallet();

      const voucherId = "voucher-network-02";
      const unblindedToken = "0xabcdef123456";
      const amount = 100;

      await redemptionService.writeVoucherToOutbox(voucherId, unblindedToken, amount);

      // Mock network failure
      mockFetch.mockRejectedValueOnce(new Error("Connection refused"));

      const success = await redemptionService.executeRedemption(voucherId, "http://localhost:3000");
      expect(success).toBe(false);

      // Verify wallet state: still staged in committing state, balance not credited
      const balance = secureWalletManager.getWalletBalance();
      expect(balance.immutableBalance).toBe(0);
      expect(balance.committingTotal).toBe(amount);

      // Verify still encrypted in outbox
      const retrieved = await redemptionService.readVoucherFromOutbox(voucherId);
      expect(retrieved).not.toBeNull();
    });
  });
});

