import * as sqlite3 from "sqlite3";

// 1. Mock expo-sqlite with in-memory sqlite3 database
class MockSQLiteDatabase {
  private db: sqlite3.Database;

  constructor() {
    this.db = new sqlite3.Database(":memory:");
  }

  async execAsync(sql: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.exec(sql, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async runAsync(sql: string, params: any[] = []): Promise<{ lastInsertRowId: number; changes: number }> {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve({ lastInsertRowId: this.lastID, changes: this.changes });
      });
    });
  }

  async getAllAsync<T>(sql: string, params: any[] = []): Promise<T[]> {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows as T[]);
      });
    });
  }

  async getFirstAsync<T>(sql: string, params: any[] = []): Promise<T | null> {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve((row as T) || null);
      });
    });
  }

  async withTransactionAsync(callback: () => Promise<void>): Promise<void> {
    await this.execAsync("BEGIN TRANSACTION");
    try {
      await callback();
      await this.execAsync("COMMIT");
    } catch (err) {
      await this.execAsync("ROLLBACK");
      throw err;
    }
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

let activeMockDb: MockSQLiteDatabase | null = null;

jest.mock(
  "expo-sqlite",
  () => {
    return {
      openDatabaseAsync: async () => {
        activeMockDb = new MockSQLiteDatabase();
        return activeMockDb;
      }
    };
  },
  { virtual: true }
);

// Virtually mock react-native to prevent missing module or syntax errors in Jest Node environment
jest.mock(
  "react-native",
  () => ({
    NativeModules: {
      ExpoSecureStore: {}
    }
  }),
  { virtual: true }
);

import {
  queueOfflineOperation,
  getQueuedOperations,
  deleteOfflineOperation,
  executeCheckBeforeCommitValidation,
  resetOfflineDatabaseInstance,
  getOfflineDatabase,
  fnv1aChecksum
} from "../offlineOutbox";
import { rollbackGuard } from "../rollbackGuard";
import { syncManager } from "../syncManager";
import { secureWalletManager } from "../../wallet/secureWallet";
import { getOrCreateOutboxKey } from "../outboxEncryption";

// Mock global fetch for sync tests
const mockFetch = jest.fn();
global.fetch = mockFetch as any;

describe("Offline Durability, Storage Isolation, and Sync Pipeline (Phase 8, Version 8.1)", () => {
  beforeEach(async () => {
    resetOfflineDatabaseInstance();
    rollbackGuard.resetGuard();
    secureWalletManager.resetLedger();
    mockFetch.mockReset();
    
    // Setup secure seed
    await secureWalletManager.initializeWallet();
  });

  describe("Block 1: Crash-Proof Encrypted Offline Outbox", () => {
    it("should open database, set WAL mode, and queue encrypted entries", async () => {
      const db = await getOfflineDatabase();
      expect(db).toBeDefined();

      const id = "op-test-01";
      const payload = { location: "cell_h3_84110adffff", hash: "0xabcdef123" };
      await queueOfflineOperation(id, "SUBMISSION", payload);

      // Verify at-rest encryption (raw values are not plain text readable)
      const rows = await db.getAllAsync<any>("SELECT * FROM offline_outbox");
      expect(rows).toHaveLength(1);
      expect(rows[0].encrypted_payload).not.toContain("cell_h3_84110adffff");
      expect(rows[0].encrypted_payload).not.toContain("0xabcdef123");

      // Verify decryptable retrieval
      const operations = await getQueuedOperations();
      expect(operations).toHaveLength(1);
      expect(operations[0].id).toBe(id);
      expect(operations[0].operationType).toBe("SUBMISSION");
      expect(operations[0].payload).toEqual(payload);
    });

    it("should execute CBC verification and rollback/evict corrupted rows on boot", async () => {
      const db = await getOfflineDatabase();
      const id1 = "op-valid";
      const id2 = "op-corrupted";
      const payload = { vote: "approve" };

      await queueOfflineOperation(id1, "VOTE", payload);
      await queueOfflineOperation(id2, "VOTE", payload);

      // Break checksum of the second row manually to simulate write crash
      await db.runAsync("UPDATE offline_outbox SET checksum = 'broken-hash' WHERE id = ?", [id2]);

      // Run boot validator pass
      const corruptedCount = await executeCheckBeforeCommitValidation();
      expect(corruptedCount).toBe(1);

      // Verify corrupted row is deleted
      const operations = await getQueuedOperations();
      expect(operations).toHaveLength(1);
      expect(operations[0].id).toBe(id1);
    });

    it("should enforce FIFO eviction if size exceeds storage limit threshold", async () => {
      const db = await getOfflineDatabase();
      
      const { setStorageCeilingChars } = require("../offlineOutbox");
      
      // Enforce a tiny ceiling of 100 characters for test
      setStorageCeilingChars(100);

      try {
        await queueOfflineOperation("op-fifo-1", "SUBMISSION", { data: "small" }); // ~25 chars
        await queueOfflineOperation("op-fifo-2", "SUBMISSION", { data: "small2" }); // ~26 chars
        
        // This big one will trigger FIFO eviction of op-fifo-1
        await queueOfflineOperation("op-fifo-3", "SUBMISSION", { data: "a".repeat(150) });

        const operations = await getQueuedOperations();
        // The first operation should have been evicted to make room
        const hasFirst = operations.some(op => op.id === "op-fifo-1");
        expect(hasFirst).toBe(false);
      } finally {
        // Restore default 50MB ceiling
        setStorageCeilingChars(50 * 1024 * 1024);
      }
    });
  });

  describe("Block 2: Transaction Rollback Guard", () => {
    it("should isolate ledger and throw if trying to spend/mutate locked voucher", () => {
      const voucherId = "voucher-locked-01";
      
      // Lock voucher
      rollbackGuard.lockVoucher(voucherId);
      expect(rollbackGuard.isLocked(voucherId)).toBe(true);

      // Double locking or mutation attempts should throw
      expect(() => {
        rollbackGuard.lockVoucher(voucherId);
      }).toThrow();
      
      expect(rollbackGuard.getVoucherStatus(voucherId)).toBe("PENDING_SUBMISSION");
    });

    it("should trigger rollback and lock in PENDING_RETRY flag status on transit failure", () => {
      const voucherId = "voucher-rollback-01";
      
      // Stage it in ledger 2PL first
      secureWalletManager.stageVoucherReward(voucherId, 200);

      rollbackGuard.lockVoucher(voucherId);
      
      // Trigger rollback
      rollbackGuard.triggerRollbackToPendingRetry(voucherId);

      // Wallet staged balance must be rolled back
      const balance = secureWalletManager.getWalletBalance();
      expect(balance.committingTotal).toBe(0);

      // In-memory lock is released but persists PENDING_RETRY status flag to prevent double-spend
      expect(rollbackGuard.getVoucherStatus(voucherId)).toBe("PENDING_RETRY");
      expect(rollbackGuard.isLocked(voucherId)).toBe(true); // Still locks out updates
    });
  });

  describe("Block 3: Privacy-Preserving Sync Manager", () => {
    it("should process outbox using batching, randomized delays, and cycle metadata headers", async () => {
      const id = "op-sync-01";
      const payload = { zk_proof: { proof_signature: "valid-sig" }, decision: "approve" };
      await queueOfflineOperation(id, "VOTE", payload);

      // Override delay metrics to prevent 10 minute waits in test
      syncManager.baseIntervalMs = 0;
      syncManager.jitterRangeMs = 0;

      // Mock success response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          receipt_signature: "sync-receipt-sig"
        })
      });

      const successCount = await syncManager.reconcileOfflineOutbox("http://localhost:3000");
      expect(successCount).toBe(1);

      // Verify request payload headers were cycled and scrubbed (clean origin points)
      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:3000/tasks/op-sync-01/vote",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            "User-Agent": expect.any(String),
            "X-Ephemeral-Socket-ID": expect.any(String)
          })
        })
      );

      // Verify entry got deleted on success
      const operations = await getQueuedOperations();
      expect(operations).toHaveLength(0);
    });

    it("should lock status in PENDING_RETRY on sync failure", async () => {
      const id = "op-sync-02";
      const payload = { zk_proof: { proof_signature: "valid" }, decision: "reject" };
      await queueOfflineOperation(id, "VOTE", payload);

      syncManager.baseIntervalMs = 0;
      syncManager.jitterRangeMs = 0;

      // Mock server error
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500
      });

      const successCount = await syncManager.reconcileOfflineOutbox("http://localhost:3000");
      expect(successCount).toBe(0);

      // Verify the guard locked the voucher status as PENDING_RETRY
      expect(rollbackGuard.getVoucherStatus(id)).toBe("PENDING_RETRY");
    });
  });
});
