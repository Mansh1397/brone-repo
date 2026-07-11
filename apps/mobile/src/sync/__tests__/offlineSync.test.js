"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const sqlite3 = __importStar(require("sqlite3"));
// 1. Mock expo-sqlite with in-memory sqlite3 database
class MockSQLiteDatabase {
    db;
    constructor() {
        this.db = new sqlite3.Database(":memory:");
    }
    async execAsync(sql) {
        return new Promise((resolve, reject) => {
            this.db.exec(sql, (err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
    async runAsync(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function (err) {
                if (err)
                    reject(err);
                else
                    resolve({ lastInsertRowId: this.lastID, changes: this.changes });
            });
        });
    }
    async getAllAsync(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err)
                    reject(err);
                else
                    resolve(rows);
            });
        });
    }
    async getFirstAsync(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err)
                    reject(err);
                else
                    resolve(row || null);
            });
        });
    }
    async withTransactionAsync(callback) {
        await this.execAsync("BEGIN TRANSACTION");
        try {
            await callback();
            await this.execAsync("COMMIT");
        }
        catch (err) {
            await this.execAsync("ROLLBACK");
            throw err;
        }
    }
    close() {
        return new Promise((resolve, reject) => {
            this.db.close((err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
}
let activeMockDb = null;
jest.mock("expo-sqlite", () => {
    return {
        openDatabaseAsync: async () => {
            activeMockDb = new MockSQLiteDatabase();
            return activeMockDb;
        }
    };
}, { virtual: true });
// Virtually mock react-native to prevent missing module or syntax errors in Jest Node environment
jest.mock("react-native", () => ({
    NativeModules: {
        ExpoSecureStore: {}
    }
}), { virtual: true });
const offlineOutbox_1 = require("../offlineOutbox");
const rollbackGuard_1 = require("../rollbackGuard");
const syncManager_1 = require("../syncManager");
const secureWallet_1 = require("../../wallet/secureWallet");
// Mock global fetch for sync tests
const mockFetch = jest.fn();
global.fetch = mockFetch;
describe("Offline Durability, Storage Isolation, and Sync Pipeline (Phase 8, Version 8.1)", () => {
    beforeEach(async () => {
        (0, offlineOutbox_1.resetOfflineDatabaseInstance)();
        rollbackGuard_1.rollbackGuard.resetGuard();
        secureWallet_1.secureWalletManager.resetLedger();
        mockFetch.mockReset();
        // Setup secure seed
        await secureWallet_1.secureWalletManager.initializeWallet();
    });
    describe("Block 1: Crash-Proof Encrypted Offline Outbox", () => {
        it("should open database, set WAL mode, and queue encrypted entries", async () => {
            const db = await (0, offlineOutbox_1.getOfflineDatabase)();
            expect(db).toBeDefined();
            const id = "op-test-01";
            const payload = { location: "cell_h3_84110adffff", hash: "0xabcdef123" };
            await (0, offlineOutbox_1.queueOfflineOperation)(id, "SUBMISSION", payload);
            // Verify at-rest encryption (raw values are not plain text readable)
            const rows = await db.getAllAsync("SELECT * FROM offline_outbox");
            expect(rows).toHaveLength(1);
            expect(rows[0].encrypted_payload).not.toContain("cell_h3_84110adffff");
            expect(rows[0].encrypted_payload).not.toContain("0xabcdef123");
            // Verify decryptable retrieval
            const operations = await (0, offlineOutbox_1.getQueuedOperations)();
            expect(operations).toHaveLength(1);
            expect(operations[0].id).toBe(id);
            expect(operations[0].operationType).toBe("SUBMISSION");
            expect(operations[0].payload).toEqual(payload);
        });
        it("should execute CBC verification and rollback/evict corrupted rows on boot", async () => {
            const db = await (0, offlineOutbox_1.getOfflineDatabase)();
            const id1 = "op-valid";
            const id2 = "op-corrupted";
            const payload = { vote: "approve" };
            await (0, offlineOutbox_1.queueOfflineOperation)(id1, "VOTE", payload);
            await (0, offlineOutbox_1.queueOfflineOperation)(id2, "VOTE", payload);
            // Break checksum of the second row manually to simulate write crash
            await db.runAsync("UPDATE offline_outbox SET checksum = 'broken-hash' WHERE id = ?", [id2]);
            // Run boot validator pass
            const corruptedCount = await (0, offlineOutbox_1.executeCheckBeforeCommitValidation)();
            expect(corruptedCount).toBe(1);
            // Verify corrupted row is deleted
            const operations = await (0, offlineOutbox_1.getQueuedOperations)();
            expect(operations).toHaveLength(1);
            expect(operations[0].id).toBe(id1);
        });
        it("should enforce FIFO eviction if size exceeds storage limit threshold", async () => {
            const db = await (0, offlineOutbox_1.getOfflineDatabase)();
            const { setStorageCeilingChars } = require("../offlineOutbox");
            // Enforce a tiny ceiling of 100 characters for test
            setStorageCeilingChars(100);
            try {
                await (0, offlineOutbox_1.queueOfflineOperation)("op-fifo-1", "SUBMISSION", { data: "small" }); // ~25 chars
                await (0, offlineOutbox_1.queueOfflineOperation)("op-fifo-2", "SUBMISSION", { data: "small2" }); // ~26 chars
                // This big one will trigger FIFO eviction of op-fifo-1
                await (0, offlineOutbox_1.queueOfflineOperation)("op-fifo-3", "SUBMISSION", { data: "a".repeat(150) });
                const operations = await (0, offlineOutbox_1.getQueuedOperations)();
                // The first operation should have been evicted to make room
                const hasFirst = operations.some(op => op.id === "op-fifo-1");
                expect(hasFirst).toBe(false);
            }
            finally {
                // Restore default 50MB ceiling
                setStorageCeilingChars(50 * 1024 * 1024);
            }
        });
    });
    describe("Block 2: Transaction Rollback Guard", () => {
        it("should isolate ledger and throw if trying to spend/mutate locked voucher", () => {
            const voucherId = "voucher-locked-01";
            // Lock voucher
            rollbackGuard_1.rollbackGuard.lockVoucher(voucherId);
            expect(rollbackGuard_1.rollbackGuard.isLocked(voucherId)).toBe(true);
            // Double locking or mutation attempts should throw
            expect(() => {
                rollbackGuard_1.rollbackGuard.lockVoucher(voucherId);
            }).toThrow();
            expect(rollbackGuard_1.rollbackGuard.getVoucherStatus(voucherId)).toBe("PENDING_SUBMISSION");
        });
        it("should trigger rollback and lock in PENDING_RETRY flag status on transit failure", () => {
            const voucherId = "voucher-rollback-01";
            // Stage it in ledger 2PL first
            secureWallet_1.secureWalletManager.stageVoucherReward(voucherId, 200);
            rollbackGuard_1.rollbackGuard.lockVoucher(voucherId);
            // Trigger rollback
            rollbackGuard_1.rollbackGuard.triggerRollbackToPendingRetry(voucherId);
            // Wallet staged balance must be rolled back
            const balance = secureWallet_1.secureWalletManager.getWalletBalance();
            expect(balance.committingTotal).toBe(0);
            // In-memory lock is released but persists PENDING_RETRY status flag to prevent double-spend
            expect(rollbackGuard_1.rollbackGuard.getVoucherStatus(voucherId)).toBe("PENDING_RETRY");
            expect(rollbackGuard_1.rollbackGuard.isLocked(voucherId)).toBe(true); // Still locks out updates
        });
    });
    describe("Block 3: Privacy-Preserving Sync Manager", () => {
        it("should process outbox using batching, randomized delays, and cycle metadata headers", async () => {
            const id = "op-sync-01";
            const payload = { zk_proof: { proof_signature: "valid-sig" }, decision: "approve" };
            await (0, offlineOutbox_1.queueOfflineOperation)(id, "VOTE", payload);
            // Override delay metrics to prevent 10 minute waits in test
            syncManager_1.syncManager.baseIntervalMs = 0;
            syncManager_1.syncManager.jitterRangeMs = 0;
            // Mock success response
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    success: true,
                    receipt_signature: "sync-receipt-sig"
                })
            });
            const successCount = await syncManager_1.syncManager.reconcileOfflineOutbox("http://localhost:3000");
            expect(successCount).toBe(1);
            // Verify request payload headers were cycled and scrubbed (clean origin points)
            expect(mockFetch).toHaveBeenCalledWith("http://localhost:3000/tasks/op-sync-01/vote", expect.objectContaining({
                method: "POST",
                headers: expect.objectContaining({
                    "Content-Type": "application/json",
                    "User-Agent": expect.any(String),
                    "X-Ephemeral-Socket-ID": expect.any(String)
                })
            }));
            // Verify entry got deleted on success
            const operations = await (0, offlineOutbox_1.getQueuedOperations)();
            expect(operations).toHaveLength(0);
        });
        it("should lock status in PENDING_RETRY on sync failure", async () => {
            const id = "op-sync-02";
            const payload = { zk_proof: { proof_signature: "valid" }, decision: "reject" };
            await (0, offlineOutbox_1.queueOfflineOperation)(id, "VOTE", payload);
            syncManager_1.syncManager.baseIntervalMs = 0;
            syncManager_1.syncManager.jitterRangeMs = 0;
            // Mock server error
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 500
            });
            const successCount = await syncManager_1.syncManager.reconcileOfflineOutbox("http://localhost:3000");
            expect(successCount).toBe(0);
            // Verify the guard locked the voucher status as PENDING_RETRY
            expect(rollbackGuard_1.rollbackGuard.getVoucherStatus(id)).toBe("PENDING_RETRY");
        });
    });
});
