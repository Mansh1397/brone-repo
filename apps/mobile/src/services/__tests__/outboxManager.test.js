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
// Create the in-memory SQLite wrapper mocking expo-sqlite
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
let openCount = 0;
// Mock the expo-sqlite module virtually
jest.mock("expo-sqlite", () => {
    return {
        openDatabaseAsync: async () => {
            openCount++;
            activeMockDb = new MockSQLiteDatabase();
            return activeMockDb;
        }
    };
}, { virtual: true });
// Import the outbox manager under test
const outboxManager_1 = require("../outboxManager");
describe("Write-Ahead Offline Outbox Database Service Tests", () => {
    beforeEach(async () => {
        (0, outboxManager_1.resetDatabaseInstance)();
        openCount = 0;
        // Force a fresh database instantiation in memory for each test
        await (0, outboxManager_1.getDatabase)();
    });
    afterEach(async () => {
        if (activeMockDb) {
            await activeMockDb.close();
            activeMockDb = null;
        }
    });
    it("should initialize database table structure correctly and enforce CHECK constraints", async () => {
        const db = await (0, outboxManager_1.getDatabase)();
        // Verify valid insertion succeeds
        await expect((0, outboxManager_1.queueToken)("t-1", "AUTH_TOKEN", "raw-msg-1", "r-factor-1", "blinded-T-1")).resolves.not.toThrow();
        // Verify CHECK constraint on token_type
        await expect(db.runAsync("INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('t-2', 'INVALID_TYPE', 'PENDING_BLINDING', 'raw-msg-2')")).rejects.toThrow();
        // Verify CHECK constraint on state
        await expect(db.runAsync("INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('t-3', 'AUTH_TOKEN', 'INVALID_STATE', 'raw-msg-3')")).rejects.toThrow();
    });
    it("should enforce UNIQUE constraint on raw_message_x", async () => {
        // Insert first token
        await (0, outboxManager_1.queueToken)("t-1", "AUTH_TOKEN", "raw-msg-duplicate", "r-1", "T-1");
        // Attempt duplicate insertion on raw_message_x
        await expect((0, outboxManager_1.queueToken)("t-2", "AUTH_TOKEN", "raw-msg-duplicate", "r-2", "T-2")).rejects.toThrow();
    });
    it("should successfully execute offline token state transition flows", async () => {
        const id = "token-voucher-77";
        await (0, outboxManager_1.queueToken)(id, "REWARD_VOUCHER", "x-value-77", "r-value-77", "T-value-77");
        // 1. Initial State Check
        let entry = await (0, outboxManager_1.getOutboxEntry)(id);
        expect(entry).not.toBeNull();
        expect(entry?.state).toBe("PENDING_BLINDING");
        expect(entry?.blind_factor_r).toBe("r-value-77");
        expect(entry?.retry_count).toBe(0);
        // 2. Transition to BLINDED_SENT
        await (0, outboxManager_1.transitionToBlindedSent)(id);
        entry = await (0, outboxManager_1.getOutboxEntry)(id);
        expect(entry?.state).toBe("BLINDED_SENT");
        expect(entry?.last_attempted_at).toBeGreaterThan(0);
        // 3. Transition to UNBLINDED - Must verify zeroization of blind_factor_r
        await (0, outboxManager_1.transitionToUnblinded)(id, "S-prime-77", "S-signature-77");
        entry = await (0, outboxManager_1.getOutboxEntry)(id);
        expect(entry?.state).toBe("UNBLINDED");
        expect(entry?.blind_factor_r).toBeNull(); // Strict zeroization verification
        expect(entry?.signed_blinded_token_S_prime).toBe("S-prime-77");
        expect(entry?.unblinded_signature_S).toBe("S-signature-77");
        // 4. Transition to REDEMPTION_SENT
        await (0, outboxManager_1.transitionToRedemptionSent)(id);
        entry = await (0, outboxManager_1.getOutboxEntry)(id);
        expect(entry?.state).toBe("REDEMPTION_SENT");
        expect(entry?.retry_count).toBe(1);
        // 5. Transition to SPENT
        await (0, outboxManager_1.transitionToSpent)(id);
        entry = await (0, outboxManager_1.getOutboxEntry)(id);
        expect(entry?.state).toBe("SPENT");
        // 6. Verify it is no longer returned in pending tokens
        const pending = await (0, outboxManager_1.getPendingTokens)();
        expect(pending.find(p => p.id === id)).toBeUndefined();
    });
    it("should guarantee atomic rollback during transaction failures", async () => {
        const db = await (0, outboxManager_1.getDatabase)();
        // Trigger atomic transaction execution failure inside transaction
        await expect(db.withTransactionAsync(async () => {
            // This query is valid
            await db.runAsync("INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('tx-1', 'AUTH_TOKEN', 'PENDING_BLINDING', 'raw-tx-1')");
            // This query will fail CHECK constraint, triggering an error
            await db.runAsync("INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('tx-2', 'INVALID_TYPE', 'PENDING_BLINDING', 'raw-tx-2')");
        })).rejects.toThrow();
        // Verify that the first query 'tx-1' was rolled back successfully
        const entry = await (0, outboxManager_1.getOutboxEntry)("tx-1");
        expect(entry).toBeNull();
    });
    it("should enforce a strict Singleton connection pattern and prevent concurrent open call leaks", async () => {
        (0, outboxManager_1.resetDatabaseInstance)();
        openCount = 0;
        // Fire multiple concurrent database retrieval calls
        const promises = [(0, outboxManager_1.getDatabase)(), (0, outboxManager_1.getDatabase)(), (0, outboxManager_1.getDatabase)()];
        const dbs = await Promise.all(promises);
        // Verify all resolved databases are the exact same instance
        expect(dbs[0]).toBe(dbs[1]);
        expect(dbs[1]).toBe(dbs[2]);
        // Verify openDatabaseAsync was only invoked exactly once
        expect(openCount).toBe(1);
    });
});
