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
// Mock the expo-sqlite module virtually
jest.mock("expo-sqlite", () => {
    return {
        openDatabaseAsync: async () => {
            activeMockDb = new MockSQLiteDatabase();
            return activeMockDb;
        }
    };
}, { virtual: true });
// Mock expo-background-fetch and expo-task-manager virtually
jest.mock("expo-background-fetch", () => {
    return {
        BackgroundFetchResult: {
            NewData: 1,
            NoData: 2,
            Failed: 3
        },
        registerTaskAsync: jest.fn()
    };
}, { virtual: true });
jest.mock("expo-task-manager", () => {
    return {
        defineTask: jest.fn(),
        isTaskRegisteredAsync: jest.fn().mockResolvedValue(false)
    };
}, { virtual: true });
// Mock react-native AppState
let appStateChangeCallback = null;
jest.mock("react-native", () => {
    return {
        AppState: {
            addEventListener: jest.fn((event, callback) => {
                if (event === "change") {
                    appStateChangeCallback = callback;
                }
                return { remove: jest.fn() };
            })
        },
        NativeModules: {
            ExpoSecureStore: {
                setItemAsync: jest.fn(),
                getItemAsync: jest.fn(),
                deleteItemAsync: jest.fn()
            }
        }
    };
}, { virtual: true });
// Mock voucherStripper
jest.mock("../../wallet/voucherStripper", () => {
    return {
        unblindSignedVoucher: jest.fn((sig) => sig)
    };
}, { virtual: true });
const syncWorker_1 = require("../syncWorker");
const outboxManager_1 = require("../outboxManager");
const mockFetch = jest.fn();
global.fetch = mockFetch;
describe("Time-Masked Background Synchronization Worker Tests", () => {
    beforeEach(async () => {
        (0, syncWorker_1.resetSyncWorkerState)();
        (0, outboxManager_1.resetDatabaseInstance)();
        mockFetch.mockReset();
        await (0, outboxManager_1.getDatabase)();
    });
    afterEach(async () => {
        if (activeMockDb) {
            await activeMockDb.close();
            activeMockDb = null;
        }
    });
    it("should verify padPayload outputs exactly 2048 bytes for various structures", () => {
        const payload1 = { message: "test" };
        const padded1 = (0, syncWorker_1.padPayload)(payload1, 2048);
        expect(padded1.length).toBe(2048);
        const parsed1 = JSON.parse(padded1);
        expect(parsed1.payload.message).toBe("test");
        expect(parsed1.padding).toBeDefined();
        const payload2 = { test: 123, list: [1, 2, 3] };
        const padded2 = (0, syncWorker_1.padPayload)(payload2, 2048);
        expect(padded2.length).toBe(2048);
    });
    it("should process PENDING_BLINDING tokens, transitioning to UNBLINDED on success", async () => {
        await (0, outboxManager_1.queueToken)("t-1", "AUTH_TOKEN", "42", "12345", "blinded-T-1");
        mockFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ signed_blinded_token: "987654321" })
        });
        const success = await (0, syncWorker_1.runSyncLoop)();
        expect(success).toBe(true);
        const entry = await (0, outboxManager_1.getOutboxEntry)("t-1");
        expect(entry?.state).toBe("UNBLINDED");
        expect(entry?.unblinded_signature_S).toBe("987654321");
        expect(entry?.blind_factor_r).toBeNull(); // Zeroed
    });
    it("should handle sync execution failures with automatic database state rollbacks", async () => {
        await (0, outboxManager_1.queueToken)("t-2", "AUTH_TOKEN", "42", "12345", "blinded-T-2");
        // Mock network failure
        mockFetch.mockRejectedValueOnce(new Error("Connection timeout"));
        const success = await (0, syncWorker_1.runSyncLoop)();
        // Engine catches error and returns false
        expect(success).toBe(false);
        // Database record state must be rolled back to PENDING_BLINDING
        const entry = await (0, outboxManager_1.getOutboxEntry)("t-2");
        expect(entry?.state).toBe("PENDING_BLINDING");
        expect(entry?.blind_factor_r).toBe("12345");
    });
    it("should aggressively freeze execution and throw if app transitions to background during execution", async () => {
        await (0, outboxManager_1.queueToken)("t-3", "AUTH_TOKEN", "42", "12345", "blinded-T-3");
        // Transition AppState to background
        if (appStateChangeCallback) {
            appStateChangeCallback("background");
        }
        mockFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ signed_blinded_token: "9999" })
        });
        const success = await (0, syncWorker_1.runSyncLoop)();
        expect(success).toBe(false);
        // Verify record state remained unchanged
        const entry = await (0, outboxManager_1.getOutboxEntry)("t-3");
        expect(entry?.state).toBe("PENDING_BLINDING");
        // Transition AppState back to active
        if (appStateChangeCallback) {
            appStateChangeCallback("active");
        }
    });
});
