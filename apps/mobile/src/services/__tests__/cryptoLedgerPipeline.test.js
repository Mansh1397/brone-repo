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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/** @jest-environment jsdom */
const react_1 = __importDefault(require("react"));
const sqlite3 = __importStar(require("sqlite3"));
const react_2 = require("@testing-library/react");
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
jest.mock("expo-sqlite", () => {
    return {
        openDatabaseAsync: async () => {
            return new MockSQLiteDatabase();
        }
    };
}, { virtual: true });
jest.mock("react-native", () => {
    const React = require("react");
    const View = React.forwardRef(({ children, style, testID, ...props }, ref) => React.createElement("div", { ...props, ref, style, "data-testid": testID }, children));
    const Text = ({ children, style, testID, ...props }) => React.createElement("span", { ...props, style, "data-testid": testID }, children);
    return {
        View,
        Text,
        StyleSheet: {
            create: (styles) => styles
        },
        NativeModules: {
            ExpoSecureStore: {}
        }
    };
}, { virtual: true });
const cryptoBroker_1 = require("../cryptoBroker");
const ledgerStore_1 = require("../../state/ledgerStore");
const syncStatusView_1 = require("../../components/syncStatusView");
const offlineOutbox_1 = require("../../sync/offlineOutbox");
const secureWallet_1 = require("../../wallet/secureWallet");
describe("Frontend JSI Blinding, Non-Blocking Ledger Store, and Telemetry UI Suite (Phase 10A, Version 10A.9)", () => {
    beforeEach(async () => {
        (0, offlineOutbox_1.resetOfflineDatabaseInstance)();
        ledgerStore_1.ledgerStore.resetStore();
        secureWallet_1.secureWalletManager.resetLedger();
        await secureWallet_1.secureWalletManager.initializeWallet();
    });
    describe("Block 1: Cryptographic JSI Service Broker", () => {
        it("should successfully generate and retrieve an anonymous blinded attestation token", async () => {
            await cryptoBroker_1.cryptoBroker.refreshBlindedAttestationToken();
            const token = cryptoBroker_1.cryptoBroker.getAnonymousDeviceToken();
            expect(token).toContain("unblinded-generic-untampered-device-token-");
        });
        it("should poison context and fail hard on execution loop tampering / bitwise mismatch", async () => {
            // Access private method by casting to any to inject fault
            const originalLoop = cryptoBroker_1.cryptoBroker.executeBlindingLoop;
            let count = 0;
            cryptoBroker_1.cryptoBroker.executeBlindingLoop = (input, r) => {
                count++;
                if (count === 2) {
                    // Fault injection: modify output of the second loop
                    return originalLoop(input, r) + "corrupted-bit";
                }
                return originalLoop(input, r);
            };
            try {
                await expect(cryptoBroker_1.cryptoBroker.refreshBlindedAttestationToken()).rejects.toThrow("[FATAL CRYPTO EXCEPTION] Anti-Fault bitwise mismatch detected. Session terminated.");
            }
            finally {
                // Restore loop
                cryptoBroker_1.cryptoBroker.executeBlindingLoop = originalLoop;
            }
        });
    });
    describe("Block 2: Two-Phase Non-Blocking Ledger State Engine", () => {
        it("should handle transaction slice commit cleanly and adjust balances atomically", async () => {
            const txId = "tx-slice-success";
            const submitMock = jest.fn().mockResolvedValueOnce({
                success: true,
                receipt_signature: "receipt-sig-abc"
            });
            const dispatchPromise = ledgerStore_1.ledgerStore.dispatchTransaction(txId, 250, {}, submitMock);
            expect(ledgerStore_1.ledgerStore.getSliceState(txId)).toBe("STAGED_COMMITTING");
            await dispatchPromise;
            expect(ledgerStore_1.ledgerStore.getSliceState(txId)).toBe("SYNCED");
            expect(ledgerStore_1.ledgerStore.getBalance()).toBe(1250);
        });
        it("should route to offline outbox and set state to RECONCILING on network failure/timeout", async () => {
            const txId = "tx-slice-failure";
            const submitMock = jest.fn().mockRejectedValueOnce(new Error("Timeout"));
            await ledgerStore_1.ledgerStore.dispatchTransaction(txId, 100, { amount: 100 }, submitMock);
            // Verify slice status transitions to RECONCILING
            expect(ledgerStore_1.ledgerStore.getSliceState(txId)).toBe("RECONCILING");
            // Verify payload is stored inside offline outbox
            const queued = await (0, offlineOutbox_1.getQueuedOperations)();
            expect(queued).toHaveLength(1);
            expect(queued[0].id).toBe(txId);
        });
    });
    describe("Block 3: Hardened Secure Outbox Telemetry UI", () => {
        it("should display stable state and mask counts or timing metadata", () => {
            const { getByTestId } = (0, react_2.render)(react_1.default.createElement(syncStatusView_1.SyncStatusView, null));
            const container = getByTestId("sync-status-container");
            const text = getByTestId("sync-status-text");
            expect(container).toBeDefined();
            expect(text.textContent).toBe("Stable Connection Secured");
            // Verify it does NOT expose data size descriptors or row count integers
            expect(text.textContent).not.toContain("bytes");
            expect(text.textContent).not.toContain("rows");
        });
    });
});
