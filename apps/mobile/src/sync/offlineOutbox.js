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
exports.STORAGE_CEILING_CHARS = void 0;
exports.fnv1aChecksum = fnv1aChecksum;
exports.getOfflineDatabase = getOfflineDatabase;
exports.resetOfflineDatabaseInstance = resetOfflineDatabaseInstance;
exports.executeCheckBeforeCommitValidation = executeCheckBeforeCommitValidation;
exports.setStorageCeilingChars = setStorageCeilingChars;
exports.queueOfflineOperation = queueOfflineOperation;
exports.getQueuedOperations = getQueuedOperations;
exports.deleteOfflineOperation = deleteOfflineOperation;
const SQLite = __importStar(require("expo-sqlite"));
const outboxEncryption_1 = require("./outboxEncryption");
// Custom lightweight checksum function (FNV-1a)
function fnv1aChecksum(str) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        // Integer multiplication simulation
        hash = (hash * 0x01000193) | 0;
    }
    return (hash >>> 0).toString(16);
}
let dbInstance = null;
let dbInitPromise = null;
function getOfflineDatabase() {
    if (dbInstance) {
        return Promise.resolve(dbInstance);
    }
    if (!dbInitPromise) {
        dbInitPromise = (async () => {
            const db = await SQLite.openDatabaseAsync("brone_offline_outbox.db");
            // 1. Force database engine into Write-Ahead Logging (WAL) mode
            await db.execAsync("PRAGMA journal_mode = WAL;");
            // 2. Initialize table schema
            await db.execAsync(`
        CREATE TABLE IF NOT EXISTS offline_outbox (
          id TEXT PRIMARY KEY,
          operation_type TEXT CHECK(operation_type IN ('SUBMISSION', 'VOTE')),
          encrypted_payload TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          checksum TEXT NOT NULL
        );
      `);
            dbInstance = db;
            return db;
        })();
    }
    return dbInitPromise;
}
function resetOfflineDatabaseInstance() {
    dbInstance = null;
    dbInitPromise = null;
}
/**
 * 3. CRYPTOGRAPHIC CHECK-BEFORE-COMMIT (CBC) VALIDATION
 * Scans all entries on boot, validating checksum integrity.
 * If any fragmented or un-committed write boundaries are found, rolls back that portion.
 */
async function executeCheckBeforeCommitValidation() {
    const db = await getOfflineDatabase();
    const key = await (0, outboxEncryption_1.getOrCreateOutboxKey)();
    const rows = await db.getAllAsync("SELECT * FROM offline_outbox");
    let corruptedCount = 0;
    for (const row of rows) {
        const calculated = fnv1aChecksum(row.id + row.encrypted_payload + key);
        if (row.checksum !== calculated) {
            corruptedCount++;
            // Rollback pointers / delete corrupted segment
            await db.runAsync("DELETE FROM offline_outbox WHERE id = ?", [row.id]);
            console.warn(`[CBC ROLLBACK] Fragmented or corrupt write boundary detected on record: ${row.id}. Evicted.`);
        }
    }
    return corruptedCount;
}
/**
 * 4. FIFO EVICTION LOGIC
 * Keeps total database characters below 50MB ceiling limit.
 */
exports.STORAGE_CEILING_CHARS = 50 * 1024 * 1024; // 50MB in characters
function setStorageCeilingChars(limit) {
    exports.STORAGE_CEILING_CHARS = limit;
}
async function enforceFifoEviction(db) {
    const rows = await db.getAllAsync("SELECT id, LENGTH(encrypted_payload) as payload_len FROM offline_outbox ORDER BY created_at ASC");
    let currentTotal = rows.reduce((sum, row) => sum + row.payload_len, 0);
    if (currentTotal > exports.STORAGE_CEILING_CHARS) {
        console.warn(`[FIFO EVICTION] Total outbox payload size ${currentTotal} exceeds 50MB ceiling. Enforcing FIFO rules.`);
        for (const row of rows) {
            if (currentTotal <= exports.STORAGE_CEILING_CHARS)
                break;
            await db.runAsync("DELETE FROM offline_outbox WHERE id = ?", [row.id]);
            currentTotal -= row.payload_len;
            console.log(`[FIFO EVICTION] Evicted record: ${row.id}`);
        }
    }
}
/**
 * Encrypts and queues a new offline operation.
 */
async function queueOfflineOperation(id, operationType, rawPayload) {
    const db = await getOfflineDatabase();
    const key = await (0, outboxEncryption_1.getOrCreateOutboxKey)();
    const plainJson = JSON.stringify(rawPayload);
    const encryptedPayload = (0, outboxEncryption_1.encryptPayload)(plainJson, key);
    const createdAt = Date.now();
    const checksum = fnv1aChecksum(id + encryptedPayload + key);
    await db.withTransactionAsync(async () => {
        await db.runAsync(`INSERT OR REPLACE INTO offline_outbox (id, operation_type, encrypted_payload, created_at, checksum)
       VALUES (?, ?, ?, ?, ?)`, [id, operationType, encryptedPayload, createdAt, checksum]);
        await enforceFifoEviction(db);
    });
}
/**
 * Decrypts and retrieves all queued operations.
 */
async function getQueuedOperations() {
    const db = await getOfflineDatabase();
    const key = await (0, outboxEncryption_1.getOrCreateOutboxKey)();
    const rows = await db.getAllAsync("SELECT * FROM offline_outbox ORDER BY created_at ASC");
    const result = [];
    for (const row of rows) {
        try {
            const decrypted = (0, outboxEncryption_1.decryptPayload)(row.encrypted_payload, key);
            result.push({
                id: row.id,
                operationType: row.operation_type,
                payload: JSON.parse(decrypted),
                createdAt: row.created_at
            });
        }
        catch (err) {
            // Discard un-decryptable/corrupt row safely
            console.error(`[DECRYPTION FAILED] Failed to decrypt row ${row.id}:`, err);
        }
    }
    return result;
}
/**
 * Deletes a completed operation from outbox.
 */
async function deleteOfflineOperation(id) {
    const db = await getOfflineDatabase();
    await db.runAsync("DELETE FROM offline_outbox WHERE id = ?", [id]);
}
