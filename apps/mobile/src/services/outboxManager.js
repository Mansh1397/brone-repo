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
exports.getDatabase = getDatabase;
exports.resetDatabaseInstance = resetDatabaseInstance;
exports.queueToken = queueToken;
exports.stageTokenRecord = stageTokenRecord;
exports.transitionToBlindedSent = transitionToBlindedSent;
exports.transitionToUnblinded = transitionToUnblinded;
exports.transitionToRedemptionSent = transitionToRedemptionSent;
exports.transitionToSpent = transitionToSpent;
exports.getPendingTokens = getPendingTokens;
exports.getOutboxEntry = getOutboxEntry;
const SQLite = __importStar(require("expo-sqlite"));
let dbInstance = null;
let dbInitPromise = null;
/**
 * Initializes and retrieves the database connection.
 * Enforces a strict Singleton connection pattern using a shared Promise
 * to prevent duplicate native open calls and file descriptor leaks under concurrency.
 */
function getDatabase() {
    if (dbInstance) {
        return Promise.resolve(dbInstance);
    }
    if (!dbInitPromise) {
        dbInitPromise = (async () => {
            const db = await SQLite.openDatabaseAsync("brone_outbox.db");
            // Execute strict schema creation query
            await db.execAsync(`
        CREATE TABLE IF NOT EXISTS local_token_outbox (
          id TEXT PRIMARY KEY,
          token_type TEXT CHECK(token_type IN ('AUTH_TOKEN', 'REWARD_VOUCHER')),
          state TEXT CHECK(state IN ('PENDING_BLINDING', 'BLINDED_SENT', 'UNBLINDED', 'REDEMPTION_SENT', 'SPENT')),
          blind_factor_r TEXT,
          raw_message_x TEXT UNIQUE,
          blinded_message_T TEXT,
          signed_blinded_token_S_prime TEXT,
          unblinded_signature_S TEXT,
          retry_count INTEGER DEFAULT 0,
          last_attempted_at INTEGER
        );
      `);
            dbInstance = db;
            return db;
        })();
    }
    return dbInitPromise;
}
/**
 * Clears the active database instance and initialization promise.
 * Useful for clean testing environments.
 */
function resetDatabaseInstance() {
    dbInstance = null;
    dbInitPromise = null;
}
/**
 * Queues a new token in PENDING_BLINDING state.
 */
async function queueToken(id, tokenType, rawMessageX, blindFactorR, blindedMessageT) {
    const db = await getDatabase();
    await db.withTransactionAsync(async () => {
        await db.runAsync(`INSERT INTO local_token_outbox (
        id, token_type, state, blind_factor_r, raw_message_x, blinded_message_T, retry_count
      ) VALUES (?, ?, 'PENDING_BLINDING', ?, ?, ?, 0)`, [id, tokenType, blindFactorR, rawMessageX, blindedMessageT]);
    });
}
/**
 * Staging token record inside the outbox ledger. Alias wrapper for queueToken.
 */
async function stageTokenRecord(id, tokenType, rawMessageX, blindFactorR, blindedMessageT) {
    return queueToken(id, tokenType, rawMessageX, blindFactorR, blindedMessageT);
}
/**
 * Transition to BLINDED_SENT state.
 */
async function transitionToBlindedSent(id) {
    const db = await getDatabase();
    await db.withTransactionAsync(async () => {
        await db.runAsync("UPDATE local_token_outbox SET state = 'BLINDED_SENT', last_attempted_at = ? WHERE id = ?", [Date.now(), id]);
    });
}
/**
 * Transition to UNBLINDED state and zeroizes the blinding factor 'r' to prevent key-leakage.
 */
async function transitionToUnblinded(id, signedBlindedTokenSPrime, unblindedSignatureS) {
    const db = await getDatabase();
    await db.withTransactionAsync(async () => {
        await db.runAsync(`UPDATE local_token_outbox 
       SET state = 'UNBLINDED', 
           blind_factor_r = NULL, 
           signed_blinded_token_S_prime = ?, 
           unblinded_signature_S = ?, 
           last_attempted_at = ? 
       WHERE id = ?`, [signedBlindedTokenSPrime, unblindedSignatureS, Date.now(), id]);
    });
}
/**
 * Transition to REDEMPTION_SENT state, updating retry count and timestamp.
 */
async function transitionToRedemptionSent(id) {
    const db = await getDatabase();
    await db.withTransactionAsync(async () => {
        await db.runAsync(`UPDATE local_token_outbox 
       SET state = 'REDEMPTION_SENT', 
           retry_count = retry_count + 1, 
           last_attempted_at = ? 
       WHERE id = ?`, [Date.now(), id]);
    });
}
/**
 * Transition to SPENT state.
 */
async function transitionToSpent(id) {
    const db = await getDatabase();
    await db.withTransactionAsync(async () => {
        await db.runAsync("UPDATE local_token_outbox SET state = 'SPENT', last_attempted_at = ? WHERE id = ?", [Date.now(), id]);
    });
}
/**
 * Retrieves all pending (non-SPENT) tokens.
 */
async function getPendingTokens() {
    const db = await getDatabase();
    const rows = await db.getAllAsync("SELECT * FROM local_token_outbox WHERE state != 'SPENT'");
    return rows;
}
/**
 * Retrieves a specific token by its ID.
 */
async function getOutboxEntry(id) {
    const db = await getDatabase();
    const entry = await db.getFirstAsync("SELECT * FROM local_token_outbox WHERE id = ?", [id]);
    return entry;
}
