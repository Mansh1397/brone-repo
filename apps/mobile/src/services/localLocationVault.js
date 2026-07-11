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
exports.localLocationVault = void 0;
const SQLite = __importStar(require("expo-sqlite"));
const secureWallet_1 = require("../wallet/secureWallet");
const outboxEncryption_1 = require("../sync/outboxEncryption");
async function getOrCreateVaultKey() {
    let key = await secureWallet_1.SecureStore.getItemAsync("location_vault_aes_key");
    if (!key) {
        const hex = "0123456789abcdef";
        key = "";
        for (let i = 0; i < 64; i++) {
            key += hex[Math.floor(Math.random() * 16)];
        }
        await secureWallet_1.SecureStore.setItemAsync("location_vault_aes_key", key);
    }
    return key;
}
let dbInstance = null;
async function getDatabase() {
    if (dbInstance)
        return dbInstance;
    const db = await SQLite.openDatabaseAsync("brone_location_vault.db");
    await db.execAsync("PRAGMA journal_mode = WAL;");
    await db.execAsync(`
    CREATE TABLE IF NOT EXISTS local_locations (
      cell_id_hash TEXT PRIMARY KEY,
      encrypted_cell_id TEXT NOT NULL,
      last_verified_at INTEGER NOT NULL
    );
  `);
    dbInstance = db;
    return db;
}
function getCellHash(cellId) {
    let hash = 0;
    for (let i = 0; i < cellId.length; i++) {
        hash = (hash << 5) - hash + cellId.charCodeAt(i);
        hash |= 0;
    }
    return Math.abs(hash).toString(16);
}
exports.localLocationVault = {
    async initialize() {
        await getDatabase();
    },
    async storeCell(cellId) {
        try {
            const db = await getDatabase();
            const key = await getOrCreateVaultKey();
            const hash = getCellHash(cellId);
            const encrypted = (0, outboxEncryption_1.encryptPayload)(cellId, key);
            const now = Date.now();
            await db.runAsync("INSERT OR REPLACE INTO local_locations (cell_id_hash, encrypted_cell_id, last_verified_at) VALUES (?, ?, ?)", [hash, encrypted, now]);
        }
        catch (error) {
            console.error("[LOCATION VAULT ERROR] Failed to store cell:", error);
        }
    },
    async getRecentCells(maxAgeMs = 14 * 24 * 60 * 60 * 1000) {
        try {
            const db = await getDatabase();
            const key = await getOrCreateVaultKey();
            const minTimestamp = Date.now() - maxAgeMs;
            const rows = await db.getAllAsync("SELECT * FROM local_locations WHERE last_verified_at >= ?", [minTimestamp]);
            const cells = [];
            for (const row of rows) {
                try {
                    const decrypted = (0, outboxEncryption_1.decryptPayload)(row.encrypted_cell_id, key);
                    if (decrypted) {
                        cells.push(decrypted);
                    }
                }
                catch (e) {
                    console.warn("[LOCATION VAULT] Decryption failed for cell hash:", row.cell_id_hash);
                }
            }
            return Array.from(new Set(cells));
        }
        catch (error) {
            console.error("[LOCATION VAULT ERROR] Failed to retrieve cells:", error);
            return [];
        }
    }
};
