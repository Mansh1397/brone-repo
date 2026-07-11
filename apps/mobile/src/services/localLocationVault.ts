import * as SQLite from "expo-sqlite";
import { SecureStore } from "../wallet/secureWallet";
import { encryptPayload, decryptPayload } from "../sync/outboxEncryption";
async function getOrCreateVaultKey(): Promise<string> {
  let key = await SecureStore.getItemAsync("location_vault_aes_key");
  if (!key) {
    const hex = "0123456789abcdef";
    key = "";
    for (let i = 0; i < 64; i++) {
      key += hex[Math.floor(Math.random() * 16)];
    }
    await SecureStore.setItemAsync("location_vault_aes_key", key);
  }
  return key;
}
let dbInstance: SQLite.SQLiteDatabase | null = null;
async function getDatabase(): Promise<SQLite.SQLiteDatabase> {
  if (dbInstance) return dbInstance;
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
function getCellHash(cellId: string): string {
  let hash = 0;
  for (let i = 0; i < cellId.length; i++) {
    hash = (hash << 5) - hash + cellId.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(16);
}
export const localLocationVault = {
  async initialize(): Promise<void> {
    await getDatabase();
  },
  async storeCell(cellId: string): Promise<void> {
    try {
      const db = await getDatabase();
      const key = await getOrCreateVaultKey();
      const hash = getCellHash(cellId);
      const encrypted = encryptPayload(cellId, key);
      const now = Date.now();
      await db.runAsync(
        "INSERT OR REPLACE INTO local_locations (cell_id_hash, encrypted_cell_id, last_verified_at) VALUES (?, ?, ?)",
        [hash, encrypted, now]
      );
    } catch (error) {
      console.error("[LOCATION VAULT ERROR] Failed to store cell:", error);
    }
  },
  async getRecentCells(maxAgeMs: number = 14 * 24 * 60 * 60 * 1000): Promise<string[]> {
    try {
      const db = await getDatabase();
      const key = await getOrCreateVaultKey();
      const minTimestamp = Date.now() - maxAgeMs;
      const rows = await db.getAllAsync<{ cell_id_hash: string; encrypted_cell_id: string; last_verified_at: number }>(
        "SELECT * FROM local_locations WHERE last_verified_at >= ?",
        [minTimestamp]
      );
      const cells: string[] = [];
      for (const row of rows) {
        try {
          const decrypted = decryptPayload(row.encrypted_cell_id, key);
          if (decrypted) {
            cells.push(decrypted);
          }
        } catch (e) {
          console.warn("[LOCATION VAULT] Decryption failed for cell hash:", row.cell_id_hash);
        }
      }
      return Array.from(new Set(cells));
    } catch (error) {
      console.error("[LOCATION VAULT ERROR] Failed to retrieve cells:", error);
      return [];
    }
  }
};
