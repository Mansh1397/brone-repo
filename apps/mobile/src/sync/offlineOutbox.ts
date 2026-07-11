import * as SQLite from "expo-sqlite";
import { getOrCreateOutboxKey, encryptPayload, decryptPayload } from "./outboxEncryption";

// Custom lightweight checksum function (FNV-1a)
export function fnv1aChecksum(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    // Integer multiplication simulation
    hash = (hash * 0x01000193) | 0;
  }
  return (hash >>> 0).toString(16);
}

// Database row structure
export interface DbOfflineOperation {
  id: string;
  operation_type: "SUBMISSION" | "VOTE";
  encrypted_payload: string;
  created_at: number;
  checksum: string;
}

let dbInstance: SQLite.SQLiteDatabase | null = null;
let dbInitPromise: Promise<SQLite.SQLiteDatabase> | null = null;

export function getOfflineDatabase(): Promise<SQLite.SQLiteDatabase> {
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

export function resetOfflineDatabaseInstance(): void {
  dbInstance = null;
  dbInitPromise = null;
}

/**
 * 3. CRYPTOGRAPHIC CHECK-BEFORE-COMMIT (CBC) VALIDATION
 * Scans all entries on boot, validating checksum integrity.
 * If any fragmented or un-committed write boundaries are found, rolls back that portion.
 */
export async function executeCheckBeforeCommitValidation(): Promise<number> {
  const db = await getOfflineDatabase();
  const key = await getOrCreateOutboxKey();

  const rows = await db.getAllAsync<DbOfflineOperation>("SELECT * FROM offline_outbox");
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
export let STORAGE_CEILING_CHARS = 50 * 1024 * 1024; // 50MB in characters

export function setStorageCeilingChars(limit: number): void {
  STORAGE_CEILING_CHARS = limit;
}

async function enforceFifoEviction(db: SQLite.SQLiteDatabase): Promise<void> {
  const rows = await db.getAllAsync<{ id: string; payload_len: number }>(
    "SELECT id, LENGTH(encrypted_payload) as payload_len FROM offline_outbox ORDER BY created_at ASC"
  );

  let currentTotal = rows.reduce((sum, row) => sum + row.payload_len, 0);

  if (currentTotal > STORAGE_CEILING_CHARS) {
    console.warn(`[FIFO EVICTION] Total outbox payload size ${currentTotal} exceeds 50MB ceiling. Enforcing FIFO rules.`);
    for (const row of rows) {
      if (currentTotal <= STORAGE_CEILING_CHARS) break;
      await db.runAsync("DELETE FROM offline_outbox WHERE id = ?", [row.id]);
      currentTotal -= row.payload_len;
      console.log(`[FIFO EVICTION] Evicted record: ${row.id}`);
    }
  }
}

/**
 * Encrypts and queues a new offline operation.
 */
export async function queueOfflineOperation(
  id: string,
  operationType: "SUBMISSION" | "VOTE",
  rawPayload: Record<string, any>
): Promise<void> {
  const db = await getOfflineDatabase();
  const key = await getOrCreateOutboxKey();

  const plainJson = JSON.stringify(rawPayload);
  const encryptedPayload = encryptPayload(plainJson, key);
  const createdAt = Date.now();
  const checksum = fnv1aChecksum(id + encryptedPayload + key);

  await db.withTransactionAsync(async () => {
    await db.runAsync(
      `INSERT OR REPLACE INTO offline_outbox (id, operation_type, encrypted_payload, created_at, checksum)
       VALUES (?, ?, ?, ?, ?)`,
      [id, operationType, encryptedPayload, createdAt, checksum]
    );
    await enforceFifoEviction(db);
  });
}

/**
 * Decrypts and retrieves all queued operations.
 */
export async function getQueuedOperations(): Promise<{ id: string; operationType: "SUBMISSION" | "VOTE"; payload: Record<string, any>; createdAt: number }[]> {
  const db = await getOfflineDatabase();
  const key = await getOrCreateOutboxKey();

  const rows = await db.getAllAsync<DbOfflineOperation>("SELECT * FROM offline_outbox ORDER BY created_at ASC");
  const result: any[] = [];

  for (const row of rows) {
    try {
      const decrypted = decryptPayload(row.encrypted_payload, key);
      result.push({
        id: row.id,
        operationType: row.operation_type,
        payload: JSON.parse(decrypted),
        createdAt: row.created_at
      });
    } catch (err) {
      // Discard un-decryptable/corrupt row safely
      console.error(`[DECRYPTION FAILED] Failed to decrypt row ${row.id}:`, err);
    }
  }

  return result;
}

/**
 * Deletes a completed operation from outbox.
 */
export async function deleteOfflineOperation(id: string): Promise<void> {
  const db = await getOfflineDatabase();
  await db.runAsync("DELETE FROM offline_outbox WHERE id = ?", [id]);
}
