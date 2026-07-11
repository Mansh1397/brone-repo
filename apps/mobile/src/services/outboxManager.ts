import * as SQLite from "expo-sqlite";

export interface TokenOutboxEntry {
  id: string;
  token_type: "AUTH_TOKEN" | "REWARD_VOUCHER";
  state: "PENDING_BLINDING" | "BLINDED_SENT" | "UNBLINDED" | "REDEMPTION_SENT" | "SPENT";
  blind_factor_r: string | null;
  raw_message_x: string;
  blinded_message_T: string | null;
  signed_blinded_token_S_prime: string | null;
  unblinded_signature_S: string | null;
  retry_count: number;
  last_attempted_at: number | null;
}

let dbInstance: SQLite.SQLiteDatabase | null = null;
let dbInitPromise: Promise<SQLite.SQLiteDatabase> | null = null;

/**
 * Initializes and retrieves the database connection.
 * Enforces a strict Singleton connection pattern using a shared Promise
 * to prevent duplicate native open calls and file descriptor leaks under concurrency.
 */
export function getDatabase(): Promise<SQLite.SQLiteDatabase> {
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
export function resetDatabaseInstance() {
  dbInstance = null;
  dbInitPromise = null;
}

/**
 * Queues a new token in PENDING_BLINDING state.
 */
export async function queueToken(
  id: string,
  tokenType: "AUTH_TOKEN" | "REWARD_VOUCHER",
  rawMessageX: string,
  blindFactorR: string,
  blindedMessageT: string
): Promise<void> {
  const db = await getDatabase();
  await db.withTransactionAsync(async () => {
    await db.runAsync(
      `INSERT INTO local_token_outbox (
        id, token_type, state, blind_factor_r, raw_message_x, blinded_message_T, retry_count
      ) VALUES (?, ?, 'PENDING_BLINDING', ?, ?, ?, 0)`,
      [id, tokenType, blindFactorR, rawMessageX, blindedMessageT]
    );
  });
}

/**
 * Staging token record inside the outbox ledger. Alias wrapper for queueToken.
 */
export async function stageTokenRecord(
  id: string,
  tokenType: "AUTH_TOKEN" | "REWARD_VOUCHER",
  rawMessageX: string,
  blindFactorR: string,
  blindedMessageT: string
): Promise<void> {
  return queueToken(id, tokenType, rawMessageX, blindFactorR, blindedMessageT);
}

/**
 * Transition to BLINDED_SENT state.
 */
export async function transitionToBlindedSent(id: string): Promise<void> {
  const db = await getDatabase();
  await db.withTransactionAsync(async () => {
    await db.runAsync(
      "UPDATE local_token_outbox SET state = 'BLINDED_SENT', last_attempted_at = ? WHERE id = ?",
      [Date.now(), id]
    );
  });
}

/**
 * Transition to UNBLINDED state and zeroizes the blinding factor 'r' to prevent key-leakage.
 */
export async function transitionToUnblinded(
  id: string,
  signedBlindedTokenSPrime: string,
  unblindedSignatureS: string
): Promise<void> {
  const db = await getDatabase();
  await db.withTransactionAsync(async () => {
    await db.runAsync(
      `UPDATE local_token_outbox 
       SET state = 'UNBLINDED', 
           blind_factor_r = NULL, 
           signed_blinded_token_S_prime = ?, 
           unblinded_signature_S = ?, 
           last_attempted_at = ? 
       WHERE id = ?`,
      [signedBlindedTokenSPrime, unblindedSignatureS, Date.now(), id]
    );
  });
}

/**
 * Transition to REDEMPTION_SENT state, updating retry count and timestamp.
 */
export async function transitionToRedemptionSent(id: string): Promise<void> {
  const db = await getDatabase();
  await db.withTransactionAsync(async () => {
    await db.runAsync(
      `UPDATE local_token_outbox 
       SET state = 'REDEMPTION_SENT', 
           retry_count = retry_count + 1, 
           last_attempted_at = ? 
       WHERE id = ?`,
      [Date.now(), id]
    );
  });
}

/**
 * Transition to SPENT state.
 */
export async function transitionToSpent(id: string): Promise<void> {
  const db = await getDatabase();
  await db.withTransactionAsync(async () => {
    await db.runAsync(
      "UPDATE local_token_outbox SET state = 'SPENT', last_attempted_at = ? WHERE id = ?",
      [Date.now(), id]
    );
  });
}

/**
 * Retrieves all pending (non-SPENT) tokens.
 */
export async function getPendingTokens(): Promise<TokenOutboxEntry[]> {
  const db = await getDatabase();
  const rows = await db.getAllAsync<TokenOutboxEntry>(
    "SELECT * FROM local_token_outbox WHERE state != 'SPENT'"
  );
  return rows;
}

/**
 * Retrieves a specific token by its ID.
 */
export async function getOutboxEntry(id: string): Promise<TokenOutboxEntry | null> {
  const db = await getDatabase();
  const entry = await db.getFirstAsync<TokenOutboxEntry>(
    "SELECT * FROM local_token_outbox WHERE id = ?",
    [id]
  );
  return entry;
}
