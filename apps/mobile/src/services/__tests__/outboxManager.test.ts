import * as sqlite3 from "sqlite3";

// Create the in-memory SQLite wrapper mocking expo-sqlite
class MockSQLiteDatabase {
  private db: sqlite3.Database;

  constructor() {
    this.db = new sqlite3.Database(":memory:");
  }

  async execAsync(sql: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.exec(sql, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async runAsync(sql: string, params: any[] = []): Promise<{ lastInsertRowId: number; changes: number }> {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve({ lastInsertRowId: this.lastID, changes: this.changes });
      });
    });
  }

  async getAllAsync<T>(sql: string, params: any[] = []): Promise<T[]> {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows as T[]);
      });
    });
  }

  async getFirstAsync<T>(sql: string, params: any[] = []): Promise<T | null> {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve((row as T) || null);
      });
    });
  }

  async withTransactionAsync(callback: () => Promise<void>): Promise<void> {
    await this.execAsync("BEGIN TRANSACTION");
    try {
      await callback();
      await this.execAsync("COMMIT");
    } catch (err) {
      await this.execAsync("ROLLBACK");
      throw err;
    }
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

let activeMockDb: MockSQLiteDatabase | null = null;
let openCount = 0;

// Mock the expo-sqlite module virtually
jest.mock(
  "expo-sqlite",
  () => {
    return {
      openDatabaseAsync: async () => {
        openCount++;
        activeMockDb = new MockSQLiteDatabase();
        return activeMockDb;
      }
    };
  },
  { virtual: true }
);

// Import the outbox manager under test
import {
  getDatabase,
  resetDatabaseInstance,
  queueToken,
  transitionToBlindedSent,
  transitionToUnblinded,
  transitionToRedemptionSent,
  transitionToSpent,
  getPendingTokens,
  getOutboxEntry
} from "../outboxManager";

describe("Write-Ahead Offline Outbox Database Service Tests", () => {
  beforeEach(async () => {
    resetDatabaseInstance();
    openCount = 0;
    // Force a fresh database instantiation in memory for each test
    await getDatabase();
  });

  afterEach(async () => {
    if (activeMockDb) {
      await activeMockDb.close();
      activeMockDb = null;
    }
  });

  it("should initialize database table structure correctly and enforce CHECK constraints", async () => {
    const db = await getDatabase();

    // Verify valid insertion succeeds
    await expect(
      queueToken("t-1", "AUTH_TOKEN", "raw-msg-1", "r-factor-1", "blinded-T-1")
    ).resolves.not.toThrow();

    // Verify CHECK constraint on token_type
    await expect(
      db.runAsync(
        "INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('t-2', 'INVALID_TYPE', 'PENDING_BLINDING', 'raw-msg-2')"
      )
    ).rejects.toThrow();

    // Verify CHECK constraint on state
    await expect(
      db.runAsync(
        "INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('t-3', 'AUTH_TOKEN', 'INVALID_STATE', 'raw-msg-3')"
      )
    ).rejects.toThrow();
  });

  it("should enforce UNIQUE constraint on raw_message_x", async () => {
    // Insert first token
    await queueToken("t-1", "AUTH_TOKEN", "raw-msg-duplicate", "r-1", "T-1");

    // Attempt duplicate insertion on raw_message_x
    await expect(
      queueToken("t-2", "AUTH_TOKEN", "raw-msg-duplicate", "r-2", "T-2")
    ).rejects.toThrow();
  });

  it("should successfully execute offline token state transition flows", async () => {
    const id = "token-voucher-77";
    await queueToken(id, "REWARD_VOUCHER", "x-value-77", "r-value-77", "T-value-77");

    // 1. Initial State Check
    let entry = await getOutboxEntry(id);
    expect(entry).not.toBeNull();
    expect(entry?.state).toBe("PENDING_BLINDING");
    expect(entry?.blind_factor_r).toBe("r-value-77");
    expect(entry?.retry_count).toBe(0);

    // 2. Transition to BLINDED_SENT
    await transitionToBlindedSent(id);
    entry = await getOutboxEntry(id);
    expect(entry?.state).toBe("BLINDED_SENT");
    expect(entry?.last_attempted_at).toBeGreaterThan(0);

    // 3. Transition to UNBLINDED - Must verify zeroization of blind_factor_r
    await transitionToUnblinded(id, "S-prime-77", "S-signature-77");
    entry = await getOutboxEntry(id);
    expect(entry?.state).toBe("UNBLINDED");
    expect(entry?.blind_factor_r).toBeNull(); // Strict zeroization verification
    expect(entry?.signed_blinded_token_S_prime).toBe("S-prime-77");
    expect(entry?.unblinded_signature_S).toBe("S-signature-77");

    // 4. Transition to REDEMPTION_SENT
    await transitionToRedemptionSent(id);
    entry = await getOutboxEntry(id);
    expect(entry?.state).toBe("REDEMPTION_SENT");
    expect(entry?.retry_count).toBe(1);

    // 5. Transition to SPENT
    await transitionToSpent(id);
    entry = await getOutboxEntry(id);
    expect(entry?.state).toBe("SPENT");

    // 6. Verify it is no longer returned in pending tokens
    const pending = await getPendingTokens();
    expect(pending.find(p => p.id === id)).toBeUndefined();
  });

  it("should guarantee atomic rollback during transaction failures", async () => {
    const db = await getDatabase();

    // Trigger atomic transaction execution failure inside transaction
    await expect(
      db.withTransactionAsync(async () => {
        // This query is valid
        await db.runAsync(
          "INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('tx-1', 'AUTH_TOKEN', 'PENDING_BLINDING', 'raw-tx-1')"
        );
        // This query will fail CHECK constraint, triggering an error
        await db.runAsync(
          "INSERT INTO local_token_outbox (id, token_type, state, raw_message_x) VALUES ('tx-2', 'INVALID_TYPE', 'PENDING_BLINDING', 'raw-tx-2')"
        );
      })
    ).rejects.toThrow();

    // Verify that the first query 'tx-1' was rolled back successfully
    const entry = await getOutboxEntry("tx-1");
    expect(entry).toBeNull();
  });

  it("should enforce a strict Singleton connection pattern and prevent concurrent open call leaks", async () => {
    resetDatabaseInstance();
    openCount = 0;

    // Fire multiple concurrent database retrieval calls
    const promises = [getDatabase(), getDatabase(), getDatabase()];
    const dbs = await Promise.all(promises);

    // Verify all resolved databases are the exact same instance
    expect(dbs[0]).toBe(dbs[1]);
    expect(dbs[1]).toBe(dbs[2]);

    // Verify openDatabaseAsync was only invoked exactly once
    expect(openCount).toBe(1);
  });
});
