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

// Mock the expo-sqlite module virtually
jest.mock(
  "expo-sqlite",
  () => {
    return {
      openDatabaseAsync: async () => {
        activeMockDb = new MockSQLiteDatabase();
        return activeMockDb;
      }
    };
  },
  { virtual: true }
);

// Mock expo-background-fetch and expo-task-manager virtually
jest.mock(
  "expo-background-fetch",
  () => {
    return {
      BackgroundFetchResult: {
        NewData: 1,
        NoData: 2,
        Failed: 3
      },
      registerTaskAsync: jest.fn()
    };
  },
  { virtual: true }
);

jest.mock(
  "expo-task-manager",
  () => {
    return {
      defineTask: jest.fn(),
      isTaskRegisteredAsync: jest.fn().mockResolvedValue(false)
    };
  },
  { virtual: true }
);

// Mock react-native AppState
let appStateChangeCallback: ((state: string) => void) | null = null;
jest.mock(
  "react-native",
  () => {
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
  },
  { virtual: true }
);

// Mock voucherStripper
jest.mock(
  "../../wallet/voucherStripper",
  () => {
    return {
      unblindSignedVoucher: jest.fn((sig) => sig)
    };
  },
  { virtual: true }
);

import { runSyncLoop, padPayload, resetSyncWorkerState } from "../syncWorker";
import { queueToken, getDatabase, resetDatabaseInstance, getOutboxEntry } from "../outboxManager";

const mockFetch = jest.fn();
global.fetch = mockFetch as any;

describe("Time-Masked Background Synchronization Worker Tests", () => {
  beforeEach(async () => {
    resetSyncWorkerState();
    resetDatabaseInstance();
    mockFetch.mockReset();
    await getDatabase();
  });

  afterEach(async () => {
    if (activeMockDb) {
      await activeMockDb.close();
      activeMockDb = null;
    }
  });

  it("should verify padPayload outputs exactly 2048 bytes for various structures", () => {
    const payload1 = { message: "test" };
    const padded1 = padPayload(payload1, 2048);
    expect(padded1.length).toBe(2048);

    const parsed1 = JSON.parse(padded1);
    expect(parsed1.payload.message).toBe("test");
    expect(parsed1.padding).toBeDefined();

    const payload2 = { test: 123, list: [1, 2, 3] };
    const padded2 = padPayload(payload2, 2048);
    expect(padded2.length).toBe(2048);
  });

  it("should process PENDING_BLINDING tokens, transitioning to UNBLINDED on success", async () => {
    await queueToken("t-1", "AUTH_TOKEN", "42", "12345", "blinded-T-1");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ signed_blinded_token: "987654321" })
    });

    const success = await runSyncLoop();
    expect(success).toBe(true);

    const entry = await getOutboxEntry("t-1");
    expect(entry?.state).toBe("UNBLINDED");
    expect(entry?.unblinded_signature_S).toBe("987654321");
    expect(entry?.blind_factor_r).toBeNull(); // Zeroed
  });

  it("should handle sync execution failures with automatic database state rollbacks", async () => {
    await queueToken("t-2", "AUTH_TOKEN", "42", "12345", "blinded-T-2");

    // Mock network failure
    mockFetch.mockRejectedValueOnce(new Error("Connection timeout"));

    const success = await runSyncLoop();
    // Engine catches error and returns false
    expect(success).toBe(false);

    // Database record state must be rolled back to PENDING_BLINDING
    const entry = await getOutboxEntry("t-2");
    expect(entry?.state).toBe("PENDING_BLINDING");
    expect(entry?.blind_factor_r).toBe("12345");
  });

  it("should aggressively freeze execution and throw if app transitions to background during execution", async () => {
    await queueToken("t-3", "AUTH_TOKEN", "42", "12345", "blinded-T-3");

    // Transition AppState to background
    if (appStateChangeCallback) {
      appStateChangeCallback("background");
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ signed_blinded_token: "9999" })
    });

    const success = await runSyncLoop();
    expect(success).toBe(false);

    // Verify record state remained unchanged
    const entry = await getOutboxEntry("t-3");
    expect(entry?.state).toBe("PENDING_BLINDING");

    // Transition AppState back to active
    if (appStateChangeCallback) {
      appStateChangeCallback("active");
    }
  });
});
