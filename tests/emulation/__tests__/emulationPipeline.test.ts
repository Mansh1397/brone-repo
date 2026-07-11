import * as sqlite3 from "sqlite3";

// 1. Mock expo-sqlite with in-memory sqlite3 database
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

jest.mock(
  "expo-sqlite",
  () => {
    return {
      openDatabaseAsync: async () => {
        return new MockSQLiteDatabase();
      }
    };
  },
  { virtual: true }
);

jest.mock(
  "react-native",
  () => ({
    NativeModules: {
      ExpoSecureStore: {}
    }
  }),
  { virtual: true }
);

import { ChaosInjector } from "../chaosInjector";
import { LogAnalyzer } from "../logAnalyzer";
import { getQueuedOperations, resetOfflineDatabaseInstance } from "../../../apps/mobile/src/sync/offlineOutbox";
import { rollbackGuard } from "../../../apps/mobile/src/sync/rollbackGuard";
import { secureWalletManager } from "../../../apps/mobile/src/wallet/secureWallet";

// Mock global fetch for chaos test endpoint interactions
const mockFetch = jest.fn();
global.fetch = mockFetch as any;

describe("End-to-End Local Emulation & Automated Chaos Injection Pipeline (Phase 9, Version 9.1)", () => {
  beforeEach(async () => {
    resetOfflineDatabaseInstance();
    rollbackGuard.resetGuard();
    secureWalletManager.resetLedger();
    mockFetch.mockReset();
    
    await secureWalletManager.initializeWallet();
  });

  it("should run full chaos lifecycle, verify isolated proxy read-only fallback, latency jitter, and metrics parsing", async () => {
    const config = {
      asiaProxyUrl: "http://localhost:3001",
      usProxyUrl: "http://localhost:3002",
      networkName: "brone-net",
      asiaContainerName: "proxy-region-asia"
    };

    const injector = new ChaosInjector(config);

    // 1. Monitor traffic until baseline of 1000 processed ops is achieved
    const totalOps = await injector.monitorUntilBaseline(1000);
    expect(totalOps).toBeGreaterThanOrEqual(1000);

    // 2. Mock network split simulation route response (returns unhealthy status)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ success: true, isQuorumHealthy: false })
    });

    await injector.injectNetworkSplitPartition();

    // 3. Mock 503 response on task validation to assert read-only fallback logic
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({ error: "System is in read-only recovery fallback due to quorum loss" })
    });

    const isSuccess = await injector.verifyRecoveryAndIsolation("task-split-01");
    expect(isSuccess).toBe(true);

    // Verify task was written to offline outbox cache
    const queued = await getQueuedOperations();
    expect(queued).toHaveLength(1);
    expect(queued[0].id).toBe("task-split-01");

    // 4. Run latency jitter simulation (10 loops)
    const latencies = await injector.runLatencyJitterTest(10);
    expect(latencies).toHaveLength(10);
    latencies.forEach(lat => {
      expect(lat).toBeGreaterThanOrEqual(500);
    });

    // 5. LogAnalyzer assertions
    const noOOM = LogAnalyzer.assertNoOOMKilled(["proxy-region-asia", "proxy-region-us"]);
    expect(noOOM).toBe(true);

    const integrity = await LogAnalyzer.assertReconciliationIntegrity();
    expect(integrity).toBe(true);

    // 6. Generate final matrix report
    const matrix = LogAnalyzer.generateSuccessMatrixReport({
      totalProcessed: totalOps,
      shortCircuitSavingsMs: 3450,
      tokenValidationAccuracy: 0.9998
    });
    
    expect(matrix).toContain("BRONE SYSTEM EMULATION MATRIX");
    expect(matrix).toContain("Container OOM Evictions      : 0");
  }, 60000);
});
