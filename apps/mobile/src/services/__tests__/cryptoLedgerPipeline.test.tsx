/** @jest-environment jsdom */
import React from "react";
import * as sqlite3 from "sqlite3";
import { render } from "@testing-library/react";

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
  () => {
    const React = require("react");
    const View = React.forwardRef(({ children, style, testID, ...props }: any, ref: any) =>
      React.createElement("div", { ...props, ref, style, "data-testid": testID }, children)
    );
    const Text = ({ children, style, testID, ...props }: any) =>
      React.createElement("span", { ...props, style, "data-testid": testID }, children);
    return {
      View,
      Text,
      StyleSheet: {
        create: (styles: any) => styles
      },
      NativeModules: {
        ExpoSecureStore: {}
      }
    };
  },
  { virtual: true }
);

import { cryptoBroker } from "../cryptoBroker";
import { ledgerStore } from "../../state/ledgerStore";
import { SyncStatusView } from "../../components/syncStatusView";
import { getQueuedOperations, resetOfflineDatabaseInstance } from "../../sync/offlineOutbox";
import { secureWalletManager } from "../../wallet/secureWallet";

describe("Frontend JSI Blinding, Non-Blocking Ledger Store, and Telemetry UI Suite (Phase 10A, Version 10A.9)", () => {
  beforeEach(async () => {
    resetOfflineDatabaseInstance();
    ledgerStore.resetStore();
    secureWalletManager.resetLedger();
    await secureWalletManager.initializeWallet();
  });

  describe("Block 1: Cryptographic JSI Service Broker", () => {
    it("should successfully generate and retrieve an anonymous blinded attestation token", async () => {
      await cryptoBroker.refreshBlindedAttestationToken();
      const token = cryptoBroker.getAnonymousDeviceToken();
      expect(token).toContain("unblinded-generic-untampered-device-token-");
    });

    it("should poison context and fail hard on execution loop tampering / bitwise mismatch", async () => {
      // Access private method by casting to any to inject fault
      const originalLoop = (cryptoBroker as any).executeBlindingLoop;
      let count = 0;
      (cryptoBroker as any).executeBlindingLoop = (input: string, r: string) => {
        count++;
        if (count === 2) {
          // Fault injection: modify output of the second loop
          return originalLoop(input, r) + "corrupted-bit";
        }
        return originalLoop(input, r);
      };

      try {
        await expect(cryptoBroker.refreshBlindedAttestationToken()).rejects.toThrow(
          "[FATAL CRYPTO EXCEPTION] Anti-Fault bitwise mismatch detected. Session terminated."
        );
      } finally {
        // Restore loop
        (cryptoBroker as any).executeBlindingLoop = originalLoop;
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

      const dispatchPromise = ledgerStore.dispatchTransaction(txId, 250, {}, submitMock);
      expect(ledgerStore.getSliceState(txId)).toBe("STAGED_COMMITTING");

      await dispatchPromise;

      expect(ledgerStore.getSliceState(txId)).toBe("SYNCED");
      expect(ledgerStore.getBalance()).toBe(1250);
    });

    it("should route to offline outbox and set state to RECONCILING on network failure/timeout", async () => {
      const txId = "tx-slice-failure";

      const submitMock = jest.fn().mockRejectedValueOnce(new Error("Timeout"));

      await ledgerStore.dispatchTransaction(txId, 100, { amount: 100 }, submitMock);

      // Verify slice status transitions to RECONCILING
      expect(ledgerStore.getSliceState(txId)).toBe("RECONCILING");
      
      // Verify payload is stored inside offline outbox
      const queued = await getQueuedOperations();
      expect(queued).toHaveLength(1);
      expect(queued[0].id).toBe(txId);
    });
  });

  describe("Block 3: Hardened Secure Outbox Telemetry UI", () => {
    it("should display stable state and mask counts or timing metadata", () => {
      const { getByTestId } = render(<SyncStatusView />);
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
