import { getQueuedOperations, deleteOfflineOperation } from "./offlineOutbox";
import { rollbackGuard } from "./rollbackGuard";

export class SyncManager {
  private static instance: SyncManager;

  // Configuration to allow instantaneous overrides for test validation
  public baseIntervalMs = 10 * 60 * 1000; // 10 minutes
  public jitterRangeMs = 5 * 60 * 1000;  // 5 minutes

  private isSyncing = false;

  private constructor() {}

  public static getInstance(): SyncManager {
    if (!SyncManager.instance) {
      SyncManager.instance = new SyncManager();
    }
    return SyncManager.instance;
  }

  // 1. Scrub and cycle all ephemeral device metadata headers
  private generateScrubbedHeaders(): Record<string, string> {
    const userAgents = [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/UD1A.230805.019) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
    ];
    
    const randomUA = userAgents[Math.floor(Math.random() * userAgents.length)];
    const ephemeralSocketId = Math.random().toString(36).substring(2, 15);

    return {
      "Content-Type": "application/json",
      "User-Agent": randomUA,
      "X-Ephemeral-Socket-ID": ephemeralSocketId,
      "X-Request-Epoch": Date.now().toString(),
      "Connection": "close"
    };
  }

  /**
   * 2. DECENTRALIZED RANDOMIZED BATCHING AND JITTER
   * Main synchronization routing loop called on network connectivity state recovery.
   */
  public async reconcileOfflineOutbox(backendUrl: string): Promise<number> {
    if (this.isSyncing) return 0;
    this.isSyncing = true;

    try {
      const operations = await getQueuedOperations();
      if (operations.length === 0) {
        this.isSyncing = false;
        return 0;
      }

      // Randomly select 1 to 3 payloads at a time (decentralized randomized batching)
      const batchSize = Math.floor(Math.random() * 3) + 1; // 1, 2, or 3
      const targetBatch = operations.slice(0, batchSize);
      let successCount = 0;

      for (const op of targetBatch) {
        // Calculate randomized delay jitter: base interval modulated by +/- jitter range
        const jitterMultiplier = Math.random() < 0.5 ? -1 : 1;
        const totalDelay = this.baseIntervalMs + (Math.floor(Math.random() * this.jitterRangeMs) * jitterMultiplier);

        // Sleep to delay delivery (helps defeat timing analysis)
        if (totalDelay > 0) {
          await new Promise((resolve) => setTimeout(resolve, totalDelay));
        }

        const success = await this.dispatchReconciledPayload(op, backendUrl);
        if (success) {
          successCount++;
        }
      }

      this.isSyncing = false;
      return successCount;
    } catch (err) {
      console.error("[SYNC MANAGER ERROR] Reconciliation loop failed:", err);
      this.isSyncing = false;
      return 0;
    }
  }

  private async dispatchReconciledPayload(
    op: { id: string; operationType: "SUBMISSION" | "VOTE"; payload: Record<string, any> },
    backendUrl: string
  ): Promise<boolean> {
    const headers = this.generateScrubbedHeaders();
    const endpoint = op.operationType === "VOTE" 
      ? `/tasks/${op.id}/vote` 
      : `/tasks/${op.id}/submit`;

    try {
      const response = await fetch(`${backendUrl}${endpoint}`, {
        method: "POST",
        headers,
        body: JSON.stringify(op.payload)
      });

      if (response.ok) {
        const result = await response.json();
        // Transaction succeeded, unlock state & complete
        if (op.operationType === "VOTE" || op.operationType === "SUBMISSION") {
          try {
            rollbackGuard.commitVoucherTransaction(op.id, result.receipt_signature || "reconciled-mock-sig");
          } catch (e) {
            // Suppress context errors if not staged in active memory
          }
        }
        await deleteOfflineOperation(op.id);
        return true;
      } else {
        // HTTP Fail: lock in PENDING_RETRY flag status
        rollbackGuard.triggerRollbackToPendingRetry(op.id);
        return false;
      }
    } catch (err) {
      // Socket / network exception: trigger rollback, keeping pending in SQLite
      rollbackGuard.triggerRollbackToPendingRetry(op.id);
      return false;
    }
  }
}

export const syncManager = SyncManager.getInstance();
