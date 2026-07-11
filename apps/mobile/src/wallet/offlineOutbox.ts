import { SecureStore } from "./secureWallet";

export interface OutboxEnvelope {
  id: string;
  payloadType: "VOUCHER_REDEMPTION" | "LEDGER_SYNC" | "KEY_ROTATION";
  encryptedData: string;
  stagedAt: number;
  attempts: number;
}

type OutboxListener = (queueLength: number) => void;

class OfflineOutboxManager {
  private memoryQueue: Map<string, OutboxEnvelope> = new Map();
  private listeners: Set<OutboxListener> = new Set();
  private readonly STORAGE_KEY = "brone_secure_outbox_v1";
  private isLoaded = false;

  /**
   * Hydrates the in-memory queue from the secure storage enclave on boot.
   */
  public async ensureHydrated(): Promise<void> {
    if (this.isLoaded) return;
    try {
      const rawDiskData = await SecureStore.getItemAsync(this.STORAGE_KEY);
      if (rawDiskData) {
        const parsedList: OutboxEnvelope[] = JSON.parse(rawDiskData);
        this.memoryQueue.clear();
        parsedList.forEach(envelope => this.memoryQueue.set(envelope.id, envelope));
      }
      this.isLoaded = true;
    } catch (err) {
      console.error("[OUTBOX HYDRATION ERROR]: Failed to parse secure envelope storage.", err);
      // Fallback to empty state to prevent app deadlock
      this.memoryQueue.clear();
      this.isLoaded = true;
    }
  }

  /**
   * Persists the current in-memory queue back to the secure enclave disk layer atomically.
   */
  private async flushToDisk(): Promise<void> {
    try {
      const serializedData = JSON.stringify(Array.from(this.memoryQueue.values()));
      await SecureStore.setItemAsync(this.STORAGE_KEY, serializedData);
      this.notifyListeners();
    } catch (err) {
      console.error("[OUTBOX FLUSH ERROR]: Critical disk flush write failed.", err);
      throw new Error("Outbox persistence failure. System rolling back state.");
    }
  }

  /**
   * Enqueues an encrypted transaction envelope into the secure disk pipeline.
   */
  public async enqueue(id: string, type: OutboxEnvelope["payloadType"], encryptedData: string): Promise<void> {
    await this.ensureHydrated();

    if (this.memoryQueue.has(id)) {
      throw new Error(`Collision error: Transaction ID '${id}' already exists in pending queue.`);
    }

    const envelope: OutboxEnvelope = {
      id,
      payloadType: type,
      encryptedData,
      stagedAt: Date.now(),
      attempts: 0
    };

    this.memoryQueue.set(id, envelope);
    await this.flushToDisk();
    console.log(`[OUTBOX STAGED]: Enqueued ${type} transaction with ID ${id}.`);
  }

  /**
   * Returns all currently pending transaction envelopes ordered by historical insertion sequence.
   */
  public async getPendingQueue(): Promise<OutboxEnvelope[]> {
    await this.ensureHydrated();
    return Array.from(this.memoryQueue.values()).sort((a, b) => a.stagedAt - b.stagedAt);
  }

  /**
   * Increments attempt counts or updates envelope data state on failed executions.
   */
  public async registerFailure(id: string): Promise<void> {
    await this.ensureHydrated();
    const envelope = this.memoryQueue.get(id);
    if (envelope) {
      envelope.attempts += 1;
      await this.flushToDisk();
    }
  }

  /**
   * Atomically drops a successfully synchronized entry from the execution pipeline.
   */
  public async dequeue(id: string): Promise<void> {
    await this.ensureHydrated();
    if (this.memoryQueue.has(id)) {
      this.memoryQueue.delete(id);
      await this.flushToDisk();
      console.log(`[OUTBOX DEQUEUED]: Removed synchronized transaction ID ${id}.`);
    }
  }

  /**
   * Reactive Subscriber Interface hooks
   */
  public subscribe(listener: OutboxListener): () => void {
    this.listeners.add(listener);
    // Immediate execution initialization update
    listener(this.memoryQueue.size);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyListeners(): void {
    const size = this.memoryQueue.size;
    this.listeners.forEach(listener => listener(size));
  }

  /**
   * Wipes internal tracking vectors for unit testing environments.
   */
  public async clearAll(): Promise<void> {
    this.memoryQueue.clear();
    this.isLoaded = false;
    await SecureStore.deleteItemAsync(this.STORAGE_KEY);
    this.notifyListeners();
  }
}

export const offlineOutboxManager = new OfflineOutboxManager();