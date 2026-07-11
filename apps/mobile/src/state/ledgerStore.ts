import { queueOfflineOperation } from "../sync/offlineOutbox";

export type LedgerSliceState = "IDLE" | "STAGED_COMMITTING" | "RECONCILING" | "SYNCED";

export class LedgerStore {
  private static instance: LedgerStore;
  
  private balance = 1000; // Base mock balance
  private sliceStates = new Map<string, LedgerSliceState>();
  private listeners: (() => void)[] = [];

  private constructor() {}

  public static getInstance(): LedgerStore {
    if (!LedgerStore.instance) {
      LedgerStore.instance = new LedgerStore();
    }
    return LedgerStore.instance;
  }

  public getBalance(): number {
    return this.balance;
  }

  public getSliceState(txId: string): LedgerSliceState {
    return this.sliceStates.get(txId) || "IDLE";
  }

  public setSliceState(txId: string, state: LedgerSliceState): void {
    this.sliceStates.set(txId, state);
    this.notify();
  }

  /**
   * 2. TWO-PHASE NON-BLOCKING TRANSACTION PIPELINE
   * Locks only the specific transaction slice, keeping the rest of the app fully interactive.
   */
  public async dispatchTransaction(
    txId: string,
    amount: number,
    rawPayload: Record<string, any>,
    submitFn: () => Promise<{ success: boolean; receipt_signature?: string }>
  ): Promise<void> {
    this.setSliceState(txId, "STAGED_COMMITTING");

    try {
      // Execute network submission
      const result = await submitFn();

      if (result.success) {
        // Atomically commit to primary balance upon verified receipt
        this.balance += amount;
        this.setSliceState(txId, "SYNCED");
      } else {
        // Fallback directly to offline outbox queues
        await this.handleTimeoutFallback(txId, rawPayload);
      }
    } catch (err) {
      // Connection timeouts/network drop boundaries
      await this.handleTimeoutFallback(txId, rawPayload);
    }
  }

  private async handleTimeoutFallback(txId: string, rawPayload: Record<string, any>): Promise<void> {
    console.warn(`[LEDGER STORE] Timeout or connection failure on ${txId}. Routing to offline queue.`);
    
    // Smoothly hand off to offline outbox queue
    await queueOfflineOperation(txId, "SUBMISSION", rawPayload);
    
    // Transition slice to RECONCILING, releasing the active UI loaders
    this.setSliceState(txId, "RECONCILING");
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notify(): void {
    this.listeners.forEach(l => l());
  }

  public resetStore(): void {
    this.balance = 1000;
    this.sliceStates.clear();
    this.listeners = [];
  }
}

export const ledgerStore = LedgerStore.getInstance();
