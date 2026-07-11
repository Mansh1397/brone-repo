"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ledgerStore = exports.LedgerStore = void 0;
const offlineOutbox_1 = require("../sync/offlineOutbox");
class LedgerStore {
    static instance;
    balance = 1000; // Base mock balance
    sliceStates = new Map();
    listeners = [];
    constructor() { }
    static getInstance() {
        if (!LedgerStore.instance) {
            LedgerStore.instance = new LedgerStore();
        }
        return LedgerStore.instance;
    }
    getBalance() {
        return this.balance;
    }
    getSliceState(txId) {
        return this.sliceStates.get(txId) || "IDLE";
    }
    setSliceState(txId, state) {
        this.sliceStates.set(txId, state);
        this.notify();
    }
    /**
     * 2. TWO-PHASE NON-BLOCKING TRANSACTION PIPELINE
     * Locks only the specific transaction slice, keeping the rest of the app fully interactive.
     */
    async dispatchTransaction(txId, amount, rawPayload, submitFn) {
        this.setSliceState(txId, "STAGED_COMMITTING");
        try {
            // Execute network submission
            const result = await submitFn();
            if (result.success) {
                // Atomically commit to primary balance upon verified receipt
                this.balance += amount;
                this.setSliceState(txId, "SYNCED");
            }
            else {
                // Fallback directly to offline outbox queues
                await this.handleTimeoutFallback(txId, rawPayload);
            }
        }
        catch (err) {
            // Connection timeouts/network drop boundaries
            await this.handleTimeoutFallback(txId, rawPayload);
        }
    }
    async handleTimeoutFallback(txId, rawPayload) {
        console.warn(`[LEDGER STORE] Timeout or connection failure on ${txId}. Routing to offline queue.`);
        // Smoothly hand off to offline outbox queue
        await (0, offlineOutbox_1.queueOfflineOperation)(txId, "SUBMISSION", rawPayload);
        // Transition slice to RECONCILING, releasing the active UI loaders
        this.setSliceState(txId, "RECONCILING");
    }
    subscribe(listener) {
        this.listeners.push(listener);
        return () => {
            this.listeners = this.listeners.filter(l => l !== listener);
        };
    }
    notify() {
        this.listeners.forEach(l => l());
    }
    resetStore() {
        this.balance = 1000;
        this.sliceStates.clear();
        this.listeners = [];
    }
}
exports.LedgerStore = LedgerStore;
exports.ledgerStore = LedgerStore.getInstance();
