"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.offlineOutboxManager = void 0;
const secureWallet_1 = require("./secureWallet");
class OfflineOutboxManager {
    memoryQueue = new Map();
    listeners = new Set();
    STORAGE_KEY = "brone_secure_outbox_v1";
    isLoaded = false;
    /**
     * Hydrates the in-memory queue from the secure storage enclave on boot.
     */
    async ensureHydrated() {
        if (this.isLoaded)
            return;
        try {
            const rawDiskData = await secureWallet_1.SecureStore.getItemAsync(this.STORAGE_KEY);
            if (rawDiskData) {
                const parsedList = JSON.parse(rawDiskData);
                this.memoryQueue.clear();
                parsedList.forEach(envelope => this.memoryQueue.set(envelope.id, envelope));
            }
            this.isLoaded = true;
        }
        catch (err) {
            console.error("[OUTBOX HYDRATION ERROR]: Failed to parse secure envelope storage.", err);
            // Fallback to empty state to prevent app deadlock
            this.memoryQueue.clear();
            this.isLoaded = true;
        }
    }
    /**
     * Persists the current in-memory queue back to the secure enclave disk layer atomically.
     */
    async flushToDisk() {
        try {
            const serializedData = JSON.stringify(Array.from(this.memoryQueue.values()));
            await secureWallet_1.SecureStore.setItemAsync(this.STORAGE_KEY, serializedData);
            this.notifyListeners();
        }
        catch (err) {
            console.error("[OUTBOX FLUSH ERROR]: Critical disk flush write failed.", err);
            throw new Error("Outbox persistence failure. System rolling back state.");
        }
    }
    /**
     * Enqueues an encrypted transaction envelope into the secure disk pipeline.
     */
    async enqueue(id, type, encryptedData) {
        await this.ensureHydrated();
        if (this.memoryQueue.has(id)) {
            throw new Error(`Collision error: Transaction ID '${id}' already exists in pending queue.`);
        }
        const envelope = {
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
    async getPendingQueue() {
        await this.ensureHydrated();
        return Array.from(this.memoryQueue.values()).sort((a, b) => a.stagedAt - b.stagedAt);
    }
    /**
     * Increments attempt counts or updates envelope data state on failed executions.
     */
    async registerFailure(id) {
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
    async dequeue(id) {
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
    subscribe(listener) {
        this.listeners.add(listener);
        // Immediate execution initialization update
        listener(this.memoryQueue.size);
        return () => {
            this.listeners.delete(listener);
        };
    }
    notifyListeners() {
        const size = this.memoryQueue.size;
        this.listeners.forEach(listener => listener(size));
    }
    /**
     * Wipes internal tracking vectors for unit testing environments.
     */
    async clearAll() {
        this.memoryQueue.clear();
        this.isLoaded = false;
        await secureWallet_1.SecureStore.deleteItemAsync(this.STORAGE_KEY);
        this.notifyListeners();
    }
}
exports.offlineOutboxManager = new OfflineOutboxManager();
