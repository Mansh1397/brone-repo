export class CryptoWorkerClient {
  private static instance: CryptoWorkerClient | null = null;
  private worker: Worker;
  private pendingRequests = new Map<
    string,
    {
      resolve: (value: any) => void;
      reject: (reason: any) => void;
      timeoutId: any;
    }
  >();

  private constructor() {
    // 1. CROSS-ORIGIN RESILIENT WORKER INSTANTIATION
    let metaUrl = "";
    try {
      metaUrl = eval("import.meta").url;
    } catch (e) {}
    const workerUrl = new URL("./crypto.worker.ts", metaUrl || "http://localhost").href;
    try {
      this.worker = new Worker(workerUrl, { type: "module" });
    } catch (e) {
      // Build an origin-bound inline Blob URL if cross-origin asset loading constraints are detected
      const blobScript = `importScripts("${workerUrl}");`;
      const blob = new Blob([blobScript], { type: "application/javascript" });
      const inlineUrl = URL.createObjectURL(blob);
      this.worker = new Worker(inlineUrl);
    }

    // Hook message broker
    this.worker.onmessage = (event: MessageEvent) => {
      const { id, payload, error } = event.data;
      const pending = this.pendingRequests.get(id);
      if (!pending) return;

      clearTimeout(pending.timeoutId);
      this.pendingRequests.delete(id);

      if (error) {
        pending.reject(new Error(error));
      } else if (payload instanceof Uint8Array) {
        // Decode incoming transferable buffers via native TextDecoder
        const decoded = new TextDecoder().decode(payload);
        pending.resolve(decoded);
      } else {
        pending.resolve(payload);
      }
    };

    // 2. GLOBAL ERROR HANDLING
    this.worker.onerror = (error: ErrorEvent) => {
      console.error("[CRYPTO WORKER CLIENT] Unhandled background thread exception:", error);
      // Loop through all active pending promises and reject them safely
      for (const [id, pending] of this.pendingRequests.entries()) {
        clearTimeout(pending.timeoutId);
        pending.reject(new Error(`Worker execution failed: ${error.message || "Unknown error"}`));
      }
      this.pendingRequests.clear();
    };
  }

  public static getInstance(): CryptoWorkerClient {
    if (!CryptoWorkerClient.instance) {
      CryptoWorkerClient.instance = new CryptoWorkerClient();
    }
    return CryptoWorkerClient.instance;
  }

  // 3. PROMISIFIED INVOCATION BRIDGE
  public execute(type: string, payload: any): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const id = this.generateId();

      // 4. FAIL-FAST BOUNDARY TIMEOUT
      const timeoutId = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Worker execution timed out after 30000ms`));
      }, 30000);

      this.pendingRequests.set(id, { resolve, reject, timeoutId });

      this.worker.postMessage({ id, type, payload });
    });
  }

  private generateId(): string {
    return Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
  }

  // Helper method for testing/cleanup
  public terminate(): void {
    this.worker.terminate();
    for (const pending of this.pendingRequests.values()) {
      clearTimeout(pending.timeoutId);
    }
    this.pendingRequests.clear();
    CryptoWorkerClient.instance = null;
  }
}
