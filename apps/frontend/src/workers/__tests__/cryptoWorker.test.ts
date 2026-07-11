import { TextEncoder, TextDecoder } from "util";
import { CryptoWorkerClient } from "../CryptoWorkerClient";

// 1. DOM/BROWSER GLOBAL CONTEXT MOCKING
if (typeof (global as any).TextEncoder === "undefined") {
  (global as any).TextEncoder = TextEncoder;
}
if (typeof (global as any).TextDecoder === "undefined") {
  (global as any).TextDecoder = TextDecoder;
}
if (typeof (global as any).URL === "undefined") {
  (global as any).URL = class {
    static createObjectURL() {
      return "blob:mock-url";
    }
  } as any;
} else if (typeof (global as any).URL.createObjectURL === "undefined") {
  (global as any).URL.createObjectURL = () => "blob:mock-url";
}

// Global Mock Worker setup
let activeMockWorkerInstance: any = null;

class MockWorker {
  public postMessage = jest.fn((msg: any) => {
    // Record the message sent to the worker
    this.lastPostedMessage = msg;
  });
  public terminate = jest.fn();
  public onmessage: ((this: Worker, ev: MessageEvent) => any) | null = null;
  public onerror: ((this: Worker, ev: ErrorEvent) => any) | null = null;
  public lastPostedMessage: any = null;

  constructor(public url: string, public options?: any) {
    activeMockWorkerInstance = this;
  }

  public simulateMessage(data: any) {
    if (this.onmessage) {
      (this.onmessage as any)({ data } as any);
    }
  }

  public simulateError(message: string) {
    if (this.onerror) {
      (this.onerror as any)({ message } as any);
    }
  }
}

(global as any).Worker = MockWorker;

describe("Isolated Cryptographic Web Worker Proxy Client Tests", () => {
  let client: CryptoWorkerClient;

  beforeEach(() => {
    jest.useFakeTimers();
    client = CryptoWorkerClient.getInstance();
  });

  afterEach(() => {
    client.terminate();
    jest.useRealTimers();
    activeMockWorkerInstance = null;
  });

  it("should successfully dispatch accurately structured message envelopes through postMessage", async () => {
    const payload = { value: "1234" };
    
    // Trigger invocation
    const promise = client.execute("BLIND_TOKEN_PARAMETERS", payload);

    expect(activeMockWorkerInstance).not.toBeNull();
    expect(activeMockWorkerInstance.postMessage).toHaveBeenCalledTimes(1);

    const sentMessage = activeMockWorkerInstance.lastPostedMessage;
    expect(sentMessage.type).toBe("BLIND_TOKEN_PARAMETERS");
    expect(sentMessage.payload).toEqual(payload);
    expect(sentMessage.id).toBeDefined();

    // Simulate worker successfully returning decoded data
    const resultString = "abcdef123456";
    const encodedPayload = new TextEncoder().encode(resultString);
    activeMockWorkerInstance.simulateMessage({
      id: sentMessage.id,
      payload: encodedPayload
    });

    const response = await promise;
    expect(response).toBe(resultString);
  });

  it("should set up an active timeout constraint that automatically triggers a promise rejection on silent workers", async () => {
    const promise = client.execute("UNBLIND_STAMPED_TOKEN", { token: "555" });

    // Advance timer past the 30-second fail-fast boundary
    jest.advanceTimersByTime(30000);

    await expect(promise).rejects.toThrow("Worker execution timed out after 30000ms");
  });

  it("should reject all active pending promises safely when worker onerror fires", async () => {
    const promise = client.execute("GENERATE_RING_SIGNATURE", { messageHash: "99" });

    // Trigger error event in background thread
    activeMockWorkerInstance.simulateError("V8 Heap Overflow");

    await expect(promise).rejects.toThrow("Worker execution failed: V8 Heap Overflow");
  });
});
