import { spawn, exec } from "child_process";
import * as net from "net";
import axios from "axios";
import * as crypto from "crypto";
import express from "express";
import http from "http";

// Polyfill Web Crypto API in Jest Node environment if necessary
if (typeof globalThis.crypto === 'undefined') {
  (globalThis as any).crypto = crypto.webcrypto;
}

// Import the production-ready frontend apiClient
import { apiClient, resetClockOffset } from "../../../../apps/frontend/src/api/apiClient";

// Force apiClient to target the local edge proxy
apiClient.defaults.baseURL = "http://localhost:8787";

let backendProcess: any = null;
let edgeProxyServer: http.Server | null = null;

// TCP Socket Liveness Polling helper
async function isPortOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(200);
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, "127.0.0.1");
  });
}

async function waitPortOpen(port: number, timeoutMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await isPortOpen(port)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Port ${port} did not open within ${timeoutMs}ms`);
}

async function waitPortClosed(port: number, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (!(await isPortOpen(port))) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Port ${port} did not close within ${timeoutMs}ms`);
}

function killProcessTree(pid: number): Promise<void> {
  return new Promise((resolve) => {
    if (process.platform === "win32") {
      exec(`taskkill /pid ${pid} /T /F`, () => resolve());
    } else {
      try {
        process.kill(-pid, "SIGKILL");
      } catch (e) {
        try {
          process.kill(pid, "SIGKILL");
        } catch (e2) {}
      }
      resolve();
    }
  });
}

// Local, Node-based Edge Proxy implementation to replicate Cloudflare Worker logic on Windows
function startLocalEdgeProxy(): Promise<void> {
  const proxyApp = express();
  proxyApp.disable("x-powered-by");
  proxyApp.use(express.json());

  proxyApp.use(async (req, res) => {
    const origin = req.headers.origin;
    const method = req.method;

    // 1. CORS Preflight
    if (method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", origin || "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Brone-Edge-Token");
      res.setHeader("Access-Control-Max-Age", "86400");
      res.status(204).end();
      return;
    }

    // 2. Token Check
    const token = req.headers["x-brone-edge-token"];
    if (!token) {
      res.status(400).send("Bad Request: Missing X-Brone-Edge-Token header");
      return;
    }

    // 3. Forward request to backend origin core (8080)
    try {
      const backendUrl = `http://localhost:8080${req.path}`;
      const backendRes = await axios({
        method: req.method,
        url: backendUrl,
        data: req.body,
        headers: {
          "Content-Type": "application/json",
          "X-Brone-Origin-Signature": "test_origin_secret_12345",
        },
        validateStatus: () => true,
      });

      // 4. Return response to client with atomic clock synchronization headers
      res.setHeader("X-Brone-Time", new Date().toISOString());
      res.setHeader("Access-Control-Allow-Origin", origin || "*");
      res.setHeader("Access-Control-Expose-Headers", "X-Brone-Time, X-Brone-Edge-Token, Content-Type");

      res.status(backendRes.status).json(backendRes.data);
    } catch (err) {
      res.status(502).send("Bad Gateway");
    }
  });

  return new Promise<void>((resolve) => {
    edgeProxyServer = proxyApp.listen(8787, () => {
      resolve();
    });
  });
}

describe("E2E Integration Test Suite - Interoperability Pipeline", () => {
  jest.setTimeout(75000);

  beforeAll(async () => {
    // 1. Programmatically spawn the Backend Origin Core
    backendProcess = spawn("npx", ["ts-node", "src/index.ts"], {
      cwd: "d:/Brone/apps/backend-core",
      env: {
        ...process.env,
        PORT: "8080",
        NODE_ENV: "test",
        IS_E2E: "true",
        ORIGIN_SIGNATURE_SECRET: "test_origin_secret_12345",
        SERVER_PRIVATE_KEY_D: "2753",
        SERVER_PRIVATE_KEY_N: "3233",
        SERVER_PUBLIC_KEY_E: "17",
        DATABASE_URL: "", // force in-memory fallback
      },
      shell: true,
      detached: true,
    });

    // Write logs for backend core process
    const fs = require("fs");
    fs.writeFileSync("d:/Brone/tools/e2e-testing/backend.log", "");
    backendProcess.stdout.on("data", (data: any) => {
      fs.appendFileSync("d:/Brone/tools/e2e-testing/backend.log", data.toString());
    });
    backendProcess.stderr.on("data", (data: any) => {
      fs.appendFileSync("d:/Brone/tools/e2e-testing/backend.log", "[STDERR]: " + data.toString());
    });

    // 2. Start the local edge proxy
    await startLocalEdgeProxy();

    // 3. Poll ports for liveness verification
    try {
      await Promise.all([
        waitPortOpen(8080, 45000),
        waitPortOpen(8787, 45000),
      ]);
    } catch (err) {
      if (backendProcess && backendProcess.pid) await killProcessTree(backendProcess.pid);
      if (edgeProxyServer) edgeProxyServer.close();
      throw err;
    }
  });

  afterAll(async () => {
    // Forcefully kill spawned background tasks
    if (backendProcess && backendProcess.pid) {
      await killProcessTree(backendProcess.pid);
    }
    
    // Close local edge proxy server
    if (edgeProxyServer) {
      edgeProxyServer.close();
    }

    // Await absolute verification that both ports are clean and empty
    await Promise.all([
      waitPortClosed(8080),
      waitPortClosed(8787),
    ]);
  });

  beforeEach(async () => {
    // Reset database to guarantee test determinism
    await axios.post("http://localhost:8080/api/v1/test/reset", {}, {
      headers: {
        "X-Brone-Origin-Signature": "test_origin_secret_12345",
      },
    });
    resetClockOffset();
  });

  // INVARIANT 1: THE END-TO-END HAPPY PATH STAMP
  it("should successfully route stamp requests through Edge Proxy to Backend Core and return atomic headers", async () => {
    const response = await apiClient.post("/api/v1/stamp", {
      blindedTransaction: "123",
    });

    expect(response.status).toBe(200);
    expect(response.data).toHaveProperty("signature");
    expect(typeof response.data.signature).toBe("string");
    
    // Assert response headers deliver the atomic X-Brone-Time header
    expect(
      response.headers["x-brone-time"] || response.headers["X-Brone-Time"]
    ).toBeDefined();
  });

  // INVARIANT 2: TIMING-SECURE DIRECT PROTECTION GATE
  it("should block direct attempts on the Backend Core port", async () => {
    // 1. Attempt direct request without origin signature header
    let thrownNoHeader = false;
    try {
      await axios.post("http://localhost:8080/api/v1/stamp", {
        blindedTransaction: "123",
      });
    } catch (error: any) {
      thrownNoHeader = true;
      expect(error.response?.status).toBe(401);
    }
    expect(thrownNoHeader).toBe(true);

    // 2. Attempt direct request with mutated/corrupted signature string
    let thrownCorruptedHeader = false;
    try {
      await axios.post("http://localhost:8080/api/v1/stamp", {
        blindedTransaction: "123",
      }, {
        headers: {
          "X-Brone-Origin-Signature": "invalid_origin_signature_peppered",
        },
      });
    } catch (error: any) {
      thrownCorruptedHeader = true;
      expect(error.response?.status).toBe(401);
    }
    expect(thrownCorruptedHeader).toBe(true);
  });

  // INVARIANT 3: DISTRIBUTED RACE-CONDITION DOUBLE-SPEND ATOMIZATION
  it("should enforce double-spend registry uniqueness and reject concurrent duplicates with 409", async () => {
    const nullifier = "888";
    
    // First, stamp the nullifier (treated as blinded tx) to get a valid signature
    const stampRes = await apiClient.post("/api/v1/stamp", {
      blindedTransaction: nullifier,
    });
    const signature = stampRes.data.signature;

    // 1. Initial verification call is accepted
    const verifyRes = await apiClient.post("/api/v1/verify", {
      nullifier,
      signature,
    });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.data.status).toBe("verified");

    // 2. Send concurrent duplicate spending requests immediately inside Promise.all
    const concurrentRequests = Array.from({ length: 5 }, () =>
      apiClient.post("/api/v1/verify", {
        nullifier,
        signature,
      })
    );

    const results = await Promise.allSettled(concurrentRequests);

    // 3. Confirm that every concurrent duplicate request is rejected with 409 Conflict
    results.forEach((res) => {
      expect(res.status).toBe("rejected");
      const reason = (res as PromiseRejectedResult).reason;
      expect(reason.response?.status).toBe(409);
      expect(reason.response?.data?.error).toBe("Double Spend Detected");
    });
  });
});
