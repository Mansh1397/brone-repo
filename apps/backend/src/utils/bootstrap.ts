import { Express, Request, Response } from "express";
import { verifyRingHandler, pool } from "../controllers/ringValidator";
import { handleBlindStamp } from "../controllers/stampController";

export async function initializeApplicationServer(app: Express): Promise<void> {
  // 1. POOL VALIDATION ALIVE CHECK
  try {
    await pool.query("SELECT 1;");
  } catch (error) {
    console.warn("[BOOTSTRAP] Database validation alive check failed (non-blocking during warm-up):", error);
  }

  // 2. STABLE DE-OPTIMIZATION RESISTANT WARM-UP (1,000-pass cryptographic JIT warm-up)
  const originalHrtime = process.hrtime.bigint;
  const originalPoolConnect = pool.connect;

  // Stub hrtime to return a dynamically increasing time so difference is always > 100ms
  let callCount = 0;
  process.hrtime.bigint = () => {
    callCount++;
    return originalHrtime() + BigInt(callCount) * 100_000_000n;
  };

  // Stub database pool connect to prevent hitting the database during mathematical JIT loop
  pool.connect = async () => {
    return {
      query: async () => ({ rows: Array.from({ length: 3 }) }),
      release: () => {}
    } as any;
  };

  const dummyVerifyReq: any = {
    body: {
      publicKeysRing: [
        { x: "1", y: "2" },
        { x: "3", y: "4" },
        { x: "5", y: "6" }
      ],
      messageHash: "7",
      signature: {
        c1: "8",
        s: ["9", "10", "11"],
        keyImage: { x: "12", y: "13" }
      }
    },
    socket: {
      destroy: () => {}
    }
  };

  const dummyStampReq: any = {
    body: {
      blindedTransaction: "12345678901234567890"
    },
    socket: {
      destroy: () => {}
    }
  };

  const makeMockRes = () => {
    const res: any = {
      status: function () {
        return this;
      },
      json: function () {
        return this;
      },
      setHeader: function () {
        return this;
      },
      locals: {}
    };
    return res;
  };

  try {
    for (let i = 0; i < 1000; i++) {
      const verifyRes = makeMockRes();
      await verifyRingHandler(dummyVerifyReq as Request, verifyRes as Response);

      const stampRes = makeMockRes();
      await handleBlindStamp(dummyVerifyReq as Request, stampRes as Response);
    }
    console.log("[BOOTSTRAP] Cryptographic JIT warm-up loop completed successfully (1,000 passes)");
  } catch (err) {
    console.error("[BOOTSTRAP] Cryptographic JIT warm-up encountered anomalies:", err);
  } finally {
    // Restore original process behavior and database pool methods
    process.hrtime.bigint = originalHrtime;
    pool.connect = originalPoolConnect;
  }
}

// 3. NETWORK SOCKET TIMEOUT IMMUNIZATION
export function configureServerTimeouts(server: any): void {
  server.keepAliveTimeout = 65000; // 65 seconds
  server.headersTimeout = 66000; // 66 seconds
}
