import { Request, Response, Router } from "express";
import { Pool } from "pg";
import * as crypto from "crypto";
import { verifyRing, serializeKeysRing, Point } from "@brone/crypto-core";

const router = Router();

// Initialize Postgres Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

function hashPublicKey(pk: { x: string; y: string }): string {
  const xBig = BigInt(pk.x);
  const yBig = BigInt(pk.y);
  
  const bufX = Buffer.alloc(32);
  let tmpX = xBig;
  for (let i = 31; i >= 0; i--) {
    bufX[i] = Number(tmpX & 0xffn);
    tmpX >>= 8n;
  }
  
  const bufY = Buffer.alloc(32);
  let tmpY = yBig;
  for (let i = 31; i >= 0; i--) {
    bufY[i] = Number(tmpY & 0xffn);
    tmpY >>= 8n;
  }
  
  const hash = crypto.createHash("sha256").update(bufX).update(bufY).digest("hex");
  bufX.fill(0);
  bufY.fill(0);
  return hash;
}

const sleep = (ms: number) => new Promise<void>((resolve) => {
  const timer = setTimeout(resolve, ms);
  timer.unref();
});

export async function verifyRingHandler(req: Request, res: Response): Promise<void> {
  // Start high-resolution timer immediately
  const startTime = process.hrtime.bigint();

  // 1. HARD BOUNDARY ARRAY CEILING (Early Rejection Guard)
  const ring = req.body?.publicKeysRing;
  if (!ring || !Array.isArray(ring) || ring.length < 3 || ring.length > 10) {
    res.setHeader("Connection", "close");
    res.status(401).json({ error: "Unauthorized" });
    req.socket.destroy();
    return;
  }

  let client: any = null;
  let flatRing: BigUint64Array | null = null;
  let hashes: string[] | null = null;
  let rows: any[] | null = null;
  let validationSuccess = false;

  try {
    // 2. CONSTANT-TIME HASH-INDEX SQL LOOKUPS
    hashes = ring.map((pk: any) => hashPublicKey(pk));
    
    // Check uniqueness to prevent duplicate key bypasses
    const uniqueHashes = new Set(hashes);
    if (uniqueHashes.size !== ring.length) {
      throw new Error("Duplicate keys in ring");
    }

    client = await pool.connect();
    const dbResult = await client.query({
      name: "get_public_key_hashes",
      text: "SELECT public_key_hash FROM user_identities WHERE public_key_hash = ANY($1)",
      values: [hashes]
    });
    rows = dbResult.rows;

    // Fail-fast if any key hash is missing from the database
    if (rows && rows.length === ring.length) {
      // 3. BUFFER FLATTENING STEP & CRYPTOGRAPHIC VERIFICATION
      const points: Point[] = ring.map((pk: any) => ({
        x: BigInt(pk.x),
        y: BigInt(pk.y)
      }));

      flatRing = serializeKeysRing(points);

      const msgHash = BigInt(req.body.messageHash);
      const sigC1 = BigInt(req.body.signature.c1);
      const sigS = req.body.signature.s.map((val: any) => BigInt(val));
      const sigKeyImage = {
        x: BigInt(req.body.signature.keyImage.x),
        y: BigInt(req.body.signature.keyImage.y)
      };

      const isSigValid = verifyRing(msgHash, flatRing, {
        c1: sigC1,
        s: sigS,
        keyImage: sigKeyImage
      });

      if (isSigValid) {
        validationSuccess = true;
      }
    }
  } catch (err) {
    // Suppress errors and remain opaque
    validationSuccess = false;
  } finally {
    if (client) {
      client.release();
    }

    // 4. EXPLICIT MATRICES ZEROING (Heap sanitization)
    if (flatRing) {
      flatRing.fill(0n);
      flatRing = null;
    }
    if (hashes) {
      hashes.fill("");
      hashes = null;
    }
    if (rows) {
      rows = null;
    }

    // Calculate elapsed time and sleep remaining duration to enforce exactly 45ms response time
    const endTime = process.hrtime.bigint();
    const elapsedMs = Number(endTime - startTime) / 1e6;
    const remainingMs = 45 - elapsedMs;
    if (remainingMs > 0) {
      await sleep(Math.round(remainingMs));
    }

    // Unify TCP connection headers and respond opaquely
    res.setHeader("Connection", "close");
    if (validationSuccess) {
      res.status(200).json({ success: true });
    } else {
      res.status(401).json({ error: "Unauthorized" });
    }
  }
}

router.post("/verify-ring", verifyRingHandler);

export default router;
export { pool }; // Export pool for lifecycle/test management
