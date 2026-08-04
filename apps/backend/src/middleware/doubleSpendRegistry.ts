import { Request, Response, NextFunction } from "express";
import * as crypto from "crypto";
import { pool } from "../controllers/ringValidator";

const sleep = (ms: number) => new Promise<void>((resolve) => {
  const timer = setTimeout(resolve, ms);
  timer.unref();
});

export async function guardAgainstDoubleSpend(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const keyImageObj = req.body?.signature?.keyImage || req.body?.keyImage;
  
  if (!keyImageObj) {
    res.setHeader("Connection", "close");
    res.status(400).json({ error: "Missing Key Image in request payload" });
    return;
  }

  let keyImageStr: string | null = typeof keyImageObj === "string"
    ? keyImageObj
    : `${keyImageObj.x},${keyImageObj.y}`;

  let rawHashHex: string | null = crypto.createHash("sha256").update(keyImageStr).digest("hex");
  const rawHashBigInt = BigInt("0x" + rawHashHex.substring(0, 16));
  let safeSignedXactKey: bigint | null = BigInt.asIntN(64, rawHashBigInt);

  let client: any = null;
  let retries = 0;
  const maxRetries = 2;
  let transactionCommitted = false;
  let doubleSpendDetected = false;

  try {
    while (true) {
      client = await pool.connect();
      try {
        await client.query("BEGIN");
        
        // 1. LOCK TIMEOUT HARDENING
        await client.query("SET LOCAL lock_timeout = '1500ms';");

        // 2. DUAL-LAYER ADVISORY LOCK FENCING
        await client.query({
          text: "SELECT pg_advisory_xact_lock($1);",
          values: [safeSignedXactKey]
        });

        // 3. ATOMIC ISOLATION & INTENT FORCED QUERY
        const selectResult = await client.query({
          name: "select_nullifier",
          text: "SELECT 1 FROM signatures WHERE tx_hash = $1 FOR UPDATE;",
          values: [keyImageStr]
        });

        if (selectResult.rows.length > 0) {
          doubleSpendDetected = true;
          await client.query("ROLLBACK");
          break;
        }

        // 4. REGISTRY INSERTION
        await client.query({
          name: "insert_nullifier",
          text: "INSERT INTO signatures (tx_hash) VALUES ($1);",
          values: [keyImageStr]
        });

        await client.query("COMMIT");
        transactionCommitted = true;
        break;
      } catch (err: any) {
        await client.query("ROLLBACK").catch(() => {});
        
        // 5. DEADLOCK & MUTEX EXCEPTION HANDLING (Retry on 40001 or 40P01)
        if ((err.code === "40001" || err.code === "40P01") && retries < maxRetries) {
          retries++;
          client.release();
          client = null;
          // Randomized jittered non-blocking sleep (50ms to 150ms)
          const jitterDelay = 50 + Math.floor(Math.random() * 100);
          await sleep(jitterDelay);
          continue;
        }
        throw err;
      } finally {
        if (client) {
          client.release();
          client = null;
        }
      }
    }

    if (doubleSpendDetected) {
      res.setHeader("Connection", "close");
      res.status(409).json({ error: "Conflict" });
      return;
    }

    if (transactionCommitted) {
      next();
    }
  } catch (error) {
    // 6. STRICT OPAQUE REJECTION RESPONSE
    res.setHeader("Connection", "close");
    res.status(409).json({ error: "Conflict" });
  } finally {
    // 7. EXPLICIT MATRICES ZEROING (Heap cleanup)
    keyImageStr = null;
    rawHashHex = null;
    safeSignedXactKey = null;
  }
}
