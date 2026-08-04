import { Pool } from "pg";

const sleep = (ms: number) => new Promise<void>((resolve) => {
  const timer = setTimeout(resolve, ms);
  timer.unref();
});

export async function executePurgeCycle(pool: Pool): Promise<number> {
  // 1. COMPONENT-ISOLATED CLIENT LIFECYCLE MANAGEMENT (checkout exactly once)
  let client: any = null;
  let boundary: Date | null = null;
  let totalDeleted = 0;

  try {
    client = await pool.connect();

    // MVCC SNAPSHOT TRANS_ISOLATION & Statement Timeout
    await client.query("SET statement_timeout = '3000ms';");
    await client.query("SET transaction_isolation = 'read committed';");

    // hardcoded production data retention ceiling (exactly NOW() - INTERVAL '24 hours')
    boundary = new Date(Date.now() - 24 * 60 * 60 * 1000);

    // Iterative chunk deletion for nullifiers
    while (true) {
      // CONCURRENT SKIP-LOCKED STRIDE
      const res = await client.query({
        text: "DELETE FROM nullifiers WHERE nullifier_hash IN (SELECT nullifier_hash FROM nullifiers WHERE spent_at < $1 LIMIT 500 FOR UPDATE SKIP LOCKED);",
        values: [boundary]
      });
      const affected = res.rowCount || 0;
      totalDeleted += affected;
      if (affected === 0) {
        break;
      }
      // THROTTLED RECURSION PAUSE
      await sleep(150);
    }

    // Iterative chunk deletion for signatures
    while (true) {
      const res = await client.query({
        text: "DELETE FROM signatures WHERE tx_hash IN (SELECT tx_hash FROM signatures WHERE recorded_at < $1 LIMIT 500 FOR UPDATE SKIP LOCKED);",
        values: [boundary]
      });
      const affected = res.rowCount || 0;
      totalDeleted += affected;
      if (affected === 0) {
        break;
      }
      await sleep(150);
    }

    // SEQUENTIAL CACHE & METADATA RECLAIM (VACUUM targeted tables)
    await client.query("VACUUM nullifiers;");
    await client.query("VACUUM signatures;");

    // OPAQUE LOGGING INSULATION
    console.log("[PURGE] Execution completed successfully");
    
    return totalDeleted;
  } catch (error) {
    console.error("[PURGE] Execution completed with anomalies");
    throw error;
  } finally {
    // ATOMIC RELEASE PROTECTION
    if (client) {
      try {
        client.release();
      } catch (e) {}
    }
    // EXPLICIT BUFFER TEARDOWN (Heap Sanitization)
    client = null;
    boundary = null;
    totalDeleted = 0;
  }
}
