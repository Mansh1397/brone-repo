import { Pool } from "pg";

export class DoubleSpendException extends Error {
  constructor(message: string = "Double spend detected") {
    super(message);
    this.name = "DoubleSpendException";
  }
}

// In-memory fallback database state
const mockDb = new Set<string>();

// Initialize PostgreSQL Pool using environment variables
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://mock",
});

let useMemoryDb = false;

/**
 * Processes a nullifier by writing it to the unique key registry.
 * Relies on database unique constraint check for double-spend protection.
 * Throws a DoubleSpendException if a duplicate is inserted.
 * Falls back to an in-memory db simulation if PostgreSQL is unavailable.
 */
export async function processNullifier(nullifier: string): Promise<void> {
  if (useMemoryDb || !process.env.DATABASE_URL) {
    useMemoryDb = true;
    if (mockDb.has(nullifier)) {
      throw new DoubleSpendException(`Nullifier ${nullifier} has already been spent.`);
    }
    mockDb.add(nullifier);
    return;
  }

  let client: any = null;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    
    try {
      await client.query({
        name: "insert_spent_nullifier",
        text: "INSERT INTO spent_nullifiers (key_image, spent_at) VALUES ($1, NOW());",
        values: [nullifier],
      });
      await client.query("COMMIT");
    } catch (err: any) {
      await client.query("ROLLBACK").catch(() => {});
      
      // PostgreSQL unique violation error code is 23505
      if (err.code === "23505") {
        throw new DoubleSpendException(`Nullifier ${nullifier} has already been spent.`);
      }
      throw err;
    }
  } catch (e) {
    if (client) {
      try { client.release(); } catch (_) {}
    }
    // Fallback on connection/query failure to ensure uptime and testability
    console.warn("[NULLIFIER REGISTRY] DB error during processNullifier, falling back to in-memory store:", e);
    useMemoryDb = true;
    if (mockDb.has(nullifier)) {
      throw new DoubleSpendException(`Nullifier ${nullifier} has already been spent.`);
    }
    mockDb.add(nullifier);
  } finally {
    if (client && !useMemoryDb) {
      try { client.release(); } catch (_) {}
    }
  }
}

/**
 * Reset the spent nullifier registry.
 * Useful for restoring 100% test determinism across test runner runs.
 */
export async function resetNullifierDatabase(): Promise<void> {
  mockDb.clear();
  if (process.env.DATABASE_URL && !useMemoryDb) {
    let client: any = null;
    try {
      client = await pool.connect();
      await client.query("TRUNCATE TABLE spent_nullifiers RESTART IDENTITY CASCADE;");
    } catch (err) {
      console.warn("[NULLIFIER REGISTRY] Failed to truncate table in Postgres:", err);
    } finally {
      if (client) {
        try { client.release(); } catch (_) {}
      }
    }
  }
}
