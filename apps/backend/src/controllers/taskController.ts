import { Request, Response } from "express";
import { Pool } from "pg";
import * as crypto from "crypto";

// Initialize Postgres Pool
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Generate or reuse server RSA key pair for stateless ticket signatures
const BACKEND_PRIVATE_KEY = process.env.BACKEND_PRIVATE_KEY || crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
}).privateKey;

/**
 * Mints a cryptographically verifiable Lease Ticket.
 */
export function signLeaseTicket(payload: { taskId: string; juror_hash: string; expires_at: number }): string {
  const data = JSON.stringify(payload);
  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();
  const signature = sign.sign(BACKEND_PRIVATE_KEY, "base64");
  return Buffer.from(JSON.stringify({ payload, signature })).toString("base64");
}

/**
 * Handles transactional lease allocation for jurors.
 * POST /tasks/:taskId/acquire-lease
 */
export async function acquireLease(req: Request, res: Response) {
  const { taskId } = req.params;
  const { juror_hash, ephemeral_public_key } = req.body;

  if (!juror_hash || !ephemeral_public_key) {
    return res.status(400).json({ error: "Missing required parameters: juror_hash, ephemeral_public_key" });
  }

  // Acquire a client from the pool
  const client = await pool.connect();
  try {
    let expiresAt = 0;

    await client.query("BEGIN");

    try {
      // 1. Read the parent task row with a write lock
      const taskDoc = await client.query("SELECT active_lease_count FROM tasks WHERE task_id = $1 FOR UPDATE", [taskId]);
      if (taskDoc.rows.length === 0) {
        throw { status: 404, message: "Task Not Found" };
      }

      const currentLeaseCount = taskDoc.rows[0].active_lease_count ?? 0;

      // 2. Verify active slot capacity
      if (currentLeaseCount >= 3) {
        throw { status: 423, message: "SLOT_OCCUPIED" };
      }

      // 3. Verify if an unexpired lease already exists for this juror
      const leaseDoc = await client.query(
        "SELECT expires_at FROM leases WHERE ephemeral_juror_hash = $1 AND task_id = $2 FOR UPDATE",
        [juror_hash, taskId]
      );

      const now = Date.now();
      if (leaseDoc.rows.length > 0) {
        const expiresAtVal = Number(leaseDoc.rows[0].expires_at);
        if (expiresAtVal > now) {
          throw { status: 409, message: "Lease already exists and has not expired" };
        }
      }

      // 4. Mutate State Natively
      const nextLeaseCount = currentLeaseCount + 1;
      await client.query("UPDATE tasks SET active_lease_count = $1 WHERE task_id = $2", [nextLeaseCount, taskId]);

      // 5. Write slot lock allocation parameter
      expiresAt = now + 600000; // Exactly 10 minutes from now

      // Delete any expired lease first to avoid constraint violation if present
      await client.query("DELETE FROM leases WHERE ephemeral_juror_hash = $1 AND task_id = $2", [juror_hash, taskId]);

      await client.query(
        "INSERT INTO leases (ephemeral_juror_hash, task_id, leased_at, expires_at, ephemeral_public_key) VALUES ($1, $2, $3, $4, $5)",
        [juror_hash, taskId, now, expiresAt, ephemeral_public_key]
      );

      await client.query("COMMIT");
    } catch (txError) {
      await client.query("ROLLBACK").catch(() => {});
      throw txError;
    }

    // 6. Stateless Ticket Generation post-commit
    const ticketPayload = {
      taskId,
      juror_hash,
      expires_at: expiresAt
    };
    const ticket = signLeaseTicket(ticketPayload);

    return res.status(200).json({
      success: true,
      lease_ticket: ticket
    });

  } catch (error: any) {
    if (error.status) {
      return res.status(error.status).json({ error: error.message });
    }
    return res.status(500).json({ error: error.message || "Internal database transaction failure" });
  } finally {
    // Release client connection back to pool
    client.release();
  }
}
