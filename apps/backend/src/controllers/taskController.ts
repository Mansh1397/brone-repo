import { Request, Response } from "express";
import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/**
 * Blind Task Broadcast Endpoint
 * GET /api/v1/arbitration/feed
 * 
 * Serves a global, paginated array of recent encrypted task envelopes.
 * MUST NOT accept or process any identifying user parameters (no pubkeys, no session IDs).
 */
export async function getArbitrationFeed(req: Request, res: Response) {
  try {
    const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit as string, 10) || 20));
    const offset = (page - 1) * limit;

    const queryText = `
      SELECT 
        ipfs_hash AS task_id,
        ipfs_hash,
        macro_region_cell_id AS geohash,
        created_at AS timestamp
      FROM decentralized_posts
      ORDER BY created_at DESC
      LIMIT $1 OFFSET $2;
    `;

    const result = await pool.query(queryText, [limit, offset]);

    const feed = result.rows.map((row: any) => ({
      taskId: row.task_id,
      ipfsHash: row.ipfs_hash,
      geohash: row.geohash,
      timestamp: row.timestamp,
      encryptedEnvelope: {
        version: "1.0.0-phase1",
        ciphertext: row.ipfs_hash, // Task payload reference CID
      }
    }));

    return res.status(200).json({
      success: true,
      page,
      limit,
      tasks: feed
    });
  } catch (error: any) {
    console.error("[ARBITRATION FEED ERROR] Failed to fetch task broadcast:", error.message || error);
    return res.status(500).json({ error: "Systemic task broadcast retrieval anomaly" });
  }
}
