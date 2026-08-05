import { pool } from "../controllers/ringValidator";

export async function initDB(): Promise<void> {
  console.log("[DB] Starting Zero-Knowledge database schema verification...");
  try {
    // Enable extensions
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`).catch(() => {});

    // Table 1: decentralized_posts
    await pool.query(`
      CREATE TABLE IF NOT EXISTS decentralized_posts (
        ipfs_hash VARCHAR(255) PRIMARY KEY,
        geohash VARCHAR(20) NOT NULL,
        ring_signature TEXT NOT NULL,
        encrypted_payload TEXT,
        status VARCHAR(50) DEFAULT 'PENDING' NOT NULL,
        sprt_score NUMERIC(10, 4) DEFAULT 0.0000 NOT NULL,
        submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Alter table to add encrypted_payload if it exists in legacy databases
    await pool.query(`ALTER TABLE decentralized_posts ADD COLUMN IF NOT EXISTS encrypted_payload TEXT;`).catch(() => {});

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_posts_geohash ON decentralized_posts(geohash);
    `);

    // Table 2: nullifiers
    await pool.query(`
      CREATE TABLE IF NOT EXISTS nullifiers (
        nullifier_hash VARCHAR(255) PRIMARY KEY,
        target_ipfs_hash VARCHAR(255) NOT NULL REFERENCES decentralized_posts(ipfs_hash) ON DELETE CASCADE,
        action_type VARCHAR(50) NOT NULL,
        spent_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_nullifiers_target_ipfs_hash ON nullifiers(target_ipfs_hash);
    `);

    // Table 3: reputation_ledger
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reputation_ledger (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        blind_token_hash VARCHAR(255) UNIQUE NOT NULL,
        metric_delta INTEGER NOT NULL,
        ecdsa_signature TEXT NOT NULL,
        redeemed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Table 4: signatures (Double-Spend Guard)
    const hasTxHash = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'signatures' AND column_name = 'tx_hash';
    `);
    if (hasTxHash.rows.length === 0) {
      await pool.query(`DROP TABLE IF EXISTS signatures CASCADE;`);
      await pool.query(`
        CREATE TABLE signatures (
          tx_hash VARCHAR(255) PRIMARY KEY,
          recorded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
      `);
    } else {
      const txHashType = await pool.query(`
        SELECT character_maximum_length FROM information_schema.columns
        WHERE table_name = 'signatures' AND column_name = 'tx_hash';
      `);
      if (txHashType.rows[0]?.character_maximum_length !== 255) {
        await pool.query(`DROP TABLE IF EXISTS signatures CASCADE;`);
        await pool.query(`
          CREATE TABLE signatures (
            tx_hash VARCHAR(255) PRIMARY KEY,
            recorded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
          );
        `);
      }
    }

    // Table 5: anonymous_votes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS anonymous_votes (
        id SERIAL PRIMARY KEY,
        ipfs_hash VARCHAR(90) NOT NULL,
        vote_decision VARCHAR(10) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Table 6: anonymous_public_keys
    const hasKeyHash = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'anonymous_public_keys' AND column_name = 'key_hash';
    `);
    if (hasKeyHash.rows.length === 0) {
      await pool.query(`DROP TABLE IF EXISTS anonymous_public_keys CASCADE;`);
      await pool.query(`
        CREATE TABLE anonymous_public_keys (
          key_hash VARCHAR(255) PRIMARY KEY,
          public_key_hex TEXT NOT NULL
        );
      `);
    } else {
      const keyHashType = await pool.query(`
        SELECT character_maximum_length FROM information_schema.columns
        WHERE table_name = 'anonymous_public_keys' AND column_name = 'key_hash';
      `);
      if (keyHashType.rows[0]?.character_maximum_length !== 255) {
        await pool.query(`DROP TABLE IF EXISTS anonymous_public_keys CASCADE;`);
        await pool.query(`
          CREATE TABLE anonymous_public_keys (
            key_hash VARCHAR(255) PRIMARY KEY,
            public_key_hex TEXT NOT NULL
          );
        `);
      }
    }

    console.log('[DB] Zero-Knowledge schema verified.');
  } catch (error: any) {
    console.error("[DB FATAL] Database initialization/migration failed:", error.message || error);
    throw error;
  }
}
