const { Pool } = require('pg');

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("Error: DATABASE_URL environment variable is not defined.");
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: databaseUrl.includes('render.com') ? { rejectUnauthorized: false } : false
  });

  try {
    console.log("Connecting to PostgreSQL database...");

    // Enable extensions
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`).catch(() => {});

    // 1. Table 1: decentralized_posts
    console.log("Creating table: decentralized_posts...");
    await pool.query(`
      CREATE TABLE IF NOT EXISTS decentralized_posts (
        ipfs_hash VARCHAR(255) PRIMARY KEY,
        geohash VARCHAR(20) NOT NULL,
        ring_signature TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'PENDING' NOT NULL,
        sprt_score NUMERIC(10, 4) DEFAULT 0.0000 NOT NULL,
        submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Creating index: idx_posts_geohash...");
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_posts_geohash ON decentralized_posts(geohash);
    `);

    // 2. Table 2: nullifiers
    console.log("Creating table: nullifiers...");
    await pool.query(`
      CREATE TABLE IF NOT EXISTS nullifiers (
        nullifier_hash VARCHAR(255) PRIMARY KEY,
        target_ipfs_hash VARCHAR(255) NOT NULL REFERENCES decentralized_posts(ipfs_hash) ON DELETE CASCADE,
        action_type VARCHAR(50) NOT NULL,
        spent_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Creating index: idx_nullifiers_target_ipfs_hash...");
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_nullifiers_target_ipfs_hash ON nullifiers(target_ipfs_hash);
    `);

    // 3. Table 3: reputation_ledger
    console.log("Creating table: reputation_ledger...");
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reputation_ledger (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        blind_token_hash VARCHAR(255) UNIQUE NOT NULL,
        metric_delta INTEGER NOT NULL,
        ecdsa_signature TEXT NOT NULL,
        redeemed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 4. Table 4: signatures (Double-Spend Guard)
    console.log("Creating table: signatures...");
    await pool.query(`
      CREATE TABLE IF NOT EXISTS signatures (
        tx_hash VARCHAR(255) PRIMARY KEY,
        recorded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Database initialized successfully!");
    process.exit(0);
  } catch (error) {
    console.error("Database migration/initialization failed:", error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
