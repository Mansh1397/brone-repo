BEGIN;

-- ============================================================================
-- BRONE PHASE 4: PASSKEY HYBRID & ZK LEDGER MIGRATION
-- ============================================================================

-- 1. ZK Minted Commitments Table (Populated by AWS Nitro Enclave egress)
CREATE TABLE IF NOT EXISTS zk_commitments (
  commitment CHAR(64) PRIMARY KEY,
  signature TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_zk_commitments_created 
ON zk_commitments USING btree (created_at);

-- 2. Spent Nullifiers Table (Double-spend protection for anonymous claims)
CREATE TABLE IF NOT EXISTS spent_nullifiers (
  nullifier_hash CHAR(64) PRIMARY KEY,
  spent_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_spent_nullifiers_spent 
ON spent_nullifiers USING btree (spent_at);

COMMIT;
