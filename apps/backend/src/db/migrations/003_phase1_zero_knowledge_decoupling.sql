BEGIN;

-- ============================================================================
-- BRONE PHASE 1: GOD-MODE ZERO-KNOWLEDGE DECOUPLING MIGRATION
-- ============================================================================

-- 1. Eradicate Task-to-Juror Relational Links
DROP TABLE IF EXISTS leases CASCADE;
DROP TABLE IF EXISTS active_jury_allocations CASCADE;

ALTER TABLE tasks DROP COLUMN IF EXISTS active_lease_count;

-- 2. Memory-Safe Blind OTP Sybil Resistance Ledger
CREATE TABLE IF NOT EXISTS verified_phones_hashes (
  phone_hash CHAR(64) PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verified_phones_hashes_created 
ON verified_phones_hashes USING btree (created_at);

-- 3. Anonymous Key Registration Double-Spend Prevention Ledger
CREATE TABLE IF NOT EXISTS spent_registration_tokens (
  token_hash CHAR(64) PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_spent_registration_tokens_created 
ON spent_registration_tokens USING btree (created_at);

COMMIT;
