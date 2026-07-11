-- ============================================================================
-- BRONE SECURE DATABASE PRODUCTION TUNING SPECIFICATION
-- PHASE 11G: HIGH CONCURRENCY B-TREE INDEXING & HOT UPDATE OPTIMIZATION
-- ============================================================================

-- Add high-performance B-Tree indexes to optimize concurrent lookups on decentralized posts
CREATE INDEX IF NOT EXISTS idx_posts_ipfs_hash ON decentralized_posts USING btree (ipfs_hash);
CREATE INDEX IF NOT EXISTS idx_posts_cell_id ON decentralized_posts USING btree (macro_region_cell_id);

-- Tune reputation_ledger table and index to support heavy concurrent jury voting blocks
-- A lower fillfactor reserves space on table pages to permit Heap-Only Tuple (HOT) updates,
-- preventing write lock contention and index modification overhead.
ALTER TABLE reputation_ledger SET (fillfactor = 70);
ALTER INDEX idx_reputation_ledger_key_metric SET (fillfactor = 70);
