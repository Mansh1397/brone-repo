-- ============================================================================
-- BRONE SECURE PRODUCTION DATABASE SCHEMA
-- PHASE 11G: CRYPTOGRAPHICALLY DECOUPLED IDENTITY & REGISTRY SPECIFICATION
-- ============================================================================

-- 1. Core Segregated Identity Table (Public Keys)
-- Stores public keys of registered users to build our verification ring ledger.
-- Banned: Foreign keys, tracking profiles, or physical link indexes.
CREATE TABLE IF NOT EXISTS user_identities (
    user_id SERIAL PRIMARY KEY,
    public_key TEXT NOT NULL UNIQUE,
    assigned_cell_id VARCHAR(32),
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_assigned_cell ON user_identities(assigned_cell_id);

-- decentralized posts metadata pointers
CREATE TABLE IF NOT EXISTS decentralized_posts (
    id SERIAL PRIMARY KEY,
    ipfs_hash VARCHAR(90) UNIQUE NOT NULL,
    macro_region_cell_id VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_posts_macro_region ON decentralized_posts(macro_region_cell_id);
CREATE INDEX IF NOT EXISTS idx_posts_ipfs_hash ON decentralized_posts(ipfs_hash);
CREATE INDEX IF NOT EXISTS idx_posts_cell_id ON decentralized_posts(macro_region_cell_id);

-- Tasks and leases tables for relational task allocation lease logic
CREATE TABLE IF NOT EXISTS tasks (
    task_id VARCHAR(64) PRIMARY KEY,
    active_lease_count INTEGER DEFAULT 0 NOT NULL
);

CREATE TABLE IF NOT EXISTS leases (
    ephemeral_juror_hash VARCHAR(64) PRIMARY KEY,
    task_id VARCHAR(64) NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    leased_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    ephemeral_public_key TEXT NOT NULL
);



-- 2. Asynchronous Witness Hold Queue Table
-- Temporary holding queue for colliding SimHash entries pending verification.
CREATE TABLE IF NOT EXISTS witness_hold_slots (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    slot_index INTEGER NOT NULL,
    sim_hash VARCHAR(32) NOT NULL,
    latitude NUMERIC(9, 6) NOT NULL,
    longitude NUMERIC(9, 6) NOT NULL,
    stance VARCHAR(4) NOT NULL, -- 'PRO' or 'CON'
    pow_nonce VARCHAR(128) NOT NULL,
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT unique_event_slot UNIQUE (event_id, slot_index)
);

CREATE INDEX IF NOT EXISTS idx_witness_event_slot ON witness_hold_slots(event_id, slot_index);


-- 3. Decoupled Spent Nullifiers Table
-- Stores cryptographic nullifiers of spent anonymous reward vouchers.
-- Completely isolated from user identities to prevent correlation/linkage tracking.
CREATE TABLE IF NOT EXISTS spent_nullifiers (
    nullifier_hash VARCHAR(64) PRIMARY KEY,
    spent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_spent_nullifiers_hash ON spent_nullifiers(nullifier_hash);


-- 4. Active Jury Allocations Table
CREATE TABLE IF NOT EXISTS active_jury_allocations (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    juror_id VARCHAR(64) NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT unique_event_juror UNIQUE (event_id, juror_id)
);

CREATE INDEX IF NOT EXISTS idx_jury_event_alloc ON active_jury_allocations(event_id);


-- 5. Ephemeral Author Notification Settlement Vault
CREATE TABLE IF NOT EXISTS encrypted_notification_envelopes (
    envelope_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID NOT NULL UNIQUE,
    encrypted_status_payload TEXT NOT NULL, -- Contains verification state encrypted with the author's single-use notification public key
    delivered_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pending_envelopes ON encrypted_notification_envelopes (post_id) WHERE delivered_at IS NULL;

-- ============================================================================
-- PHASE 11G/H OVERLAY: CORE POSTING RAILS AND STRUCTURAL HARDENING
-- ============================================================================



-- 6. Public Approved Content Matrix
-- Houses lightweight metadata pointers for published grid items with absolute relational isolation.
CREATE TABLE IF NOT EXISTS verified_posts (
    post_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spatial_grid_id VARCHAR(32) NOT NULL,
    encrypted_payload_ipfs_hash VARCHAR(128) NOT NULL UNIQUE,
    verification_score NUMERIC(5,2) NOT NULL,
    published_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_spatial_posts ON verified_posts (spatial_grid_id, published_at DESC);

-- Apply Foreign Key constraint safely to the notification settlement vault
-- Enforces data hygiene upon system purges without leaking identity data graphs.
ALTER TABLE encrypted_notification_envelopes 
    ADD CONSTRAINT fk_envelope_post_id 
    FOREIGN KEY (post_id) REFERENCES verified_posts(post_id) ON DELETE CASCADE;

-- 7. Telemetry & Reputation Ledger persistency tables
CREATE TABLE IF NOT EXISTS signatures (
    signature VARCHAR(130) PRIMARY KEY,
    reputation_key VARCHAR(130) NOT NULL,
    metric_type VARCHAR(64) NOT NULL,
    metric_value INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signatures_reputation_key ON signatures(reputation_key);

CREATE TABLE IF NOT EXISTS reputation_ledger (
    reputation_key VARCHAR(130) NOT NULL,
    metric_name VARCHAR(64) NOT NULL,
    value BIGINT DEFAULT 0 NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT unique_key_metric UNIQUE (reputation_key, metric_name)
) WITH (fillfactor = 70);

CREATE INDEX IF NOT EXISTS idx_reputation_ledger_key_metric ON reputation_ledger (reputation_key, metric_name) WITH (fillfactor = 70);