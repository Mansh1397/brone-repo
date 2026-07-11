BEGIN;

CREATE TABLE IF NOT EXISTS spent_nullifiers (
  id BIGSERIAL PRIMARY KEY,
  key_image CHAR(64) NOT NULL UNIQUE,
  spent_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_spent_nullifiers_key_image 
ON spent_nullifiers USING btree (key_image) 
WITH (fillfactor = 90);

CREATE TABLE IF NOT EXISTS ephemeral_sessions (
  id BIGSERIAL PRIMARY KEY,
  session_token CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ephemeral_sessions_expires_at 
ON ephemeral_sessions USING btree (expires_at) 
WITH (fillfactor = 90);

COMMIT;
