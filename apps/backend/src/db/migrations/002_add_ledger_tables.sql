BEGIN;

CREATE TABLE IF NOT EXISTS signatures (
  signature CHAR(130) PRIMARY KEY,
  reputation_key CHAR(130) NOT NULL,
  metric_type CHAR(64) NOT NULL,
  metric_value INTEGER NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signatures_reputation_key 
ON signatures USING btree (reputation_key) 
WITH (fillfactor = 90);

CREATE TABLE IF NOT EXISTS reputation_ledger (
  reputation_key CHAR(130) NOT NULL,
  metric_name CHAR(64) NOT NULL,
  value BIGINT DEFAULT 0 NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
  CONSTRAINT unique_key_metric UNIQUE (reputation_key, metric_name)
);

CREATE INDEX IF NOT EXISTS idx_reputation_ledger_key_metric 
ON reputation_ledger USING btree (reputation_key, metric_name) 
WITH (fillfactor = 90);

COMMIT;
