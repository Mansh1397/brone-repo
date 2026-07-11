export interface TaskDocument {
  task_id: string;
  geohash_sector: string;
  ipfs_cid: string;
  encrypted_symmetric_key: string;
  epoch_id: string;
  status: "pending" | "verified" | "rejected";
  active_lease_count: number;
  created_at: number;
}

export interface LeaseDocument {
  ephemeral_juror_hash: string;
  leased_at: number;
  expires_at: number;
  ephemeral_public_key: string;
}
