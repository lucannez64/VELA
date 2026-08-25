-- M16: two-phase recovery-share publication. Existing recovery_share rows are
-- implicitly finalized legacy records with a NULL recovery_split_id.
ALTER TABLE users ADD COLUMN recovery_split_id TEXT;
ALTER TABLE users ADD COLUMN recovery_pending_share TEXT;
ALTER TABLE users ADD COLUMN recovery_pending_split_id TEXT;
ALTER TABLE users ADD COLUMN recovery_pending_epoch INTEGER;
