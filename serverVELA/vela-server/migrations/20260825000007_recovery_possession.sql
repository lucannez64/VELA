-- Migration 007 (M18): staged RMS-possession commitment.
--
-- The commitment rides the two-phase publication protocol: `put_share`
-- stages it alongside the pending server share, and `finalize_share`
-- promotes it into `recovery_auth_hash` atomically with the share. The
-- column lets a recovering client prove possession of the reconstructed
-- RMS — so any two-share pair (including trusted-contact pairs that never
-- touch the server share) can obtain an enrollment grant without WebAuthn.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_pending_auth_hash TEXT;
