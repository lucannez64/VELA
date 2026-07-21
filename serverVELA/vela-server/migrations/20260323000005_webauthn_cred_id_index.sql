-- Migration 005: indexed WebAuthn credential ID
--
-- The cross-account duplicate-credential check previously scanned every row
-- with a non-null recovery_webauthn_credential and deserialized the JSON to
-- compare cred_id. That's an unbounded full-table scan on every passkey
-- registration. This adds an indexed, unique column holding just the
-- credential ID so the check is a point lookup instead.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_webauthn_cred_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_webauthn_cred_id
    ON users(recovery_webauthn_cred_id);
