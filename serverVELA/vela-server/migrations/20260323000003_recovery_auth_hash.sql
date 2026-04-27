-- Migration 003: legacy recovery auth hash column
--
-- Retained for databases created before WebAuthn recovery ceremonies were
-- added. Current recovery uses the passkey credential stored by migration 004.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_auth_hash BYTEA;
