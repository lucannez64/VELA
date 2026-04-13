-- Migration 003: recovery auth hash for proof-of-identity during recovery
--
-- Stores a BLAKE3 hash that the client must prove knowledge of to retrieve
-- their encrypted recovery share via POST /recovery/recover.
--
-- The preimage is derived from the user's FIDO2/passkey credential client-side.
-- This is a placeholder for full WebAuthn server-side verification.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_auth_hash BYTEA;
