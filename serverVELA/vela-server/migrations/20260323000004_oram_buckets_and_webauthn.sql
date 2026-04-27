-- Migration 004: Path ORAM bucket/path storage and WebAuthn recovery credential

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_webauthn_credential TEXT;

CREATE TABLE IF NOT EXISTS oram_buckets (
    user_id       TEXT NOT NULL,
    tree_id       TEXT NOT NULL,
    bucket_index  INTEGER NOT NULL,
    version       INTEGER NOT NULL DEFAULT 1,
    lamport_clock INTEGER NOT NULL DEFAULT 0,
    last_writer   TEXT,
    ciphertext    TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oram_buckets_user_tree_bucket
    ON oram_buckets(user_id, tree_id, bucket_index);
