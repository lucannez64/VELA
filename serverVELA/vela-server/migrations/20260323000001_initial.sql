-- VELA Protocol v2.0 — initial schema
-- PostgreSQL 15+

-- ─── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL    DEFAULT NOW()
);

-- ─── Devices ──────────────────────────────────────────────────────────────────
-- Each row is a hardware-bound device enrolled by a user.
--
-- Key material stored:
--   hybrid_ek   — ML-KEM-1024 (1568 B) ‖ X25519 (32 B) = 1600 B total
--                 A real, valid KEM public key advertised as part of this
--                 device's identity. Not currently used to seal anything —
--                 rms_capsule below is sealed with a symmetric transfer key
--                 delivered out-of-band via the enrollment code, not by KEM
--                 encapsulation under hybrid_ek.
--   hybrid_vk   — ML-DSA-87 (2592 B) ‖ Ed25519 (32 B) = 2624 B total
--                 Used to verify authentication and enrollment signatures.
CREATE TABLE devices (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Hybrid encapsulation public key (1600 bytes)
    hybrid_ek   BYTEA       NOT NULL,
    -- Hybrid signing verifying key (2624 bytes)
    hybrid_vk   BYTEA       NOT NULL,

    -- Enrollment provenance
    enrolled_by UUID        REFERENCES devices(id),   -- NULL for the first device

    -- RMS capsule: AEAD-encrypted under a random symmetric transfer key that
    -- is delivered to the new device out-of-band (via the enrollment code),
    -- not under hybrid_ek. Cleared after the device downloads it.
    rms_capsule BYTEA,

    -- Revocation
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at  TIMESTAMPTZ,
    revoked_by  UUID        REFERENCES devices(id),

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_user_id  ON devices(user_id);
CREATE INDEX idx_devices_revoked  ON devices(user_id, revoked);

-- ─── Vault chunks (ORAM tree storage) ────────────────────────────────────────
-- Server stores opaque 1 MB encrypted blobs.
-- Chunk layout is managed client-side via Path ORAM.
-- The server only tracks chunk_id, version, lamport_clock, and last_writer
-- for the sync manifest and optimistic concurrency.
CREATE TABLE vault_chunks (
    chunk_id      UUID        PRIMARY KEY,
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Server-managed monotonic counter for optimistic locking (If-Match).
    version       BIGINT      NOT NULL DEFAULT 1,
    -- Client-managed logical clock for conflict detection.
    lamport_clock BIGINT      NOT NULL DEFAULT 0,
    -- Which device last wrote this chunk.
    last_writer   UUID        REFERENCES devices(id),

    -- Fixed 1 MB ciphertext blob (XChaCha20-Poly1305, padded by client).
    ciphertext    BYTEA       NOT NULL,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vault_chunks_user ON vault_chunks(user_id);

-- Auto-update updated_at on write
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_vault_chunks_updated_at
    BEFORE UPDATE ON vault_chunks
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ─── Share inbox ──────────────────────────────────────────────────────────────
-- Encrypted vault-item capsules delivered from one user to another via
-- POST /share/send.  Each capsule is a Hybrid KEM ciphertext wrapping a
-- specific vault item; the server is never able to decrypt it.
CREATE TABLE share_inbox (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Serialised HybridCapsule bytes + AEAD-encrypted vault item payload.
    capsule           BYTEA       NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_share_inbox_recipient ON share_inbox(recipient_user_id, created_at DESC);
