-- Migration 002: per-user Shamir recovery share storage (§4.3)
--
-- Share 2 of the 2-of-3 SSS scheme is stored here as an opaque BYTEA blob.
-- It is encrypted client-side under a key derived from the user's FIDO2
-- credential before being uploaded; the server never sees the plaintext.
--
-- A single nullable column on `users` is sufficient — each user has at most
-- one recovery share stored at any time.  Uploading a new share overwrites
-- the previous one (e.g. after rotating the FIDO2 credential).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_share BYTEA;
