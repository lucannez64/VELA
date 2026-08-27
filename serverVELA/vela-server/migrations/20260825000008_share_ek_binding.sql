-- Migration 008 (M19): authenticated share-key bindings.
--
-- `share_ek` rows now carry the signing device and the binding timestamp of
-- the signature that authorized them (`vela share-ek binding v1`, signed
-- under an enrolled device's hybrid identity key). `share_ek_since` is also
-- compared monotonically at registration time so replayed older signatures
-- cannot roll a key back.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS share_ek_since TEXT;
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS share_ek_device_id TEXT;
