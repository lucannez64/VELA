package com.vela.android.sync

import org.json.JSONObject

/**
 * The persisted form of [ServerIdentity].
 *
 * Decoding is strict about the public keys (a record without them is not a
 * usable identity) and returns `null` for unreadable JSON, so a corrupt record
 * is treated as "no pin" rather than as an empty account.
 */
internal object ServerIdentityJson {
    fun decode(raw: String?): ServerIdentity? {
        if (raw.isNullOrBlank()) return null
        return runCatching {
            val json = JSONObject(raw)
            ServerIdentity(
                userId = json.optString("user_id").takeIf { it.isNotBlank() },
                deviceId = json.optString("device_id").takeIf { it.isNotBlank() },
                hybridEkB64 = json.getString("hybrid_ek_b64"),
                hybridVkB64 = json.getString("hybrid_vk_b64"),
                shareEkB64 = json.optString("share_ek_b64"),
                sealedB64 = json.optString("sealed_b64"),
                shareEkRegistrationPending = json.optBoolean("share_ek_registration_pending", false),
                shareEkSignedAt = json.optString("share_ek_signed_at").takeIf { it.isNotBlank() },
                shareEkSignature = json.optString("share_ek_signature").takeIf { it.isNotBlank() },
            )
        }.getOrNull()
    }

    fun encode(identity: ServerIdentity): String = JSONObject()
        .put("user_id", identity.userId)
        .put("device_id", identity.deviceId)
        .put("hybrid_ek_b64", identity.hybridEkB64)
        .put("hybrid_vk_b64", identity.hybridVkB64)
        .put("share_ek_b64", identity.shareEkB64)
        .put("sealed_b64", identity.sealedB64)
        .put("share_ek_registration_pending", identity.shareEkRegistrationPending)
        .put("share_ek_signed_at", identity.shareEkSignedAt)
        .put("share_ek_signature", identity.shareEkSignature)
        .toString()
}

/**
 * One serialized whole-record identity cell.
 *
 * The previous store wrote with `SharedPreferences.apply()` while the bearer
 * token was committed synchronously. A crash could therefore leave a durable
 * token with no identity pin, and a later sync would fall back to an empty
 * account namespace. [writeRaw] must commit synchronously and throw on
 * failure; it runs while the same monitor holds the record, so a whole-record
 * writer cannot interleave with a targeted update (for example a share-key
 * rotation) and resurrect an older copy.
 */
internal class SerializedIdentityRecord(
    private val readRaw: () -> String?,
    private val writeRaw: (String) -> Unit,
) {
    private val monitor = Any()

    /** Raw bytes for the legacy-plaintext migration path. */
    fun raw(): String? = synchronized(monitor) { readRaw() }

    fun load(): ServerIdentity? = synchronized(monitor) {
        ServerIdentityJson.decode(readRaw())
    }

    fun save(identity: ServerIdentity) {
        synchronized(monitor) {
            writeRaw(ServerIdentityJson.encode(identity))
        }
    }

    /**
     * Read, transform and write the current record as one critical section.
     * Returns `null` when there is no readable record, in which case nothing
     * is written.
     */
    fun update(transform: (ServerIdentity) -> ServerIdentity): ServerIdentity? =
        synchronized(monitor) {
            val current = ServerIdentityJson.decode(readRaw()) ?: return@synchronized null
            val next = transform(current)
            writeRaw(ServerIdentityJson.encode(next))
            next
        }
}
