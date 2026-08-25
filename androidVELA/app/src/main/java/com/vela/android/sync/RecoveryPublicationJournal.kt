package com.vela.android.sync

import android.content.Context
import org.json.JSONObject

/**
 * Keystore-encrypted write-ahead journal for one recovery split publication.
 * The full share set is committed before WebAuthn, server, or Drive I/O. Each
 * progress bit is synchronously committed after its idempotent external write,
 * allowing process death to retry the same split instead of minting another.
 */
internal data class RecoveryPublicationJournal(
    val accountId: String,
    val keyEpoch: Long,
    val splitId: String,
    val cloudShareB64: String,
    val serverShareB64: String,
    val trustedContactShareB64: String,
    /** Blind RMS commitment staged with the server share (M18). */
    val possessionHashB64: String = "",
    val serverStaged: Boolean = false,
    val cloudCandidateDurable: Boolean = false,
    val serverFinalized: Boolean = false,
    val cloudActive: Boolean = false,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("version", 1)
        .put("account_id", accountId)
        .put("key_epoch", keyEpoch)
        .put("split_id", splitId)
        .put("cloud_share_b64", cloudShareB64)
        .put("server_share_b64", serverShareB64)
        .put("trusted_contact_share_b64", trustedContactShareB64)
        .put("possession_hash_b64", possessionHashB64)
        .put("server_staged", serverStaged)
        .put("cloud_candidate_durable", cloudCandidateDurable)
        .put("server_finalized", serverFinalized)
        .put("cloud_active", cloudActive)

    companion object {
        fun fromJson(json: JSONObject): RecoveryPublicationJournal {
            require(json.getInt("version") == 1) { "Unsupported recovery journal version" }
            return RecoveryPublicationJournal(
                accountId = json.getString("account_id"),
                keyEpoch = json.getLong("key_epoch"),
                splitId = java.util.UUID.fromString(json.getString("split_id")).toString(),
                cloudShareB64 = json.getString("cloud_share_b64"),
                serverShareB64 = json.getString("server_share_b64"),
                trustedContactShareB64 = json.getString("trusted_contact_share_b64"),
                possessionHashB64 = json.optString("possession_hash_b64"),
                serverStaged = json.optBoolean("server_staged"),
                cloudCandidateDurable = json.optBoolean("cloud_candidate_durable"),
                serverFinalized = json.optBoolean("server_finalized"),
                cloudActive = json.optBoolean("cloud_active"),
            ).also {
                require(it.accountId.isNotBlank() && it.keyEpoch >= 1)
                require(!it.serverFinalized || (it.serverStaged && it.cloudCandidateDurable))
                require(!it.cloudActive || it.serverFinalized)
            }
        }
    }
}

internal class RecoveryPublicationJournalStore(context: Context) {
    private val prefs = EncryptedPrefs.open(context, "vela_recovery_publication")

    fun load(): RecoveryPublicationJournal? {
        val encoded = prefs.getString(KEY_JOURNAL, null) ?: return null
        // Fail closed: a corrupt unresolved journal must not be mistaken for
        // absence, which would mint and publish a different split.
        return RecoveryPublicationJournal.fromJson(JSONObject(encoded))
    }

    fun save(journal: RecoveryPublicationJournal) {
        check(prefs.edit().putString(KEY_JOURNAL, journal.toJson().toString()).commit()) {
            "Could not durably commit the recovery publication journal"
        }
    }

    fun clear() {
        check(prefs.edit().remove(KEY_JOURNAL).commit()) {
            "Could not retire the recovery publication journal"
        }
    }

    companion object {
        private const val KEY_JOURNAL = "journal_v1"
    }
}
