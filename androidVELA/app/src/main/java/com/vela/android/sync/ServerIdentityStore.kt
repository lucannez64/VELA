package com.vela.android.sync

import android.content.Context
import android.util.Log
import com.vela.android.core.NativeVelaCore
import java.security.SecureRandom
import java.util.Base64
import org.json.JSONObject

/**
 * What this device is, as far as the app is concerned: identifiers, public keys,
 * and an opaque sealed blob.
 *
 * The private halves — the long-term signing key that authenticates this device
 * to the server, and the share decapsulation key that opens everything shared
 * with it — are deliberately absent. They live behind a native handle
 * ([NativeVelaCore.IdentityHandle]); this record only carries the sealed bytes
 * that let the native side reconstruct them. Holding them here as base64 strings
 * meant an un-zeroizable copy on the JVM heap, readable from any heap dump or
 * crash report (audit C-1).
 */
data class ServerIdentity(
    val userId: String?,
    val deviceId: String?,
    val hybridEkB64: String,
    val hybridVkB64: String,
    val shareEkB64: String = "",
    val sealedB64: String = "",
    val shareEkRegistrationPending: Boolean = false,
    /** M19: device-signed binding metadata for the initial share key. */
    val shareEkSignedAt: String? = null,
    val shareEkSignature: String? = null,
)

class ServerIdentityStore(context: Context) {
    // Backed by the Android Keystore. That protects the blob at rest; keeping
    // the private keys out of Kotlin protects them in memory.
    private val prefs = EncryptedPrefs.open(context, "vela_server_identity")

    /** Handle for the loaded identity, opened lazily and reused. */
    @Volatile
    private var handle: NativeVelaCore.IdentityHandle? = null

    fun load(): ServerIdentity? {
        val json = prefs.getString(KEY_IDENTITY_JSON, null) ?: return null
        val parsed = runCatching { JSONObject(json) }.getOrNull() ?: return null
        migrateLegacyPlaintextKeys(parsed)?.let { return it }
        return runCatching { fromJson(parsed) }.getOrNull()
    }

    fun getOrCreate(): ServerIdentity {
        load()?.let { return it }
        val created = NativeVelaCore.identityCreate(sealKey())
            ?: error("Native VELA bridge cannot generate server identity")
        handle = created
        // M19: sign the initial share-key binding now, while the identity is
        // open; the signature travels with the publics to registration.
        val signedAt = java.time.Instant.now().toString()
        val shareEkSignature = com.vela.android.core.NativeVelaCore.identitySignShareEkBinding(
            handle = created.handle,
            shareEkB64 = created.shareEkB64,
            signedAt = signedAt,
        )
        val identity = ServerIdentity(
            userId = null,
            deviceId = null,
            hybridEkB64 = created.hybridEkB64,
            hybridVkB64 = created.hybridVkB64,
            shareEkB64 = created.shareEkB64,
            sealedB64 = created.sealedB64,
            // The initial share key has not reached the server yet; keep it
            // eligible for backfill if registration is interrupted.
            shareEkRegistrationPending = true,
            shareEkSignedAt = signedAt,
            shareEkSignature = shareEkSignature,
        )
        save(identity)
        return identity
    }

    /**
     * A brand-new identity for an enrollment v3 join, replacing any existing
     * one (audit P-1).
     *
     * Not [getOrCreate]: a device joining an account has to present a key it
     * generated for this enrollment. Reusing a stored identity would risk
     * presenting one made before v3, whose `hybrid_ek` has no private half kept
     * anywhere — it would claim the grant successfully and then be unable to
     * open the capsule sealed to it.
     */
    fun createForEnrollment(): ServerIdentity {
        close()
        val created = NativeVelaCore.identityCreate(sealKey())
            ?: error("Native VELA bridge cannot generate a device identity")
        handle = created
        // M19: sign the initial share-key binding now, while the identity is
        // open; the signature travels with the publics to registration.
        val signedAt = java.time.Instant.now().toString()
        val shareEkSignature = com.vela.android.core.NativeVelaCore.identitySignShareEkBinding(
            handle = created.handle,
            shareEkB64 = created.shareEkB64,
            signedAt = signedAt,
        )
        val identity = ServerIdentity(
            userId = null,
            deviceId = null,
            hybridEkB64 = created.hybridEkB64,
            hybridVkB64 = created.hybridVkB64,
            shareEkB64 = created.shareEkB64,
            sealedB64 = created.sealedB64,
            // The initial share key has not reached the server yet; keep it
            // eligible for backfill if registration is interrupted.
            shareEkRegistrationPending = true,
            shareEkSignedAt = signedAt,
            shareEkSignature = shareEkSignature,
        )
        save(identity)
        return identity
    }

    /** This device's own enrollment fingerprint, from the key it holds. */
    fun enrollmentFingerprint(): String? =
        handle()?.let { NativeVelaCore.identityEnrollmentFingerprint(it) }

    /**
     * Adopt key material that arrived from outside — today only the enrollment
     * code, which carries the signing key generated by the enrolling device.
     * The caller hands the bytes over once; from then on they live natively.
     */
    fun importFromEnrollment(
        deviceId: String?,
        hybridSkB64: String,
        hybridEkB64: String,
        hybridVkB64: String
    ): ServerIdentity {
        val imported = NativeVelaCore.identityImport(
            sealKey = sealKey(),
            hybridSkB64 = hybridSkB64,
            hybridEkB64 = hybridEkB64
        ) ?: error("Native VELA bridge cannot import the enrolled identity")
        handle = imported
        val identity = ServerIdentity(
            userId = null,
            deviceId = deviceId,
            // Trust the native side's view of the public halves: they are
            // recomputed from the key itself, so a malformed code cannot make
            // this device advertise keys it cannot actually use.
            hybridEkB64 = imported.hybridEkB64.ifBlank { hybridEkB64 },
            hybridVkB64 = imported.hybridVkB64.ifBlank { hybridVkB64 },
            shareEkB64 = imported.shareEkB64,
            sealedB64 = imported.sealedB64
        )
        save(identity)
        return identity
    }

    /** The native handle for the stored identity, opening it if needed. */
    fun handle(): Long? {
        handle?.let { return it.handle }
        val identity = load() ?: return null
        if (identity.sealedB64.isBlank()) return null
        val opened = NativeVelaCore.identityOpen(sealKey(), identity.sealedB64) ?: return null
        handle = opened
        return opened.handle
    }

    /** Generate a share keypair and remember that its public half still needs registration.
     *
     * The binding metadata (signedAt + signature) is refreshed for the ROTATED
     * key in the same persisted update: retaining the previous key's signature
     * would bind the old `shareEkB64`, so a registration retry for the rotated
     * key fails server verification and leaves the pending flag stuck. */
    fun rotateShareKey(): String? {
        val handleId = handle() ?: return null
        val rotated = NativeVelaCore.identityRotateShareKey(sealKey(), handleId) ?: return null
        val (shareEk, sealed) = rotated
        val signedAt = java.time.Instant.now().toString()
        val signature = handleId.takeIf { shareEk.isNotBlank() }?.let {
            NativeVelaCore.identitySignShareEkBinding(
                handle = it,
                shareEkB64 = shareEk,
                signedAt = signedAt,
            )
        }
        load()?.let {
            save(
                it.copy(
                    shareEkB64 = shareEk,
                    sealedB64 = sealed,
                    shareEkRegistrationPending = true,
                    // Fresh binding metadata for the NEW key — never carry the
                    // old key's signature forward.
                    shareEkSignedAt = signature?.let { _ -> signedAt },
                    shareEkSignature = signature,
                )
            )
        }
        handle = handle?.copy(shareEkB64 = shareEk, sealedB64 = sealed)
        return shareEk
    }

    /**
     * Clear the retry marker only if the key just acknowledged by the server
     * is still current.
     */
    fun markShareKeyRegistered(shareEkB64: String) {
        val identity = load() ?: return
        if (identity.shareEkB64 != shareEkB64) return
        save(identity.copy(shareEkRegistrationPending = false))
    }

    /** Drop the in-memory keys. Call on lock or sign-out. */
    fun close() {
        handle?.let { NativeVelaCore.identityForget(it.handle) }
        handle = null
    }

    fun save(identity: ServerIdentity) {
        prefs.edit().putString(KEY_IDENTITY_JSON, identity.toJson().toString()).apply()
    }

    /**
     * Rewrite an identity written before the keys moved behind a handle.
     *
     * The plaintext keys are read exactly once — there is no way to migrate
     * without touching them — sealed natively, and then dropped from storage.
     */
    private fun migrateLegacyPlaintextKeys(json: JSONObject): ServerIdentity? {
        val legacySk = json.optString("hybrid_sk_b64")
        if (legacySk.isBlank()) return null

        val imported = NativeVelaCore.identityImport(
            sealKey = sealKey(),
            hybridSkB64 = legacySk,
            shareDkB64 = json.optString("share_dk_b64"),
            hybridEkB64 = json.optString("hybrid_ek_b64")
        )
        if (imported == null) {
            Log.w(TAG, "could not migrate the stored identity; leaving it as-is")
            return null
        }
        handle = imported
        val migrated = ServerIdentity(
            userId = json.optString("user_id").takeIf { it.isNotBlank() },
            deviceId = json.optString("device_id").takeIf { it.isNotBlank() },
            hybridEkB64 = imported.hybridEkB64,
            hybridVkB64 = imported.hybridVkB64,
            shareEkB64 = imported.shareEkB64,
            sealedB64 = imported.sealedB64
        )
        save(migrated)
        Log.i(TAG, "migrated the stored identity behind a native handle")
        return migrated
    }

    /**
     * The 32-byte key the native side seals the identity under, minted once and
     * kept in the same Keystore-backed store.
     */
    private fun sealKey(): ByteArray {
        prefs.getString(KEY_SEAL_KEY, null)?.let { return Base64.getDecoder().decode(it) }
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        prefs.edit().putString(KEY_SEAL_KEY, Base64.getEncoder().encodeToString(key)).apply()
        return key
    }

    private fun fromJson(json: JSONObject): ServerIdentity {
        return ServerIdentity(
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
    }

    private fun ServerIdentity.toJson(): JSONObject {
        return JSONObject()
            .put("user_id", userId)
            .put("device_id", deviceId)
            .put("hybrid_ek_b64", hybridEkB64)
            .put("hybrid_vk_b64", hybridVkB64)
            .put("share_ek_b64", shareEkB64)
            .put("sealed_b64", sealedB64)
            .put("share_ek_registration_pending", shareEkRegistrationPending)
            .put("share_ek_signed_at", shareEkSignedAt)
            .put("share_ek_signature", shareEkSignature)
    }

    companion object {
        private const val TAG = "ServerIdentityStore"
        private const val KEY_IDENTITY_JSON = "identity_json"
        private const val KEY_SEAL_KEY = "identity_seal_key"
    }
}
