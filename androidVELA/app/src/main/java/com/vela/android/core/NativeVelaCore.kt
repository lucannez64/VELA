package com.vela.android.core

import org.json.JSONObject
import java.util.Base64

object NativeVelaCore {
    private val loadFailure: Throwable? = runCatching {
        System.loadLibrary("vela_android_bridge")
    }.exceptionOrNull()
    private val loaded: Boolean = loadFailure == null

    fun isAvailable(): Boolean = loaded

    fun versionOrNull(): String? {
        return callNative { nativeVersion() }
    }

    // The RMS crosses JNI as a ByteArray, never as a base64 String: JVM strings
    // are immutable, may be interned, are never zeroized, and survive in heap
    // dumps and crash reports (audit C-1). Callers wipe their array with
    // `fill(0)`; the Rust side wipes its copy on drop.

    fun encryptVaultJson(rms: ByteArray, vaultJson: String): String? {
        return callNative {
            val request = JSONObject()
                .put("vault_json", vaultJson)
                .toString()
            val response = JSONObject(nativeEncryptVaultJson(rms, request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("ciphertext_b64")
        }
    }

    fun decryptVaultJson(rms: ByteArray, ciphertext: ByteArray): String? {
        return callNative {
            val request = JSONObject()
                .put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            val response = JSONObject(nativeDecryptVaultJson(rms, request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("vault_json")
        }
    }

    fun encryptVaultChunkJson(rms: ByteArray, chunkId: String, vaultJson: String): String? {
        return callNative {
            val request = JSONObject()
                .put("chunk_id", chunkId)
                .put("vault_json", vaultJson)
                .toString()
            val response = JSONObject(nativeEncryptVaultChunkJson(rms, request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("ciphertext_b64")
        }
    }

    fun decryptVaultChunkJson(rms: ByteArray, chunkId: String, ciphertext: ByteArray): String? {
        return callNative {
            val request = JSONObject()
                .put("chunk_id", chunkId)
                .put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            val response = JSONObject(nativeDecryptVaultChunkJson(rms, request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("vault_json")
        }
    }

    /// Short out-of-band verification code for an enrollment code string.
    /// Compute this right after scanning/pasting an enrollment code and show
    /// it to the user to confirm against the enrolling device's screen
    /// *before* calling into the enrollment flow — neither device can
    /// otherwise establish trust in who actually produced the code.
    fun enrollmentVerificationCode(code: String): String? {
        return callNative { nativeEnrollmentVerificationCode(code) }
    }




    fun decryptRmsCapsule(transferKeyB64: String, capsuleB64: String): ByteArray? {
        return callNative {
            val request = JSONObject()
                .put("transfer_key_b64", transferKeyB64)
                .put("capsule_b64", capsuleB64)
                .toString()
            // The RMS comes back through this array, not through the JSON: a
            // base64 String would be another un-zeroizable copy (audit C-1).
            val rms = ByteArray(32)
            val response = JSONObject(nativeDecryptRmsCapsuleJson(request, rms))
            response.optString("error").takeIf { it.isNotBlank() }?.let {
                rms.fill(0)
                error(it)
            }
            rms
        }
    }

    fun decryptEnrollmentPackage(packageKey: ByteArray, ciphertext: ByteArray): String? {
        return callNative {
            val request = JSONObject()
                .put("key_b64", Base64.getEncoder().encodeToString(packageKey))
                .put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            val response = JSONObject(nativeDecryptEnrollmentPackageJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("plaintext")
        }
    }

    /// The per-chunk vault keys a read-write web session is granted, as
    /// `chunk_id → base64(32-byte key)`. The browser gets these instead of the
    /// RMS, so a leaked capsule yields vault chunks only — no identity, share,
    /// audit or recovery key can be derived from it (audit D-2).
    fun webSessionChunkKeys(rms: ByteArray): Map<String, String>? {
        return callNative {
            val response = JSONObject(nativeWebSessionChunkKeysJson(rms, "{}"))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            val keys = response.getJSONObject("chunk_keys")
            keys.keys().asSequence().associateWith { keys.getString(it) }
        }
    }

    // ── Device identity handles (audit C-1) ──────────────────────────────────
    //
    // The signing key and the share decapsulation key never cross this boundary.
    // Callers get a handle plus an opaque sealed blob to persist, and ask the
    // native side to sign or to open a share. The seal key travels as a
    // ByteArray so both sides can wipe it, unlike a String.

    data class IdentityHandle(
        val handle: Long,
        val hybridEkB64: String,
        val hybridVkB64: String,
        val shareEkB64: String,
        val sealedB64: String
    )

    private fun parseHandle(json: String): IdentityHandle {
        val response = JSONObject(json)
        response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
        return IdentityHandle(
            handle = response.getLong("handle"),
            hybridEkB64 = response.getString("hybrid_ek_b64"),
            hybridVkB64 = response.getString("hybrid_vk_b64"),
            shareEkB64 = response.getString("share_ek_b64"),
            sealedB64 = response.getString("sealed_b64")
        )
    }

    /// Generate a fresh device identity. The private halves stay native.
    fun identityCreate(sealKey: ByteArray): IdentityHandle? = callNative {
        parseHandle(nativeIdentityCreateJson(sealKey, "{}"))
    }

    /// Adopt existing key material — migrating a device that stored its keys in
    /// the clear, or enrolling from a code that carries the signing key.
    fun identityImport(
        sealKey: ByteArray,
        hybridSkB64: String,
        shareDkB64: String = "",
        hybridEkB64: String = ""
    ): IdentityHandle? = callNative {
        val request = JSONObject()
            .put("hybrid_sk_b64", hybridSkB64)
            .put("share_dk_b64", shareDkB64)
            .put("hybrid_ek_b64", hybridEkB64)
            .toString()
        parseHandle(nativeIdentityImportJson(sealKey, request))
    }

    /// Reopen a persisted identity.
    fun identityOpen(sealKey: ByteArray, sealedB64: String): IdentityHandle? = callNative {
        val request = JSONObject().put("sealed_b64", sealedB64).toString()
        parseHandle(nativeIdentityOpenJson(sealKey, request))
    }

    /// Sign a server auth challenge with the held signing key.
    fun identitySign(handle: Long, deviceId: String, challengeB64: String): String? = callNative {
        val request = JSONObject()
            .put("handle", handle)
            .put("device_id", deviceId)
            .put("challenge_b64", challengeB64)
            .toString()
        val response = JSONObject(nativeIdentitySignJson(request))
        response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
        response.getString("signature")
    }

    /// Open a capsule sealed to this device's share key.
    fun identityOpenShare(handle: Long, capsuleB64: String): String? = callNative {
        val request = JSONObject()
            .put("handle", handle)
            .put("capsule_b64", capsuleB64)
            .toString()
        val response = JSONObject(nativeIdentityOpenShareJson(request))
        response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
        response.getString("item_json")
    }

    /// Replace the share keypair; returns the new public half and sealed blob.
    fun identityRotateShareKey(sealKey: ByteArray, handle: Long): Pair<String, String>? = callNative {
        val request = JSONObject().put("handle", handle).toString()
        val response = JSONObject(nativeIdentityRotateShareKeyJson(sealKey, request))
        response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
        response.getString("share_ek_b64") to response.getString("sealed_b64")
    }

    /// Drop a handle, wiping its keys. Called on lock/sign-out.
    fun identityForget(handle: Long) {
        callNative { nativeIdentityForgetJson(JSONObject().put("handle", handle).toString()) }
    }

    fun identityForgetAll() {
        callNative { nativeIdentityForgetAllJson("{}") }
    }

    /// Seal `itemJson` for a recipient using their share public key (base64, 1600 B).
    /// Returns base64 capsule on success, null on error.
    fun sealShare(recipientShareEkB64: String, itemJson: String): String? {
        return callNative {
            val request = JSONObject()
                .put("recipient_share_ek_b64", recipientShareEkB64)
                .put("item_json", itemJson)
                .toString()
            val response = JSONObject(nativeSealShareJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("capsule_b64")
        }
    }


    /// Split the RMS into an [n]-share, [threshold]-of-[n] Shamir scheme
    /// (SPEC.md §4.3: recovery uses a 2-of-3 split). Returns each share
    /// base64-encoded, in order — the caller delivers each to its own
    /// channel (cloud backup, server, trusted contact).
    fun splitRecovery(rms: ByteArray, threshold: Int, n: Int): List<String>? {
        return callNative {
            val request = JSONObject()
                .put("threshold", threshold)
                .put("n", n)
                .toString()
            val response = JSONObject(nativeSplitRecoveryJson(rms, request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            val shares = response.getJSONArray("shares_b64")
            (0 until shares.length()).map { shares.getString(it) }
        }
    }

    /// Reconstruct the RMS from any `threshold` of the base64 shares produced
    /// by [splitRecovery] (e.g. Share 1 from cloud backup + Share 2 released
    /// by the server after a WebAuthn-gated `/recovery/recover` call).
    fun combineRecovery(sharesB64: List<String>): ByteArray? {
        return callNative {
            val request = JSONObject()
                .put("shares_b64", org.json.JSONArray(sharesB64))
                .toString()
            val rms = ByteArray(32)
            val response = JSONObject(nativeCombineRecoveryJson(request, rms))
            response.optString("error").takeIf { it.isNotBlank() }?.let {
                rms.fill(0)
                error(it)
            }
            rms
        }
    }

    private inline fun <T> callNative(block: () -> T): T? {
        if (!loaded) return null
        return runCatching(block).getOrElse { error("Native VELA bridge call failed: ${it.message}") }
    }

    private external fun nativeVersion(): String
    private external fun nativeEnrollmentVerificationCode(code: String): String
    private external fun nativeEncryptVaultJson(rms: ByteArray, requestJson: String): String
    private external fun nativeDecryptVaultJson(rms: ByteArray, requestJson: String): String
    private external fun nativeEncryptVaultChunkJson(rms: ByteArray, requestJson: String): String
    private external fun nativeDecryptVaultChunkJson(rms: ByteArray, requestJson: String): String
    private external fun nativeDecryptRmsCapsuleJson(requestJson: String, rmsOut: ByteArray): String
    private external fun nativeDecryptEnrollmentPackageJson(requestJson: String): String
    private external fun nativeWebSessionChunkKeysJson(rms: ByteArray, requestJson: String): String
    private external fun nativeIdentityCreateJson(sealKey: ByteArray, requestJson: String): String
    private external fun nativeIdentityImportJson(sealKey: ByteArray, requestJson: String): String
    private external fun nativeIdentityOpenJson(sealKey: ByteArray, requestJson: String): String
    private external fun nativeIdentityRotateShareKeyJson(sealKey: ByteArray, requestJson: String): String
    private external fun nativeIdentitySignJson(requestJson: String): String
    private external fun nativeIdentityOpenShareJson(requestJson: String): String
    private external fun nativeIdentityForgetJson(requestJson: String): String
    private external fun nativeIdentityForgetAllJson(requestJson: String): String
    private external fun nativeSealShareJson(requestJson: String): String
    private external fun nativeSplitRecoveryJson(rms: ByteArray, requestJson: String): String
    private external fun nativeCombineRecoveryJson(requestJson: String, rmsOut: ByteArray): String
}
