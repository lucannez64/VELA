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

    fun encryptVaultJson(rms: ByteArray, vaultJson: String): String? {
        return callNative {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("vault_json", vaultJson)
                .toString()
            val response = JSONObject(nativeEncryptVaultJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("ciphertext_b64")
        }
    }

    fun decryptVaultJson(rms: ByteArray, ciphertext: ByteArray): String? {
        return callNative {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            val response = JSONObject(nativeDecryptVaultJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("vault_json")
        }
    }

    fun encryptVaultChunkJson(rms: ByteArray, chunkId: String, vaultJson: String): String? {
        return callNative {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("chunk_id", chunkId)
                .put("vault_json", vaultJson)
                .toString()
            val response = JSONObject(nativeEncryptVaultChunkJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("ciphertext_b64")
        }
    }

    fun decryptVaultChunkJson(rms: ByteArray, chunkId: String, ciphertext: ByteArray): String? {
        return callNative {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("chunk_id", chunkId)
                .put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            val response = JSONObject(nativeDecryptVaultChunkJson(request))
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

    fun generateServerIdentityJson(): String? {
        return callNative {
            val response = JSONObject(nativeGenerateServerIdentityJson())
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.toString()
        }
    }

    /// Generate only a fresh share keypair (`{ share_ek_b64, share_dk_b64 }`).
    /// Used to backfill share keys for identities created before sharing existed.
    fun generateShareKeypairJson(): String? {
        return callNative {
            val response = JSONObject(nativeGenerateShareKeypairJson())
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.toString()
        }
    }

    fun createAuthSignatureJson(
        hybridSkB64: String,
        challengeB64: String,
        deviceId: String
    ): String? {
        return callNative {
            val request = JSONObject()
                .put("hybrid_sk_b64", hybridSkB64)
                .put("challenge_b64", challengeB64)
                .put("device_id", deviceId)
                .toString()
            val response = JSONObject(nativeCreateAuthSignatureJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.toString()
        }
    }

    fun decryptRmsCapsule(transferKeyB64: String, capsuleB64: String): ByteArray? {
        return callNative {
            val request = JSONObject()
                .put("transfer_key_b64", transferKeyB64)
                .put("capsule_b64", capsuleB64)
                .toString()
            val response = JSONObject(nativeDecryptRmsCapsuleJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            Base64.getDecoder().decode(response.getString("rms_b64"))
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

    /// Open a share capsule sealed by a sender using our share secret key (base64, 3200 B).
    /// Returns the decrypted item JSON on success, null on error.
    fun openShare(shareDkB64: String, capsuleB64: String): String? {
        return callNative {
            val request = JSONObject()
                .put("share_dk_b64", shareDkB64)
                .put("capsule_b64", capsuleB64)
                .toString()
            val response = JSONObject(nativeOpenShareJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("item_json")
        }
    }

    private inline fun <T> callNative(block: () -> T): T? {
        if (!loaded) return null
        return runCatching(block).getOrElse { error("Native VELA bridge call failed: ${it.message}") }
    }

    private external fun nativeVersion(): String
    private external fun nativeEnrollmentVerificationCode(code: String): String
    private external fun nativeEncryptVaultJson(requestJson: String): String
    private external fun nativeDecryptVaultJson(requestJson: String): String
    private external fun nativeEncryptVaultChunkJson(requestJson: String): String
    private external fun nativeDecryptVaultChunkJson(requestJson: String): String
    private external fun nativeGenerateServerIdentityJson(): String
    private external fun nativeGenerateShareKeypairJson(): String
    private external fun nativeCreateAuthSignatureJson(requestJson: String): String
    private external fun nativeDecryptRmsCapsuleJson(requestJson: String): String
    private external fun nativeDecryptEnrollmentPackageJson(requestJson: String): String
    private external fun nativeSealShareJson(requestJson: String): String
    private external fun nativeOpenShareJson(requestJson: String): String
}
