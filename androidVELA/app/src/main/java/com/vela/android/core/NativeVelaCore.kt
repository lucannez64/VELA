package com.vela.android.core

import org.json.JSONObject
import java.util.Base64

object NativeVelaCore {
    private val loaded: Boolean = runCatching {
        System.loadLibrary("vela_android_bridge")
    }.isSuccess

    fun isAvailable(): Boolean = loaded

    fun versionOrNull(): String? {
        if (!loaded) return null
        return runCatching { nativeVersion() }.getOrNull()
    }

    fun encryptVaultJson(rms: ByteArray, vaultJson: String): String? {
        if (!loaded) return null
        return runCatching {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("vault_json", vaultJson)
                .toString()
            val response = JSONObject(nativeEncryptVaultJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("ciphertext_b64")
        }.getOrNull()
    }

    fun decryptVaultJson(rms: ByteArray, ciphertext: ByteArray): String? {
        if (!loaded) return null
        return runCatching {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            val response = JSONObject(nativeDecryptVaultJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("vault_json")
        }.getOrNull()
    }

    fun encryptVaultChunkJson(rms: ByteArray, chunkId: String, vaultJson: String): String? {
        if (!loaded) return null
        return runCatching {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("chunk_id", chunkId)
                .put("vault_json", vaultJson)
                .toString()
            val response = JSONObject(nativeEncryptVaultChunkJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("ciphertext_b64")
        }.getOrNull()
    }

    fun decryptVaultChunkJson(rms: ByteArray, chunkId: String, ciphertext: ByteArray): String? {
        if (!loaded) return null
        return runCatching {
            val request = JSONObject()
                .put("rms_b64", Base64.getEncoder().encodeToString(rms))
                .put("chunk_id", chunkId)
                .put("ciphertext_b64", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            val response = JSONObject(nativeDecryptVaultChunkJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.getString("vault_json")
        }.getOrNull()
    }

    fun generateServerIdentityJson(): String? {
        if (!loaded) return null
        return runCatching {
            val response = JSONObject(nativeGenerateServerIdentityJson())
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.toString()
        }.getOrNull()
    }

    fun createAuthProofJson(
        cycloPkB64: String,
        cycloSkB64: String,
        challengeB64: String,
        deviceId: String
    ): String? {
        if (!loaded) return null
        return runCatching {
            val request = JSONObject()
                .put("cyclo_pk_b64", cycloPkB64)
                .put("cyclo_sk_b64", cycloSkB64)
                .put("challenge_b64", challengeB64)
                .put("device_id", deviceId)
                .toString()
            val response = JSONObject(nativeCreateAuthProofJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            response.toString()
        }.getOrNull()
    }

    fun decryptRmsCapsule(transferKeyB64: String, capsuleB64: String): ByteArray? {
        if (!loaded) return null
        return runCatching {
            val request = JSONObject()
                .put("transfer_key_b64", transferKeyB64)
                .put("capsule_b64", capsuleB64)
                .toString()
            val response = JSONObject(nativeDecryptRmsCapsuleJson(request))
            response.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            Base64.getDecoder().decode(response.getString("rms_b64"))
        }.getOrNull()
    }

    private external fun nativeVersion(): String
    private external fun nativeEncryptVaultJson(requestJson: String): String
    private external fun nativeDecryptVaultJson(requestJson: String): String
    private external fun nativeEncryptVaultChunkJson(requestJson: String): String
    private external fun nativeDecryptVaultChunkJson(requestJson: String): String
    private external fun nativeGenerateServerIdentityJson(): String
    private external fun nativeCreateAuthProofJson(requestJson: String): String
    private external fun nativeDecryptRmsCapsuleJson(requestJson: String): String
}
