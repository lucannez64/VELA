package com.vela.android.sync

import android.content.Context
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UploadDataProviders
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import org.json.JSONObject
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class ServerUnauthorizedException(message: String) : IOException(message)

data class ChunkManifestEntry(
    val chunkId: String,
    val version: Long,
    val lamportClock: Long,
    val lastWriter: String?
)

data class SyncManifest(val epoch: Long, val chunks: List<ChunkManifestEntry>)

internal fun parseSyncManifest(body: ByteArray): SyncManifest {
    val root = JSONObject(body.toString(Charsets.UTF_8))
    // Pre-epoch servers can only serve epoch 1. Once this device has adopted
    // N>1, the local/manifest equality check rejects this legacy default.
    val epoch = if (root.has("epoch")) root.getLong("epoch") else 1L
    require(epoch >= 1) { "Sync manifest epoch must be positive" }
    val chunksJson = root.optJSONArray("chunks") ?: org.json.JSONArray()
    val chunks = buildList {
        for (index in 0 until chunksJson.length()) {
            val item = chunksJson.getJSONObject(index)
            add(
                ChunkManifestEntry(
                    chunkId = item.getString("chunk_id"),
                    version = item.optLong("version", 0),
                    lamportClock = item.optLong("lamport_clock", 0),
                    lastWriter = item.optString("last_writer").takeIf { it.isNotBlank() }
                )
            )
        }
    }
    return SyncManifest(epoch = epoch, chunks = chunks)
}

internal fun vaultEpochHeaders(keyEpoch: Long): Map<String, String> {
    require(keyEpoch >= 1) { "Vault key epoch must be positive" }
    return mapOf("X-Vela-Epoch" to keyEpoch.toString())
}

data class DownloadedChunk(
    val ciphertext: ByteArray,
    val version: Long,
    val lamportClock: Long,
    val newToken: String?
)

data class UploadedChunk(
    val version: Long,
    val newToken: String?
)

data class RegisterAccountResponse(
    val userId: String,
    val deviceId: String,
    val token: String?
)

data class ChallengeResponse(val challengeB64: String)

data class VerifyResponse(val token: String, val userId: String)

data class CapsuleResponse(val capsuleB64: String, val newToken: String?)
data class VaultEpochResponse(val epoch: Long, val state: String, val newToken: String?)
data class WebSessionKeysResponse(
    val ephemeralPkB64: String,
    val webVkB64: String,
    val newToken: String?,
)
data class GrantWebSessionResponse(val expiresAt: String, val newToken: String?)
data class EnrollmentPackageResponse(val ciphertext: String)

data class DeviceInfo(
    val id: String,
    val name: String,
    val deviceType: String,
    val enrolledBy: String?,
    val lastActive: String?,
    val revoked: Boolean,
    val pending: Boolean,
    val revokedAt: String?,
    val revokedBy: String?,
    val createdAt: String
)

data class InboxShareItem(
    val id: String,
    val senderUserId: String,
    val capsuleB64: String,
    val createdAt: String
)

data class LinkedShareItem(
    val id: String,
    val senderUserId: String,
    val recipientUserId: String,
    val capsuleB64: String,
    val createdAt: String,
    val updatedAt: String,
    val revoked: Boolean
)

data class SendShareResponse(val inboxId: String, val shareId: String, val newToken: String?)

data class HttpResponse(
    val code: Int,
    val headers: Map<String, List<String>>,
    val body: ByteArray,
    val negotiatedProtocol: String? = null
) {
    val newToken: String?
        get() = headers["X-New-Token"]?.firstOrNull() ?: headers["x-new-token"]?.firstOrNull()

    fun requireSuccess(message: String) {
        if (code !in 200..299) {
            val detail = body.toString(Charsets.UTF_8).ifBlank { "HTTP $code" }
            if (code == 401) {
                throw ServerUnauthorizedException("$message: $detail")
            }
            throw IOException("$message: $detail")
        }
    }
}

interface VelaHttpTransport {
    fun request(
        method: String,
        url: String,
        token: String,
        body: ByteArray?,
        extraHeaders: Map<String, String>,
        contentType: String
    ): HttpResponse
}

class AndroidVelaApiClient(
    private val baseUrl: String,
    context: Context? = null
) {
    private val fallbackTransport = UrlConnectionTransport()
    private val h3Transport = if (baseUrl.startsWith("https://") && context != null) {
        runCatching { CronetHttp3Transport(context.applicationContext, baseUrl) }.getOrNull()
    } else {
        null
    }
    @Volatile private var selectedTransport: VelaHttpTransport? = null
    @Volatile private var latestNewToken: String? = null

    fun latestSessionToken(): String? = latestNewToken

    fun clearLatestSessionToken() {
        latestNewToken = null
    }

    fun registerAccount(identity: ServerIdentity): RegisterAccountResponse {
        val bodyObj = JSONObject()
            .put("hybrid_ek", identity.hybridEkB64)
            .put("hybrid_vk", identity.hybridVkB64)
            .put("device_name", android.os.Build.MODEL ?: "Android")
            .put("device_type", "android")
        if (identity.shareEkB64.isNotBlank() && !identity.shareEkSignature.isNullOrBlank()) {
            // M19: the initial share key must arrive device-signed.
            bodyObj.put("share_ek", identity.shareEkB64)
                .put("share_ek_signed_at", identity.shareEkSignedAt)
                .put("share_ek_signature", identity.shareEkSignature)
        }
        val body = bodyObj.toString().toByteArray(Charsets.UTF_8)
        val response = request("POST", "/account/register", token = "", body = body, contentType = "application/json")
        response.requireSuccess("Account registration failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return RegisterAccountResponse(
            userId = json.getString("user_id"),
            deviceId = json.getString("device_id"),
            token = json.optString("token").takeIf { it.isNotBlank() }
        )
    }

    fun getChallenge(): ChallengeResponse {
        val response = request("GET", "/auth/challenge", token = "")
        response.requireSuccess("Challenge request failed")
        return ChallengeResponse(JSONObject(response.body.toString(Charsets.UTF_8)).getString("challenge"))
    }

    fun verifySignature(deviceId: String, challengeB64: String, signature: String): VerifyResponse {
        val body = JSONObject()
            .put("device_id", deviceId)
            .put("challenge", challengeB64)
            .put("signature", signature)
            .put("device_name", android.os.Build.MODEL ?: "Android")
            .put("device_type", "android")
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request("POST", "/auth/verify", token = "", body = body, contentType = "application/json")
        response.requireSuccess("Signature verification failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return VerifyResponse(token = json.getString("token"), userId = json.getString("user_id"))
    }

    fun getSyncManifest(token: String): Pair<SyncManifest, String?> {
        val response = request("GET", "/vault/sync", token)
        response.requireSuccess("Sync manifest request failed")
        return parseSyncManifest(response.body) to response.newToken
    }

    /** Current vault-key epoch and rotation state ("active" or "freezing"). */
    fun markRekeyCapable(token: String): String? {
        val response = request("POST", "/device/rekey-capable", token)
        response.requireSuccess("Mark rekey-capable failed")
        return response.newToken
    }

    fun acknowledgeRekeyCapsule(token: String, epoch: Long): String? {
        val body = JSONObject().put("epoch", epoch).toString().toByteArray(Charsets.UTF_8)
        val response = request("POST", "/device/capsule/ack", token, body, contentType = "application/json")
        response.requireSuccess("Acknowledge rekey capsule failed")
        return response.newToken
    }

    fun getVaultEpoch(token: String): VaultEpochResponse {
        val response = request("GET", "/vault/epoch", token)
        response.requireSuccess("Vault epoch request failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return VaultEpochResponse(
            epoch = json.getLong("epoch"),
            state = json.getString("state"),
            newToken = response.newToken,
        )
    }

    fun getCapsule(token: String): CapsuleResponse {
        val response = request("GET", "/device/capsule", token)
        response.requireSuccess("RMS capsule download failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return CapsuleResponse(
            capsuleB64 = json.getString("capsule"),
            newToken = response.newToken
        )
    }

    // ── Enrollment v3 (audit P-1) ───────────────────────────────────────────
    //
    // Both calls are unauthenticated by necessity: this device has no identity
    // the server knows about yet, which is the thing it is asking for. What
    // stands in is the grant id for the claim, and a signature under the key
    // that claimed for the result.

    /// Present this device's *public* keys under a grant.
    ///
    /// A grant admits exactly one claim, so losing the race is reported (409)
    /// rather than silently replacing whoever claimed first — a hijack that
    /// went unnoticed is the failure this whole design exists to prevent.
    fun claimEnrollmentGrant(
        grantId: String,
        hybridEkB64: String,
        hybridVkB64: String,
        deviceName: String,
        deviceType: String
    ) {
        val body = JSONObject()
            .put("hybrid_ek", hybridEkB64)
            .put("hybrid_vk", hybridVkB64)
            .put("device_name", deviceName)
            .put("device_type", deviceType)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request(
            "POST",
            "/device/enrollment-grant/$grantId/claim",
            token = "",
            body = body,
            contentType = "application/json"
        )
        response.requireSuccess("Could not use this enrollment code")
    }

    /// Ask which device this one became. `null` while the other device's user
    /// has not confirmed yet.
    fun collectEnrollmentResult(grantId: String, signatureB64: String): String? {
        val body = JSONObject()
            .put("signature", signatureB64)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request(
            "POST",
            "/device/enrollment-grant/$grantId/result",
            token = "",
            body = body,
            contentType = "application/json"
        )
        response.requireSuccess("Enrollment could not be confirmed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return when (json.optString("status")) {
            "enrolled" -> json.getString("device_id")
            else -> null
        }
    }

    fun getEnrollmentPackage(token: String): EnrollmentPackageResponse {
        val response = request("GET", "/device/enrollment-package/$token", token = "")
        response.requireSuccess("Enrollment package download failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return EnrollmentPackageResponse(ciphertext = json.getString("ciphertext"))
    }

    fun getChunk(token: String, chunkId: String): DownloadedChunk {
        val response = request("GET", "/vault/chunk/$chunkId", token)
        response.requireSuccess("Chunk download failed")
        return DownloadedChunk(
            ciphertext = response.body,
            version = response.headers["X-Chunk-Version"]?.firstOrNull()?.toLongOrNull() ?: 0,
            lamportClock = response.headers["X-Lamport-Clock"]?.firstOrNull()?.toLongOrNull() ?: 0,
            newToken = response.newToken
        )
    }

    fun putChunk(
        token: String = "",
        chunkId: String,
        ifMatch: Long,
        lamportClock: Long,
        keyEpoch: Long,
        ciphertext: ByteArray
    ): UploadedChunk {
        val response = request(
            method = "PUT",
            path = "/vault/chunk/$chunkId",
            token = token,
            body = ciphertext,
            extraHeaders = vaultEpochHeaders(keyEpoch) + mapOf(
                "If-Match" to ifMatch.toString(),
                "X-Lamport-Clock" to lamportClock.toString()
            )
        )
        response.requireSuccess("Chunk upload failed")
        val version = JSONObject(response.body.toString(Charsets.UTF_8)).optLong("version", 0)
        return UploadedChunk(version = version, newToken = response.newToken)
    }

    fun deleteChunk(token: String, chunkId: String, ifMatch: Long, keyEpoch: Long): String? {
        val response = request(
            method = "DELETE",
            path = "/vault/chunk/$chunkId",
            token = token,
            extraHeaders = vaultEpochHeaders(keyEpoch) + mapOf("If-Match" to ifMatch.toString())
        )
        response.requireSuccess("Chunk delete failed")
        return response.newToken
    }

    fun getDevices(token: String): Pair<List<DeviceInfo>, String?> {
        val response = request("GET", "/devices", token)
        response.requireSuccess("Device list request failed")
        val root = JSONObject(response.body.toString(Charsets.UTF_8))
        val items = root.optJSONArray("devices") ?: JSONArray()
        return buildList {
            for (index in 0 until items.length()) {
                val json = items.getJSONObject(index)
                add(
                    DeviceInfo(
                        id = json.getString("id"),
                        name = json.optString("name", "Device"),
                        deviceType = json.optString("device_type", "unknown"),
                        enrolledBy = json.optNullableString("enrolled_by"),
                        lastActive = json.optNullableString("last_active"),
                        revoked = json.optBoolean("revoked", false),
                        pending = json.optBoolean("pending", false),
                        revokedAt = json.optNullableString("revoked_at"),
                        revokedBy = json.optNullableString("revoked_by"),
                        createdAt = json.optString("created_at")
                    )
                )
            }
        } to response.newToken
    }

    fun revokeDevice(token: String, deviceId: String): String? {
        val body = JSONObject().put("target_device_id", deviceId).toString().toByteArray(Charsets.UTF_8)
        val response = request("POST", "/device/revoke", token, body, contentType = "application/json")
        response.requireSuccess("Device revoke request failed")
        return response.newToken
    }

    fun getInbox(token: String): Pair<List<InboxShareItem>, String?> {
        val response = request("GET", "/share/inbox", token)
        response.requireSuccess("Share inbox request failed")
        val root = JSONObject(response.body.toString(Charsets.UTF_8))
        val items = root.optJSONArray("items") ?: JSONArray()
        return buildList {
            for (index in 0 until items.length()) {
                val json = items.getJSONObject(index)
                add(
                    InboxShareItem(
                        id = json.getString("id"),
                        senderUserId = json.getString("sender_user_id"),
                        capsuleB64 = json.getString("capsule"),
                        createdAt = json.optString("created_at")
                    )
                )
            }
        } to response.newToken
    }

    fun getLinkedShares(token: String): Pair<List<LinkedShareItem>, String?> {
        val response = request("GET", "/share/linked", token)
        response.requireSuccess("Linked share request failed")
        val root = JSONObject(response.body.toString(Charsets.UTF_8))
        val items = root.optJSONArray("items") ?: JSONArray()
        return buildList {
            for (index in 0 until items.length()) {
                val json = items.getJSONObject(index)
                add(
                    LinkedShareItem(
                        id = json.getString("id"),
                        senderUserId = json.getString("sender_user_id"),
                        recipientUserId = json.getString("recipient_user_id"),
                        capsuleB64 = json.getString("capsule"),
                        createdAt = json.optString("created_at"),
                        updatedAt = json.optString("updated_at"),
                        revoked = json.optBoolean("revoked", false)
                    )
                )
            }
        } to response.newToken
    }

    fun sendShare(token: String, recipientUserId: String, capsuleB64: String): SendShareResponse {
        val body = JSONObject()
            .put("recipient_user_id", recipientUserId)
            .put("capsule", capsuleB64)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request("POST", "/share/send", token, body, contentType = "application/json")
        response.requireSuccess("Share send request failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return SendShareResponse(
            inboxId = json.getString("inbox_id"),
            shareId = json.getString("share_id"),
            newToken = response.newToken
        )
    }

    fun deleteInboxItem(token: String, id: String): String? {
        val response = request("DELETE", "/share/inbox/$id", token)
        response.requireSuccess("Share inbox delete request failed")
        return response.newToken
    }

    fun deleteLinkedShare(token: String, id: String): String? {
        val response = request("DELETE", "/share/linked/$id", token)
        response.requireSuccess("Linked share delete request failed")
        return response.newToken
    }

    fun getRecipientShareEk(token: String, userId: String): Pair<String, String?> {
        val response = request("GET", "/share/recipient/$userId/ek", token)
        response.requireSuccess("Get recipient share key failed")
        return JSONObject(response.body.toString(Charsets.UTF_8)).getString("share_ek") to response.newToken
    }

    fun updateLinkedShare(token: String, shareId: String, capsuleB64: String): String? {
        val body = JSONObject()
            .put("capsule", capsuleB64)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request("PUT", "/share/linked/$shareId", token, body, contentType = "application/json")
        response.requireSuccess("Update linked share failed")
        return response.newToken
    }

    /// Register (or update) the caller's own share encapsulation key. Backfill
    /// path for accounts created before share keys existed.
    fun putMyShareEk(token: String, shareEkB64: String, deviceId: String, signedAt: String, signature: String): String? {
        val body = JSONObject()
            .put("share_ek", shareEkB64)
            .put("device_id", deviceId)
            .put("signed_at", signedAt)
            .put("signature", signature)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request("PUT", "/share/my-ek", token, body, contentType = "application/json")
        response.requireSuccess("Register share key failed")
        return response.newToken
    }

    /// Look up a pending web session's ephemeral public keys (the QR carries only
    /// the session id). `webVkB64` is empty for read-only sessions.
    fun getWebSessionKeys(token: String, sessionId: String): WebSessionKeysResponse {
        val response = request("GET", "/web-session/$sessionId/keys", token)
        response.requireSuccess("Fetch web session keys failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return WebSessionKeysResponse(
            ephemeralPkB64 = json.getString("ephemeral_pk"),
            webVkB64 = json.optString("web_vk"),
            newToken = response.newToken,
        )
    }

    /// Approve an ephemeral web session: deliver the sealed capsule with the
    /// chosen mode and TTL. `linkNonce` is echoed back from the link code so the
    /// server can bind the grant to the requesting browser.
    /// Returns the server-clamped expiry (RFC3339).
    fun grantWebSession(
        token: String,
        sessionId: String,
        mode: String,
        capsuleB64: String,
        ttlSecs: Long,
        linkNonce: String,
        keyEpoch: Long,
    ): GrantWebSessionResponse {
        val body = JSONObject()
            .put("mode", mode)
            .put("capsule", capsuleB64)
            .put("ttl_secs", ttlSecs)
            .put("link_nonce", linkNonce)
            .put("key_epoch", keyEpoch)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request("POST", "/web-session/$sessionId/grant", token, body, contentType = "application/json")
        response.requireSuccess("Grant web access failed")
        return GrantWebSessionResponse(
            expiresAt = JSONObject(response.body.toString(Charsets.UTF_8)).getString("expires_at"),
            newToken = response.newToken,
        )
    }

    data class WebSessionInfo(
        val id: String,
        val mode: String,
        val status: String,
        val createdAt: String,
        val expiresAt: String?,
    )

    fun listWebSessions(token: String): Pair<List<WebSessionInfo>, String?> {
        val response = request("GET", "/web-sessions", token)
        response.requireSuccess("List web sessions failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        val arr = json.getJSONArray("sessions")
        return (0 until arr.length()).map { i ->
            val obj = arr.getJSONObject(i)
            WebSessionInfo(
                id = obj.getString("id"),
                mode = obj.getString("mode"),
                status = obj.getString("status"),
                createdAt = obj.getString("created_at"),
                expiresAt = obj.optString("expires_at").takeIf { it.isNotEmpty() },
            )
        } to response.newToken
    }

    fun revokeWebSession(token: String, sessionId: String) {
        val response = request("DELETE", "/web-session/$sessionId", token)
        response.requireSuccess("Revoke web session failed")
    }

    // Recovery (SPEC.md §4.3)

    fun putRecoveryShare(token: String, shareB64: String, keyEpoch: Long, splitId: String, possessionHashB64: String): String? {
        require(keyEpoch >= 1) { "Recovery share epoch must be positive" }
        require(splitId.isNotBlank()) { "Recovery split ID is required" }
        require(possessionHashB64.isNotBlank()) { "RMS possession hash is required" }
        val body = JSONObject()
            .put("share", shareB64)
            .put("key_epoch", keyEpoch)
            .put("split_id", splitId)
            // M18: blind RMS commitment staged and finalized with the share.
            .put("possession_hash", possessionHashB64)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request("PUT", "/recovery/share", token, body, contentType = "application/json")
        response.requireSuccess("Store recovery share failed")
        return response.newToken
    }

    fun finalizeRecoveryShare(token: String, keyEpoch: Long, splitId: String): String? {
        require(keyEpoch >= 1) { "Recovery share epoch must be positive" }
        require(splitId.isNotBlank()) { "Recovery split ID is required" }
        val body = JSONObject()
            .put("key_epoch", keyEpoch)
            .put("split_id", splitId)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request(
            "POST", "/recovery/share/finalize", token, body,
            contentType = "application/json"
        )
        response.requireSuccess("Finalize recovery share failed")
        return response.newToken
    }

    fun startRecoveryWebAuthnRegistration(token: String): Pair<JSONObject, String?> {
        val body = JSONObject().put("user_display_name", "VELA recovery key").toString().toByteArray(Charsets.UTF_8)
        val response = request("POST", "/recovery/webauthn/register/start", token, body, contentType = "application/json")
        response.requireSuccess("Start recovery passkey registration failed")
        return JSONObject(response.body.toString(Charsets.UTF_8)) to response.newToken
    }

    fun finishRecoveryWebAuthnRegistration(token: String, credentialJson: JSONObject): Pair<Boolean, String?> {
        val body = credentialJson.toString().toByteArray(Charsets.UTF_8)
        val response = request("POST", "/recovery/webauthn/register/finish", token, body, contentType = "application/json")
        response.requireSuccess("Finish recovery passkey registration failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return json.optBoolean("registered", false) to response.newToken
    }

    data class RecoveryInitiateResult(val recoveryId: String?, val publicKeyJson: JSONObject)

    /// Starts the WebAuthn assertion ceremony for a user with a stored
    /// recovery share and recovery passkey. Unauthenticated — there is no
    /// session yet on a brand-new device.
    fun initiateRecovery(userId: String): RecoveryInitiateResult {
        val body = JSONObject().put("user_id", userId).toString().toByteArray(Charsets.UTF_8)
        val response = request("POST", "/recovery/initiate", token = "", body = body, contentType = "application/json")
        response.requireSuccess("Recovery initiation failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        return RecoveryInitiateResult(
            recoveryId = json.optString("recovery_id").takeIf { it.isNotBlank() },
            publicKeyJson = json.getJSONObject("public_key")
        )
    }

    data class RecoveryRecoverResult(
        val shareB64: String,
        val recoveryGrant: String,
        val keyEpoch: Long,
        val splitId: String?
    )

    /// Submits the WebAuthn assertion; the server releases Share 2 plus a
    /// single-use grant redeemable at `enrollDeviceViaRecovery`.
    fun recoverAccount(userId: String, recoveryId: String?, credentialJson: JSONObject): RecoveryRecoverResult {
        val bodyObj = JSONObject().put("user_id", userId).put("credential", credentialJson)
        if (recoveryId != null) bodyObj.put("recovery_id", recoveryId)
        val response = request("POST", "/recovery/recover", token = "", body = bodyObj.toString().toByteArray(Charsets.UTF_8), contentType = "application/json")
        response.requireSuccess("Account recovery failed")
        val json = JSONObject(response.body.toString(Charsets.UTF_8))
        val keyEpoch = json.getLong("key_epoch")
        require(keyEpoch >= 1) { "Server returned an invalid recovery epoch" }
        return RecoveryRecoverResult(
            shareB64 = json.getString("share"),
            recoveryGrant = json.getString("recovery_grant"),
            keyEpoch = keyEpoch,
            splitId = json.optString("split_id").takeIf { it.isNotBlank() }
        )
    }

    /// Registers this device's identity key against an existing account once
    /// its RMS has been reconstructed from Share 1 + Share 2. There is no
    /// other enrolled device to authorize this one (SPEC.md §4.2) — the
    /// single-use `recoveryGrant` from `recoverAccount` stands in for that
    /// signature.
    fun enrollDeviceViaRecovery(
        userId: String,
        recoveryGrant: String,
        hybridEkB64: String,
        hybridVkB64: String,
        deviceName: String? = null
    ): String {
        val bodyObj = JSONObject()
            .put("user_id", userId)
            .put("recovery_grant", recoveryGrant)
            .put("hybrid_ek", hybridEkB64)
            .put("hybrid_vk", hybridVkB64)
            .put("device_type", "android")
        if (deviceName != null) bodyObj.put("device_name", deviceName)
        val response = request("POST", "/recovery/enroll-device", token = "", body = bodyObj.toString().toByteArray(Charsets.UTF_8), contentType = "application/json")
        response.requireSuccess("Recovery device enrollment failed")
        return JSONObject(response.body.toString(Charsets.UTF_8)).getString("device_id")
    }

    private fun request(
        method: String,
        path: String,
        token: String,
        body: ByteArray? = null,
        extraHeaders: Map<String, String> = emptyMap(),
        contentType: String = "application/octet-stream"
    ): HttpResponse {
        val url = "$baseUrl$path"
        val transport = selectTransport()
        val response = try {
            transport.request(method, url, token, body, extraHeaders, contentType)
        } catch (e: IOException) {
            if (transport === h3Transport) {
                selectedTransport = fallbackTransport
                if (method == "GET" || method == "HEAD") {
                    fallbackTransport.request(method, url, token, body, extraHeaders, contentType)
                } else {
                    throw e
                }
            } else {
                throw e
            }
        }
        response.newToken?.takeIf { it.isNotBlank() }?.let { latestNewToken = it }
        return response
    }

    private fun selectTransport(): VelaHttpTransport {
        selectedTransport?.let { return it }
        val candidate = h3Transport
        if (candidate != null) {
            val healthy = runCatching {
                val response = candidate.request(
                    method = "GET",
                    url = "$baseUrl/health",
                    token = "",
                    body = null,
                    extraHeaders = emptyMap(),
                    contentType = "application/octet-stream"
                )
                response.code in 200..299 && response.negotiatedProtocol.orEmpty()
                    .contains("h3", ignoreCase = true)
            }.getOrDefault(false)
            if (healthy) {
                selectedTransport = candidate
                return candidate
            }
        }
        selectedTransport = fallbackTransport
        return fallbackTransport
    }
}

class UrlConnectionTransport : VelaHttpTransport {
    private companion object {
        const val MAX_REDIRECTS = 5
    }

    override fun request(
        method: String,
        url: String,
        token: String,
        body: ByteArray?,
        extraHeaders: Map<String, String>,
        contentType: String
    ): HttpResponse {
        // HttpURLConnection follows redirects transparently and re-sends this
        // request's properties — including the Authorization Bearer token — to
        // whatever host the redirect points at. Mirror CronetHttp3Transport's
        // policy: follow same-host redirects manually, refuse cross-host ones.
        val originalHost = URI(url).host
            ?: throw IOException("Request URL $url has no host")

        var currentUrl = url
        var redirects = 0
        while (true) {
            val connection = (URL(currentUrl).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                requestMethod = method
                connectTimeout = 10_000
                readTimeout = 20_000
                if (token.isNotBlank()) {
                    setRequestProperty("Authorization", "Bearer $token")
                }
                extraHeaders.forEach { (key, value) -> setRequestProperty(key, value) }
                if (body != null) {
                    doOutput = true
                    setRequestProperty("Content-Type", contentType)
                    outputStream.use { it.write(body) }
                }
            }

            val code = connection.responseCode
            if (code in 300..399 && code != 304) {
                redirects++
                if (redirects > MAX_REDIRECTS) {
                    throw IOException("Too many redirects from $url")
                }
                val location = connection.headerFields?.get("Location")?.firstOrNull()
                    ?: throw IOException("Redirect $code from $currentUrl without Location header")
                val target = URL(URL(currentUrl), location)
                val targetHost = target.host
                    ?: throw IOException("Redirect to $location without a host")
                if (!originalHost.equals(targetHost, ignoreCase = true)) {
                    throw IOException("Refusing cross-host redirect from $originalHost to $targetHost")
                }
                currentUrl = target.toString()
                continue
            }

            val bytes = runCatching {
                val stream = if (code in 200..299) connection.inputStream else connection.errorStream
                stream?.use { it.readBytes() } ?: ByteArray(0)
            }.getOrDefault(ByteArray(0))
            return HttpResponse(
                code = code,
                headers = connection.headerFields.orEmpty(),
                body = bytes
            )
        }
    }
}

class CronetHttp3Transport(context: Context, baseUrl: String) : VelaHttpTransport {
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private val engine: CronetEngine

    init {
        val uri = URI(baseUrl)
        val port = when {
            uri.port > 0 -> uri.port
            uri.scheme.equals("https", ignoreCase = true) -> 443
            else -> 80
        }
        engine = CronetEngine.Builder(context)
            .enableQuic(true)
            .enableHttp2(true)
            .addQuicHint(uri.host, port, port)
            .build()
    }

    override fun request(
        method: String,
        url: String,
        token: String,
        body: ByteArray?,
        extraHeaders: Map<String, String>,
        contentType: String
    ): HttpResponse {
        val latch = CountDownLatch(1)
        val result = AtomicReference<HttpResponse?>()
        val failure = AtomicReference<IOException?>()

        val callback = object : UrlRequest.Callback() {
            private val output = ByteArrayOutputStream()

            override fun onRedirectReceived(
                request: UrlRequest,
                info: UrlResponseInfo,
                newLocationUrl: String
            ) {
                // Only follow same-host redirects. Cronet re-attaches this
                // request's original headers — including the Authorization
                // Bearer token — when following a redirect; a cross-host
                // redirect (from a compromised/misconfigured server, or a
                // MITM on a non-pinned hop) would hand the token to whatever
                // host the redirect points at. VELA's API never legitimately
                // redirects cross-host, so treat one as a failure instead.
                val originalHost = runCatching { java.net.URI(url).host }.getOrNull()
                val redirectHost = runCatching { java.net.URI(newLocationUrl).host }.getOrNull()
                if (originalHost != null && originalHost.equals(redirectHost, ignoreCase = true)) {
                    request.followRedirect()
                } else {
                    failure.set(IOException("Refusing cross-host redirect from $originalHost to $redirectHost"))
                    request.cancel()
                }
            }

            override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                request.read(ByteBuffer.allocateDirect(32 * 1024))
            }

            override fun onReadCompleted(
                request: UrlRequest,
                info: UrlResponseInfo,
                byteBuffer: ByteBuffer
            ) {
                byteBuffer.flip()
                val bytes = ByteArray(byteBuffer.remaining())
                byteBuffer.get(bytes)
                output.write(bytes)
                byteBuffer.clear()
                request.read(byteBuffer)
            }

            override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
                result.set(
                    HttpResponse(
                        code = info.httpStatusCode,
                        headers = info.allHeaders,
                        body = output.toByteArray(),
                        negotiatedProtocol = info.negotiatedProtocol
                    )
                )
                latch.countDown()
            }

            override fun onFailed(request: UrlRequest, info: UrlResponseInfo?, error: CronetException) {
                failure.set(IOException(error.message ?: "Cronet request failed", error))
                latch.countDown()
            }

            override fun onCanceled(request: UrlRequest, info: UrlResponseInfo?) {
                // onCanceled has a no-op default in Cronet's API (unlike the
                // abstract onFailed) — without this override, request.cancel()
                // above (cross-host redirect refusal) would never count down
                // the latch and hang the caller forever.
                if (failure.get() == null) {
                    failure.set(IOException("Request was canceled"))
                }
                latch.countDown()
            }
        }

        val builder = engine.newUrlRequestBuilder(url, callback, executor)
            .setHttpMethod(method)
            .allowDirectExecutor()
        if (token.isNotBlank()) {
            builder.addHeader("Authorization", "Bearer $token")
        }
        extraHeaders.forEach { (key, value) -> builder.addHeader(key, value) }
        if (body != null) {
            builder.addHeader("Content-Type", contentType)
            builder.setUploadDataProvider(UploadDataProviders.create(body), executor)
        }

        builder.build().start()
        if (!latch.await(30, TimeUnit.SECONDS)) {
            throw IOException("Cronet request timed out")
        }
        failure.get()?.let { throw it }
        return result.get() ?: throw IOException("Cronet request completed without a response")
    }
}

private fun JSONObject.optNullableString(name: String): String? {
    if (!has(name) || isNull(name)) return null
    return optString(name).takeIf { it.isNotBlank() }
}
