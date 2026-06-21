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

data class SyncManifest(val chunks: List<ChunkManifestEntry>)

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

    fun registerAccount(identity: ServerIdentity): RegisterAccountResponse {
        val bodyObj = JSONObject()
            .put("hybrid_ek", identity.hybridEkB64)
            .put("hybrid_vk", identity.hybridVkB64)
            .put("device_name", android.os.Build.MODEL ?: "Android")
            .put("device_type", "android")
        if (identity.shareEkB64.isNotBlank()) {
            bodyObj.put("share_ek", identity.shareEkB64)
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
        val root = JSONObject(response.body.toString(Charsets.UTF_8))
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
        return SyncManifest(chunks) to response.newToken
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
        ciphertext: ByteArray
    ): UploadedChunk {
        val response = request(
            method = "PUT",
            path = "/vault/chunk/$chunkId",
            token = token,
            body = ciphertext,
            extraHeaders = mapOf(
                "If-Match" to ifMatch.toString(),
                "X-Lamport-Clock" to lamportClock.toString()
            )
        )
        response.requireSuccess("Chunk upload failed")
        val version = JSONObject(response.body.toString(Charsets.UTF_8)).optLong("version", 0)
        return UploadedChunk(version = version, newToken = response.newToken)
    }

    fun deleteChunk(token: String, chunkId: String, ifMatch: Long): String? {
        val response = request(
            method = "DELETE",
            path = "/vault/chunk/$chunkId",
            token = token,
            extraHeaders = mapOf("If-Match" to ifMatch.toString())
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

    fun getRecipientShareEk(token: String, userId: String): String {
        val response = request("GET", "/share/recipient/$userId/ek", token)
        response.requireSuccess("Get recipient share key failed")
        return JSONObject(response.body.toString(Charsets.UTF_8)).getString("share_ek")
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
    fun putMyShareEk(token: String, shareEkB64: String): String? {
        val body = JSONObject()
            .put("share_ek", shareEkB64)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = request("PUT", "/share/my-ek", token, body, contentType = "application/json")
        response.requireSuccess("Register share key failed")
        return response.newToken
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
        return try {
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
    override fun request(
        method: String,
        url: String,
        token: String,
        body: ByteArray?,
        extraHeaders: Map<String, String>,
        contentType: String
    ): HttpResponse {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
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
                request.followRedirect()
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
