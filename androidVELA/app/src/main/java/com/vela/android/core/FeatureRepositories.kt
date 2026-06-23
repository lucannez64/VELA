package com.vela.android.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.UUID

enum class ShareDirection { Received, Sent }

data class VaultShare(
    val id: String,
    val itemId: String,
    val itemName: String,
    val itemType: String,
    val direction: ShareDirection,
    val from: String,
    val to: String?,
    val sharedAt: String,
    val accepted: Boolean? = null
)

data class AuditEntry(
    val id: String = UUID.randomUUID().toString(),
    val timestamp: Instant = Instant.now(),
    val actionType: String,
    val detail: String? = null,
    val deviceName: String = android.os.Build.MODEL ?: "Android"
)

data class PasswordBreachResult(
    val breached: Boolean,
    val count: Int,
    val description: String
)

data class SentShareRecord(
    val shareId: String,
    val itemId: String,
    val itemName: String,
    val itemType: String,
    val recipientUserId: String,
    val recipientShareEkB64: String
)

class SentShareManifest(context: Context) {
    private val prefs = context.getSharedPreferences("vela_sent_shares", Context.MODE_PRIVATE)

    fun get(shareId: String): SentShareRecord? {
        val raw = prefs.getString(shareId, null) ?: return null
        return runCatching { fromJson(JSONObject(raw)) }.getOrNull()
    }

    fun forItem(itemId: String): List<SentShareRecord> =
        prefs.all.values.mapNotNull { raw ->
            runCatching { fromJson(JSONObject(raw as String)) }.getOrNull()
        }.filter { it.itemId == itemId }

    fun add(record: SentShareRecord) {
        prefs.edit().putString(record.shareId, record.toJson().toString()).apply()
    }

    fun remove(shareId: String) {
        prefs.edit().remove(shareId).apply()
    }

    private fun fromJson(json: JSONObject) = SentShareRecord(
        shareId = json.getString("share_id"),
        itemId = json.getString("item_id"),
        itemName = json.getString("item_name"),
        itemType = json.getString("item_type"),
        recipientUserId = json.getString("recipient_user_id"),
        recipientShareEkB64 = json.getString("recipient_share_ek_b64")
    )

    private fun SentShareRecord.toJson() = JSONObject()
        .put("share_id", shareId)
        .put("item_id", itemId)
        .put("item_name", itemName)
        .put("item_type", itemType)
        .put("recipient_user_id", recipientUserId)
        .put("recipient_share_ek_b64", recipientShareEkB64)
}

class SharingRepository(
    private val vault: LocalVaultRepository,
    private val security: com.vela.android.security.SecureVaultManager,
    private val sync: com.vela.android.sync.VaultSyncManager,
    private val identityStore: com.vela.android.sync.ServerIdentityStore,
    context: Context
) {
    private val manifest = SentShareManifest(context.applicationContext)

    fun listShares(): List<VaultShare> = sync.withAuthenticatedClient { client, token ->
        var currentToken = token
        val (inbox, inboxToken) = client.getInbox(currentToken)
        inboxToken?.let { currentToken = it }
        val (linked, linkedToken) = client.getLinkedShares(currentToken)
        linkedToken?.let { currentToken = it }

        val shareDkB64 = identityStore.load()?.shareDkB64

        val received = inbox.map { item ->
            val decoded = if (shareDkB64 != null) openShareItem(shareDkB64, item.capsuleB64) else null
            VaultShare(
                id = item.id,
                itemId = item.id,
                itemName = decoded?.name ?: "Shared item",
                itemType = decoded?.type?.name?.lowercase() ?: "item",
                direction = ShareDirection.Received,
                from = item.senderUserId,
                to = null,
                sharedAt = item.createdAt
            )
        }
        val sent = linked
            .filter { share -> share.senderUserId != share.recipientUserId }
            .map { item ->
                val meta = manifest.get(item.id)
                VaultShare(
                    id = item.id,
                    itemId = meta?.itemId ?: item.id,
                    itemName = meta?.itemName ?: "Shared item",
                    itemType = meta?.itemType ?: "item",
                    direction = ShareDirection.Sent,
                    from = item.senderUserId,
                    to = item.recipientUserId,
                    sharedAt = item.updatedAt
                )
            }
        received + sent
    }

    fun sendShare(itemId: String, recipientUserId: String) {
        val item = vault.snapshot().items.find { it.id == itemId } ?: error("Item not found")
        val itemJson = VaultJson.encodeItem(item).toString(Charsets.UTF_8)

        sync.withAuthenticatedClient { client, token ->
            val recipientShareEkB64 = client.getRecipientShareEk(token, recipientUserId)
            val capsuleB64 = NativeVelaCore.sealShare(recipientShareEkB64, itemJson)
                ?: error("Native VELA bridge is required for sharing")
            val response = client.sendShare(token, recipientUserId, capsuleB64)
            manifest.add(
                SentShareRecord(
                    shareId = response.shareId,
                    itemId = item.id,
                    itemName = item.name,
                    itemType = item.type.name.lowercase(),
                    recipientUserId = recipientUserId,
                    recipientShareEkB64 = recipientShareEkB64
                )
            )
        }
        vault.updateItem(item.withSharedStatus(recipientUserId))
        VelaRepositories.audit.record("share_sent", "To ${recipientUserId.take(8)}")
    }

    fun acceptShare(shareId: String) {
        val shareDkB64 = identityStore.load()?.shareDkB64 ?: error("Share key not available")
        sync.withAuthenticatedClient { client, token ->
            val (inbox, newToken) = client.getInbox(token)
            val item = inbox.find { it.id == shareId } ?: error("Share not found")
            val decoded = openShareItem(shareDkB64, item.capsuleB64)?.withReceivedShare()
                ?: error("Could not decrypt shared item")
            vault.addItem(decoded)
            client.deleteInboxItem(newToken ?: token, shareId)
            VelaRepositories.audit.record("share_received", "From ${item.senderUserId.take(8)}")
        }
    }

    fun declineShare(shareId: String) {
        sync.withAuthenticatedClient { client, token -> client.deleteInboxItem(token, shareId) }
        VelaRepositories.audit.record("share_declined", shareId.take(8))
    }

    fun revokeShare(shareId: String) {
        sync.withAuthenticatedClient { client, token -> client.deleteLinkedShare(token, shareId) }
        manifest.remove(shareId)
        VelaRepositories.audit.record("share_revoked", shareId.take(8))
    }

    fun pushShareUpdates(item: VaultItem) {
        val records = manifest.forItem(item.id)
        if (records.isEmpty()) return
        val itemJson = VaultJson.encodeItem(item).toString(Charsets.UTF_8)
        sync.withAuthenticatedClient { client, token ->
            for (record in records) {
                val newCapsule = NativeVelaCore.sealShare(record.recipientShareEkB64, itemJson) ?: continue
                client.updateLinkedShare(token, record.shareId, newCapsule)
            }
        }
    }

    /// Approve a browser's ephemeral web access. Parses the link QR, seals the
    /// appropriate capsule (RO vault snapshot / RW RMS) to the browser's ephemeral
    /// key, grants it, and records the audit event. Returns the granted expiry.
    /// See EPHEMERAL_WEB_ACCESS_DESIGN.md §14 for the wire formats.
    fun grantWebAccess(qrJson: String, mode: String, ttlSecs: Long): String {
        require(mode == "ro" || mode == "rw") { "mode must be 'ro' or 'rw'" }
        // The QR/code now carries only the session id (and optional #fingerprint); fetch the
        // browser's ephemeral key from the server (keeps the QR small enough to scan).
        val (sessionId, expectedFp) = parseSessionId(qrJson)

        val expiresAt = sync.withAuthenticatedClient { client, token ->
            val (ephemeralPk, webVk) = client.getWebSessionKeys(token, sessionId)

            // Verify fingerprint if present to detect server-side key substitution.
            if (expectedFp != null) {
                val keyBytes = android.util.Base64.decode(ephemeralPk, android.util.Base64.DEFAULT)
                val digest = java.security.MessageDigest.getInstance("SHA-256").digest(keyBytes)
                val actualFp = base32Encode(digest.take(8).toByteArray())
                require(actualFp == expectedFp) {
                    "Key fingerprint mismatch — possible server-side key substitution. " +
                    "Expected $expectedFp, got $actualFp. Approval aborted."
                }
            }

            val envelope = JSONObject().put("v", 1).put("mode", mode)
            if (mode == "rw") {
                if (webVk.isBlank()) error("This browser did not offer read-write access; choose read-only.")
                val rms = security.currentRmsCopy() ?: error("Vault is locked")
                try {
                    envelope.put("rms_b64", Base64.getEncoder().encodeToString(rms))
                } finally {
                    rms.fill(0)
                }
            } else {
                val vaultJson = VaultJson.encode(vault.snapshot()).toString(Charsets.UTF_8)
                envelope.put("vault", JSONObject(vaultJson))
            }

            val capsuleB64 = NativeVelaCore.sealShare(ephemeralPk, envelope.toString())
                ?: error("Native VELA bridge is required for web access")
            client.grantWebSession(token, sessionId, mode, capsuleB64, ttlSecs)
        }
        val label = if (mode == "rw") "read-write" else "read-only"
        VelaRepositories.audit.record("web_session_granted", "$label · ${ttlSecs / 60} min")
        return expiresAt
    }

    /// The scanned/pasted code is `{id}#{fingerprint}`, a bare id, or (older) JSON.
    /// Returns `Pair(sessionId, expectedFingerprint?)`.
    private fun parseSessionId(input: String): Pair<String, String?> {
        val t = input.trim()
        if (t.startsWith("{")) return Pair(JSONObject(t).getString("session_id"), null)
        val hash = t.indexOf('#')
        return if (hash >= 0) Pair(t.substring(0, hash), t.substring(hash + 1).ifEmpty { null })
        else Pair(t, null)
    }

    private fun base32Encode(bytes: ByteArray): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var bits = 0; var value = 0; val out = StringBuilder()
        for (b in bytes) {
            value = (value shl 8) or (b.toInt() and 0xff); bits += 8
            while (bits >= 5) { out.append(alphabet[(value shr (bits - 5)) and 31]); bits -= 5 }
        }
        if (bits > 0) out.append(alphabet[(value shl (5 - bits)) and 31])
        return out.toString()
    }

    private fun openShareItem(shareDkB64: String, capsuleB64: String): VaultItem? {
        val json = NativeVelaCore.openShare(shareDkB64, capsuleB64) ?: return null
        return VaultJson.decodeItem(json.toByteArray(Charsets.UTF_8))
    }
}

class AuditLogRepository(context: Context) {
    private val prefs = context.getSharedPreferences("vela_audit", Context.MODE_PRIVATE)

    fun list(): List<AuditEntry> {
        val array = JSONArray(prefs.getString(KEY_ENTRIES, "[]"))
        return buildList {
            for (index in 0 until array.length()) {
                val json = array.getJSONObject(index)
                add(
                    AuditEntry(
                        id = json.optString("id"),
                        timestamp = Instant.parse(json.optString("timestamp")),
                        actionType = json.optString("action_type"),
                        detail = json.optString("detail").takeIf { it.isNotBlank() },
                        deviceName = json.optString("device_name", android.os.Build.MODEL ?: "Android")
                    )
                )
            }
        }
    }

    fun record(actionType: String, detail: String? = null) {
        val entries = (list() + AuditEntry(actionType = actionType, detail = detail)).takeLast(1000)
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(
                JSONObject()
                    .put("id", entry.id)
                    .put("timestamp", entry.timestamp.toString())
                    .put("action_type", entry.actionType)
                    .put("detail", entry.detail)
                    .put("device_name", entry.deviceName)
            )
        }
        prefs.edit().putString(KEY_ENTRIES, array.toString()).apply()
    }

    companion object {
        private const val KEY_ENTRIES = "entries"
    }
}

object BreachCheckService {
    fun checkEmail(email: String): List<BreachEntry> {
        val encoded = URLEncoder.encode(email, Charsets.UTF_8.name())
        val response = request("https://haveibeenpwned.com/api/v3/breachedaccount/$encoded?truncateResponse=false")
        if (response.code == 404) return emptyList()
        if (response.code == 401 || response.code == 403) {
            error("HaveIBeenPwned email checks require an API key on this endpoint")
        }
        if (response.code !in 200..299) error("HIBP API error: HTTP ${response.code}")
        val array = JSONArray(response.body)
        return buildList {
            for (index in 0 until array.length()) {
                val json = array.getJSONObject(index)
                add(
                    BreachEntry(
                        name = json.optString("Name"),
                        title = json.optString("Title"),
                        domain = json.optString("Domain"),
                        breachDate = json.optString("BreachDate"),
                        description = json.optString("Description").replace(Regex("<[^>]*>"), ""),
                        dataClasses = json.optJSONArray("DataClasses")?.let { classes ->
                            buildList {
                                for (i in 0 until classes.length()) add(classes.optString(i))
                            }
                        }.orEmpty(),
                        isVerified = json.optBoolean("IsVerified"),
                        isFabricated = json.optBoolean("IsFabricated"),
                        isSensitive = json.optBoolean("IsSensitive"),
                        isRetired = json.optBoolean("IsRetired"),
                        isSpamList = json.optBoolean("IsSpamList")
                    )
                )
            }
        }
    }

    fun checkPassword(password: String): PasswordBreachResult {
        val hash = MessageDigest.getInstance("SHA-1")
            .digest(password.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02X".format(it) }
        val prefix = hash.take(5)
        val suffix = hash.drop(5)
        val response = request("https://api.pwnedpasswords.com/range/$prefix")
        if (response.code !in 200..299) error("Pwned Passwords API error: HTTP ${response.code}")
        response.body.lineSequence().forEach { line ->
            val parts = line.split(':')
            if (parts.size == 2 && parts[0] == suffix) {
                val count = parts[1].toIntOrNull() ?: 0
                return PasswordBreachResult(
                    breached = true,
                    count = count,
                    description = "This password appears $count times in breached password databases."
                )
            }
        }
        return PasswordBreachResult(false, 0, "This password has not been found in known breaches.")
    }

    private fun request(url: String): HttpTextResponse {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 20_000
            setRequestProperty("User-Agent", "VELA-Android-App")
        }
        val code = connection.responseCode
        val body = runCatching {
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            stream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
        }.getOrDefault("")
        return HttpTextResponse(code, body)
    }
}

private data class HttpTextResponse(val code: Int, val body: String)

private fun VaultItem.withSharedStatus(recipient: String): VaultItem =
    withMeta { it.copy(shared = true, shareRecipient = recipient) }

private fun VaultItem.withReceivedShare(): VaultItem =
    withMeta { it.copy(id = UUID.randomUUID().toString(), shared = true, shareRecipient = null) }
