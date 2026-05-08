package com.vela.android.core

import android.content.Context
import com.vela.android.sync.DeviceInfo
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

class SharingRepository(
    private val vault: LocalVaultRepository,
    private val security: com.vela.android.security.SecureVaultManager,
    private val sync: com.vela.android.sync.VaultSyncManager
) {
    fun listShares(): List<VaultShare> = sync.withAuthenticatedClient { client, token ->
        var currentToken = token
        val (inbox, inboxToken) = client.getInbox(currentToken)
        inboxToken?.let { currentToken = it }
        val (linked, linkedToken) = client.getLinkedShares(currentToken)
        linkedToken?.let { currentToken = it }

        val rms = security.currentRmsCopy() ?: error("Vault is locked")
        try {
            val received = inbox.map { item ->
                val decoded = decryptShareItem(rms, item.capsuleB64)
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
                    val decoded = decryptShareItem(rms, item.capsuleB64)
                    VaultShare(
                        id = item.id,
                        itemId = decoded?.id ?: item.id,
                        itemName = decoded?.name ?: "Shared item",
                        itemType = decoded?.type?.name?.lowercase() ?: "item",
                        direction = ShareDirection.Sent,
                        from = item.senderUserId,
                        to = item.recipientUserId,
                        sharedAt = item.updatedAt
                    )
                }
            received + sent
        } finally {
            rms.fill(0)
        }
    }

    fun sendShare(itemId: String, recipientUserId: String) {
        val item = vault.snapshot().items.find { it.id == itemId } ?: error("Item not found")
        val rms = security.currentRmsCopy() ?: error("Vault is locked")
        val capsule = try {
            NativeVelaCore.encryptVaultJson(rms, VaultJson.encodeItem(item).toString(Charsets.UTF_8))
                ?: error("Native VELA bridge is required for sharing")
        } finally {
            rms.fill(0)
        }

        sync.withAuthenticatedClient { client, token ->
            client.sendShare(token, recipientUserId, capsule)
        }
        vault.updateItem(item.withSharedStatus(recipientUserId))
        VelaRepositories.audit.record("share_sent", "To ${recipientUserId.take(8)}")
    }

    fun acceptShare(shareId: String) {
        sync.withAuthenticatedClient { client, token ->
            val (inbox, newToken) = client.getInbox(token)
            val item = inbox.find { it.id == shareId } ?: error("Share not found")
            val rms = security.currentRmsCopy() ?: error("Vault is locked")
            val decoded = try {
                decryptShareItem(rms, item.capsuleB64)?.withReceivedShare()
                    ?: error("Could not decrypt shared item")
            } finally {
                rms.fill(0)
            }
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
        VelaRepositories.audit.record("share_revoked", shareId.take(8))
    }

    private fun decryptShareItem(rms: ByteArray, capsuleB64: String): VaultItem? {
        val ciphertext = Base64.getDecoder().decode(capsuleB64)
        val json = NativeVelaCore.decryptVaultJson(rms, ciphertext) ?: return null
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
