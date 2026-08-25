package com.vela.android.security

import android.app.Activity
import android.content.Intent
import android.content.IntentSender
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.Scope
import kotlinx.coroutines.tasks.await
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Stores/retrieves Share 1 of the recovery split (SPEC.md §4.3) in the
 * user's Google Drive "appDataFolder" — a hidden, per-app storage area that
 * doesn't show up in the user's normal Drive file list or file picker. Uses
 * the Identity Authorization API for incremental scope consent (just
 * `drive.appdata`, not a full Google Sign-In) and talks to the Drive v3 REST
 * API directly with the resulting access token — consistent with how the
 * rest of this app talks to servers (raw HTTP + JSON, no heavy client
 * library).
 *
 * Authorization is a two-step dance because the system may need to show a
 * consent screen: [getAccessToken] tries silently first, and only falls
 * back to launching a resolution `IntentSender` (via the caller-supplied
 * `awaitConsent`, which must run it through
 * `Activity#startIntentSenderForResult` and hand the resulting `Intent`
 * back) when the user hasn't already granted this scope.
 */
class GoogleDriveRecoveryBackup(private val activity: Activity) {
    data class Share1Backup(
        val userId: String,
        val shareB64: String,
        val keyEpoch: Long,
        val splitId: String?
    )

    suspend fun getAccessToken(awaitConsent: suspend (IntentSender) -> Intent?): String {
        val request = AuthorizationRequest.builder()
            .setRequestedScopes(listOf(Scope(DRIVE_APPDATA_SCOPE)))
            .build()
        val client = Identity.getAuthorizationClient(activity)
        val result = client.authorize(request).await()
        if (!result.hasResolution()) {
            return result.accessToken ?: error("Google did not return a Drive access token")
        }
        val intentSender = result.pendingIntent?.intentSender
            ?: error("Drive authorization requires consent but no resolution was provided")
        val data = awaitConsent(intentSender) ?: error("Drive authorization was cancelled")
        val resolved = client.getAuthorizationResultFromIntent(data)
        return resolved.accessToken ?: error("Drive authorization was not granted")
    }

    /// Uploads (or overwrites) Share 1 as a small JSON file in the app's
    /// hidden Drive appDataFolder.
    fun uploadCandidate(
        accessToken: String,
        userId: String,
        shareB64: String,
        keyEpoch: Long,
        splitId: String,
    ) = upload(accessToken, userId, shareB64, keyEpoch, splitId, "candidate")

    fun promote(
        accessToken: String,
        userId: String,
        shareB64: String,
        keyEpoch: Long,
        splitId: String,
    ) = upload(accessToken, userId, shareB64, keyEpoch, splitId, "active")

    private fun upload(
        accessToken: String,
        userId: String,
        shareB64: String,
        keyEpoch: Long,
        splitId: String,
        status: String,
    ) {
        require(keyEpoch >= 1) { "Recovery share epoch must be positive" }
        require(userId.matches(Regex("[A-Za-z0-9-]{1,128}"))) {
            "Recovery backup account ID is invalid"
        }
        val canonicalSplitId = runCatching { java.util.UUID.fromString(splitId).toString() }
            .getOrElse { error("Recovery split ID is invalid") }
        require(status == "candidate" || status == "active") { "Recovery backup status is invalid" }
        val body = JSONObject()
            .put("version", 3)
            .put("user_id", userId)
            .put("key_epoch", keyEpoch)
            .put("split_id", canonicalSplitId)
            .put("status", status)
            .put("share_b64", shareB64)
            .toString()
            .toByteArray(Charsets.UTF_8)

        val fileName = if (status == "active") {
            "$FILE_NAME_PREFIX-$userId-active.json"
        } else {
            "$FILE_NAME_PREFIX-$userId-$keyEpoch-$canonicalSplitId.json"
        }
        val existingFileId = findFileId(accessToken, fileName)
        if (existingFileId != null) {
            request(
                "PATCH",
                "https://www.googleapis.com/upload/drive/v3/files/$existingFileId?uploadType=media",
                accessToken, body
            )
        } else {
            val metadata = JSONObject()
                .put("name", fileName)
                .put("parents", JSONArray().put("appDataFolder"))
            multipartUpload(accessToken, metadata, body)
        }
    }

    /// Downloads Share 1 from the app's hidden Drive appDataFolder, or null
    /// if this Google account has never backed one up.
    fun download(accessToken: String): Share1Backup? {
        return findRecoveryFileIds(accessToken)
            .mapNotNull { fileId -> runCatching { downloadFile(accessToken, fileId) }.getOrNull() }
            .maxWithOrNull(compareBy<Share1Backup> { it.keyEpoch }
                .thenBy { if (it.splitId != null) 1 else 0 })
    }

    private fun downloadFile(accessToken: String, fileId: String): Share1Backup {
        val response = request(
            "GET",
            "https://www.googleapis.com/drive/v3/files/$fileId?alt=media",
            accessToken,
            null
        )
        val json = JSONObject(response)
        val version = json.optInt("version", 1)
        val keyEpoch = if (json.has("key_epoch")) json.getLong("key_epoch") else if (version == 1) 1 else 0
        require(keyEpoch >= 1) { "Drive recovery backup has an invalid epoch" }
        val status = json.optString("status", "active")
        require(status != "candidate") { "Drive recovery candidate is not finalized" }
        val splitId = json.optString("split_id").takeIf { it.isNotBlank() }?.let { raw ->
            runCatching { java.util.UUID.fromString(raw).toString() }
                .getOrElse { error("Drive recovery backup has an invalid split ID") }
        }
        require(version in 1..3) { "Drive recovery backup version is unsupported" }
        if (version == 3) {
            require(status == "active") { "Drive recovery backup is not the active pointer" }
            require(splitId != null) {
                "Drive recovery backup has an invalid split ID"
            }
        }
        return Share1Backup(
            userId = json.getString("user_id"),
            shareB64 = json.getString("share_b64"),
            keyEpoch = keyEpoch,
            splitId = splitId,
        )
    }

    private fun findFileId(accessToken: String, fileName: String): String? {
        val query = URLEncoder.encode("name = '$fileName' and trashed = false", "UTF-8")
        val response = request(
            "GET",
            "https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=$query&fields=files(id)",
            accessToken, null
        )
        val files = JSONObject(response).optJSONArray("files") ?: return null
        return if (files.length() > 0) files.getJSONObject(0).getString("id") else null
    }

    private fun findRecoveryFileIds(accessToken: String): List<String> {
        val query = URLEncoder.encode(
            "name contains '$FILE_NAME_PREFIX' and trashed = false",
            "UTF-8"
        )
        val response = request(
            "GET",
            "https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=$query&fields=files(id,name)",
            accessToken,
            null
        )
        val files = JSONObject(response).optJSONArray("files") ?: return emptyList()
        return (0 until files.length()).mapNotNull { index ->
            files.optJSONObject(index)?.getString("id")
        }
    }

    private fun multipartUpload(accessToken: String, metadata: JSONObject, content: ByteArray) {
        val boundary = "vela-drive-${System.currentTimeMillis()}"
        val bodyBuilder = StringBuilder()
            .append("--").append(boundary).append("\r\n")
            .append("Content-Type: application/json; charset=UTF-8\r\n\r\n")
            .append(metadata.toString())
            .append("\r\n--").append(boundary).append("\r\n")
            .append("Content-Type: application/json; charset=UTF-8\r\n\r\n")
            .append(String(content, Charsets.UTF_8))
            .append("\r\n--").append(boundary).append("--")

        val connection = (URL("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Authorization", "Bearer $accessToken")
            setRequestProperty("Content-Type", "multipart/related; boundary=$boundary")
            doOutput = true
            connectTimeout = 15_000
            readTimeout = 20_000
        }
        connection.outputStream.use { it.write(bodyBuilder.toString().toByteArray(Charsets.UTF_8)) }
        val code = connection.responseCode
        if (code !in 200..299) {
            val text = connection.errorStream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
            throw IOException("Drive upload failed: HTTP $code — $text")
        }
    }

    private fun request(method: String, url: String, accessToken: String, body: ByteArray?): String {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            setRequestProperty("Authorization", "Bearer $accessToken")
            connectTimeout = 15_000
            readTimeout = 20_000
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            }
        }
        if (body != null) {
            connection.outputStream.use { it.write(body) }
        }
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
        if (code !in 200..299) throw IOException("Drive API error: HTTP $code — $text")
        return text
    }

    companion object {
        private const val DRIVE_APPDATA_SCOPE = "https://www.googleapis.com/auth/drive.appdata"
        // Also matches the legacy `vela-recovery-share1.json` envelope when
        // listing, while new names remain unambiguous and epoch-specific.
        private const val FILE_NAME_PREFIX = "vela-recovery-share1"
    }
}
