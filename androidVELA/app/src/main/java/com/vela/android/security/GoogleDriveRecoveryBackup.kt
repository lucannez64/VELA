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
    data class Share1Backup(val userId: String, val shareB64: String)

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
    fun upload(accessToken: String, userId: String, shareB64: String) {
        val body = JSONObject()
            .put("version", 1)
            .put("user_id", userId)
            .put("share_b64", shareB64)
            .toString()
            .toByteArray(Charsets.UTF_8)

        val existingFileId = findFileId(accessToken)
        if (existingFileId != null) {
            request(
                "PATCH",
                "https://www.googleapis.com/upload/drive/v3/files/$existingFileId?uploadType=media",
                accessToken, body
            )
        } else {
            val metadata = JSONObject()
                .put("name", FILE_NAME)
                .put("parents", JSONArray().put("appDataFolder"))
            multipartUpload(accessToken, metadata, body)
        }
    }

    /// Downloads Share 1 from the app's hidden Drive appDataFolder, or null
    /// if this Google account has never backed one up.
    fun download(accessToken: String): Share1Backup? {
        val fileId = findFileId(accessToken) ?: return null
        val response = request(
            "GET", "https://www.googleapis.com/drive/v3/files/$fileId?alt=media", accessToken, null
        )
        val json = JSONObject(response)
        return Share1Backup(userId = json.getString("user_id"), shareB64 = json.getString("share_b64"))
    }

    private fun findFileId(accessToken: String): String? {
        val query = URLEncoder.encode("name = '$FILE_NAME' and trashed = false", "UTF-8")
        val response = request(
            "GET",
            "https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=$query&fields=files(id)",
            accessToken, null
        )
        val files = JSONObject(response).optJSONArray("files") ?: return null
        return if (files.length() > 0) files.getJSONObject(0).getString("id") else null
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
        private const val FILE_NAME = "vela-recovery-share1.json"
    }
}
