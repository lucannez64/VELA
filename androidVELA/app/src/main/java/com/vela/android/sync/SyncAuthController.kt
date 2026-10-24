package com.vela.android.sync

/** A 401 that a fresh signed re-authentication may repair. */
internal fun ServerUnauthorizedException.isRecoverableTokenFailure(): Boolean {
    val text = message.orEmpty()
    return text.contains("token has been revoked", ignoreCase = true) ||
        text.contains("token verification failed", ignoreCase = true) ||
        text.contains("malformed token", ignoreCase = true) ||
        text.contains("session hard cap exceeded", ignoreCase = true)
}

/**
 * Production retry/token-acceptance controller.
 *
 * Extracted from [VaultSyncManager] so the real ordering — not a test-only
 * lambda — can be exercised against [AndroidVelaApiClient] and
 * [AccountAuthenticator]. The controller owns no Android state; the manager
 * wires these callbacks to the live settings, client and identity store.
 *
 * Token acceptance rule: a response's `X-New-Token` is accepted only when the
 * *entire* operation (including a recoverable-401 re-authentication and its
 * retry) succeeded. On any failure the client's collected token is cleared and
 * nothing is committed. A hostile server can therefore answer 401, return a
 * different `user_id` plus an `X-New-Token` on the verification response, and
 * the pin check aborts the operation without leaving that token durable.
 */
internal class SyncAuthController(
    private val currentSettings: () -> SyncSettings,
    private val commitToken: (String) -> Unit,
    private val latestResponseToken: () -> String?,
    private val clearResponseToken: () -> Unit,
    private val reauthenticate: () -> String,
) {
    fun <T> run(startToken: String, operation: (String) -> T): T {
        var token = startToken
        var reauthenticated = false
        // Start from a clean collector: only responses produced by this
        // operation (or its authenticated retry) are eligible for acceptance.
        clearResponseToken()
        try {
            val result = try {
                operation(token)
            } catch (e: ServerUnauthorizedException) {
                val settings = currentSettings()
                if (!e.isRecoverableTokenFailure() || settings.bearerToken.isBlank()) throw e
                // The 401's header token is not a success. Forget it before
                // re-authentication so a failure cannot inherit it.
                clearResponseToken()
                token = reauthenticate()
                reauthenticated = true
                // Only the retried, authenticated operation's response may
                // contribute a header token. In particular, an unauthenticated
                // `/auth/challenge` response cannot smuggle one into the
                // success path.
                clearResponseToken()
                operation(token)
            }

            // Success, and only success, may publish a replacement token. If
            // the server rotated the token, prefer the latest successful
            // response; otherwise keep the freshly authenticated token.
            val next = latestResponseToken()?.takeIf { it.isNotBlank() }
                ?: token.takeIf { reauthenticated }
            if (next != null && next != currentSettings().bearerToken) {
                commitToken(next)
            }
            return result
        } catch (t: Throwable) {
            // Do not persist anything collected from a failed auth operation.
            clearResponseToken()
            throw t
        }
    }
}
