package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI

/**
 * Focused blank-token refusals (residual-coverage note).
 *
 * A recoverable 401 may trigger one signed re-authentication. If that
 * re-authentication yields a blank token the operation must stop before the
 * retry: a blank token is not a credential, and persisting it would erase the
 * durable token while replacing it with something the next sync cannot use.
 * A blank `X-New-Token` header is likewise never collected or committed.
 */
class BlankTokenRefusalTest {
    private val server = "https://vault.example"
    private val scopeKey = syncBaselineScope(server, "alice", 1).key

    @Test
    fun blankReauthenticationTokenIsRefusedBeforeTheRetry() {
        val state = SyncSettingsState(
            SyncSettings(
                serverUrl = server,
                bearerToken = "stored-token",
                seenLamportByContext = mapOf(scopeKey to mapOf("vault-data-000000" to 7L)),
            )
        ) { it }
        var requests = 0
        val transport = FakeTransport { _, url, _ ->
            requests++
            when (URI(url).path) {
                "/vault/sync" -> response(401, "token has been revoked")
                else -> error("a blank re-authentication token must not trigger $url")
            }
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")
        val commits = mutableListOf<String>()
        val controller = SyncAuthController(
            currentSettings = { state.settings.value },
            commitToken = { token ->
                commits += token
                state.update { it.copy(bearerToken = token) }
            },
            latestResponseToken = client::latestSessionToken,
            clearResponseToken = client::clearLatestSessionToken,
            reauthenticate = { "" },
        )

        val error = assertThrows(IdentityBindingException::class.java) {
            controller.run("stored-token") { token -> client.getSyncManifest(token) }
        }
        assertTrue(
            "the refusal must name the empty re-authentication token",
            error.message!!.contains("empty token"),
        )
        assertEquals("only the original request may run", 1, requests)
        assertEquals("stored-token", state.settings.value.bearerToken)
        assertTrue("a blank token must never be committed", commits.isEmpty())
        assertNull(client.latestSessionToken())
        assertEquals(
            7L,
            state.settings.value.seenLamportByContext.getValue(scopeKey).getValue("vault-data-000000"),
        )
    }

    @Test
    fun blankRotatedHeaderIsIgnoredAndNotCommitted() {
        val state = SyncSettingsState(
            SyncSettings(serverUrl = server, bearerToken = "stored-token")
        ) { it }
        val transport = FakeTransport { _, _, _ ->
            HttpResponse(
                code = 200,
                headers = mapOf("X-New-Token" to listOf("")),
                body = """{"epoch":1,"chunks":[]}""".toByteArray(Charsets.UTF_8),
            )
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")
        val commits = mutableListOf<String>()
        val controller = SyncAuthController(
            currentSettings = { state.settings.value },
            commitToken = { token ->
                commits += token
                state.update { it.copy(bearerToken = token) }
            },
            latestResponseToken = client::latestSessionToken,
            clearResponseToken = client::clearLatestSessionToken,
            reauthenticate = { error("no re-authentication is needed") },
        )

        val (manifest, headerToken) = controller.run("stored-token") { token ->
            client.getSyncManifest(token)
        }

        assertEquals(1L, manifest.epoch)
        assertTrue("a blank header is not a token", headerToken.isNullOrBlank())
        assertNull("a blank header must not be collected", client.latestSessionToken())
        assertEquals("stored-token", state.settings.value.bearerToken)
        assertTrue("a blank header must not be committed", commits.isEmpty())
    }

    private class FakeTransport(
        private val handler: (method: String, url: String, token: String) -> HttpResponse,
    ) : VelaHttpTransport {
        override fun request(
            method: String,
            url: String,
            token: String,
            body: ByteArray?,
            extraHeaders: Map<String, String>,
            contentType: String,
        ): HttpResponse = handler(method, url, token)
    }

    private fun response(code: Int, body: String, newToken: String? = null) = HttpResponse(
        code = code,
        headers = if (newToken == null) emptyMap() else mapOf("X-New-Token" to listOf(newToken)),
        body = body.toByteArray(Charsets.UTF_8),
    )
}
