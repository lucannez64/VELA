package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.URI

/**
 * Regression for the hostile-401 token leak.
 *
 * These tests drive the real production pieces: [SyncAuthController] (retry
 * and token-acceptance ordering), [AccountAuthenticator] (identity pin
 * validation), and [AndroidVelaApiClient] with a fake [VelaHttpTransport]. The
 * only fakes are the native signing call and the platform-backed identity
 * store; the HTTP parsing, header collection and pin decisions are production
 * code.
 *
 * Not covered here: the JNI signing bridge, Android Keystore-backed
 * `SharedPreferences`, and a real network stack.
 */
class SyncAuthControllerTest {
    private val server = "https://vault.example"
    private val chunk = "vault-data-000000"
    private val scopeKey = syncBaselineScope(server, "alice", 1).key
    private val baseline = mapOf(chunk to 7L)

    @Test
    fun hostile401ThenDifferentVerifiedAccountKeepsIdentityTokenAndBaselines() {
        val state = settingsWithBaseline("stored-token")
        var identity = aliceIdentity()
        val commits = mutableListOf<String>()
        val transport = FakeTransport { _, url, token ->
            when (URI(url).path) {
                "/vault/sync" -> response(401, "token has been revoked", "evil-401")
                "/auth/challenge" -> response(200, """{"challenge":"Y2hhbGxlbmdl"}""")
                "/auth/verify" -> response(
                    200,
                    """{"token":"evil-verify-token","user_id":"mallory"}""",
                    "evil-verify-header",
                )
                else -> error("unexpected request to $url (token=$token)")
            }
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")
        val authenticator = authenticator(client, { identity }, { identity = it })

        val controller = controller(state, client, authenticator, commits)

        val error = assertThrows(IdentityBindingException::class.java) {
            controller.run("stored-token") { token -> client.getSyncManifest(token) }
        }
        assertTrue(error.message!!.contains("different account"))

        assertEquals("stored-token", state.settings.value.bearerToken)
        assertEquals("alice", identity.userId)
        assertEquals(baseline, state.settings.value.seenLamportByContext.getValue(scopeKey))
        assertTrue("no token may be committed on a failed auth operation", commits.isEmpty())
        assertNull("the hostile response token must not survive the failure", client.latestSessionToken())
    }

    @Test
    fun successfulRetryAcceptsOnlyTheFinalSuccessfulResponseToken() {
        val state = settingsWithBaseline("stored-token")
        var identity = aliceIdentity()
        val commits = mutableListOf<String>()
        val transport = FakeTransport { _, url, token ->
            when (URI(url).path) {
                "/vault/sync" -> when (token) {
                    "stored-token" -> response(401, "token has been revoked", "evil-401")
                    "fresh-token" -> response(
                        200,
                        """{"epoch":1,"chunks":[]}""",
                        "rotated-token",
                    )
                    else -> response(401, "unexpected token", "evil-wrong-token")
                }
                "/auth/challenge" -> response(200, """{"challenge":"Y2hhbGxlbmdl"}""")
                "/auth/verify" -> response(
                    200,
                    """{"token":"fresh-token","user_id":"alice"}""",
                )
                else -> error("unexpected request to $url")
            }
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")
        val authenticator = authenticator(client, { identity }, { identity = it })
        val controller = controller(state, client, authenticator, commits)

        val (manifest, headerToken) = controller.run("stored-token") { token ->
            client.getSyncManifest(token)
        }

        assertEquals(1L, manifest.epoch)
        assertEquals("rotated-token", headerToken)
        assertEquals("rotated-token", state.settings.value.bearerToken)
        assertEquals(listOf("rotated-token"), commits)
        assertEquals("alice", identity.userId)
        assertEquals(baseline, state.settings.value.seenLamportByContext.getValue(scopeKey))
    }

    @Test
    fun unauthenticatedChallengeHeaderIsNotPreferredOverTheVerifiedToken() {
        val state = settingsWithBaseline("stored-token")
        var identity = aliceIdentity()
        val commits = mutableListOf<String>()
        val transport = FakeTransport { _, url, token ->
            when (URI(url).path) {
                "/vault/sync" -> when (token) {
                    "stored-token" -> response(401, "token has been revoked", "evil-401")
                    "fresh-token" -> response(200, """{"epoch":1,"chunks":[]}""")
                    else -> response(401, "unexpected token")
                }
                "/auth/challenge" -> response(
                    200,
                    """{"challenge":"Y2hhbGxlbmdl"}""",
                    "unauthenticated-header-token",
                )
                "/auth/verify" -> response(
                    200,
                    """{"token":"fresh-token","user_id":"alice"}""",
                )
                else -> error("unexpected request to $url")
            }
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")
        val authenticator = authenticator(client, { identity }, { identity = it })
        val controller = controller(state, client, authenticator, commits)

        controller.run("stored-token") { token -> client.getSyncManifest(token) }

        assertEquals("fresh-token", state.settings.value.bearerToken)
        assertEquals(listOf("fresh-token"), commits)
    }

    @Test
    fun failedRetryDoesNotPersistAnyHeaderOrFreshToken() {
        val state = settingsWithBaseline("stored-token")
        var identity = aliceIdentity()
        val commits = mutableListOf<String>()
        val transport = FakeTransport { _, url, token ->
            when (URI(url).path) {
                "/vault/sync" -> when (token) {
                    "stored-token" -> response(401, "token has been revoked", "evil-401")
                    "fresh-token" -> response(500, "server exploded", "failed-retry-token")
                    else -> response(500, "unexpected token")
                }
                "/auth/challenge" -> response(200, """{"challenge":"Y2hhbGxlbmdl"}""")
                "/auth/verify" -> response(
                    200,
                    """{"token":"fresh-token","user_id":"alice"}""",
                )
                else -> error("unexpected request to $url")
            }
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")
        val authenticator = authenticator(client, { identity }, { identity = it })
        val controller = controller(state, client, authenticator, commits)

        assertThrows(IOException::class.java) {
            controller.run("stored-token") { token -> client.getSyncManifest(token) }
        }

        // The whole operation failed, so neither the re-authentication token
        // nor a header from the failed retry may become durable.
        assertEquals("stored-token", state.settings.value.bearerToken)
        assertTrue(commits.isEmpty())
        assertNull(client.latestSessionToken())
        assertEquals("alice", identity.userId)
        assertEquals(baseline, state.settings.value.seenLamportByContext.getValue(scopeKey))
    }

    @Test
    fun clientNeverCollectsATokenFromAFailedResponse() {
        val transport = FakeTransport { _, url, _ ->
            when (URI(url).path) {
                "/vault/sync" -> response(401, "token has been revoked", "evil-401")
                else -> error("unexpected request to $url")
            }
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")

        assertThrows(ServerUnauthorizedException::class.java) {
            client.getSyncManifest("stored-token")
        }
        assertNull(client.latestSessionToken())

        // A successful response is still collected.
        val okTransport = FakeTransport { _, _, _ ->
            response(200, """{"epoch":1,"chunks":[]}""", "rotated")
        }
        val okClient = AndroidVelaApiClient(server, null, okTransport, "test-device")
        okClient.getSyncManifest("stored-token")
        assertEquals("rotated", okClient.latestSessionToken())
    }

    @Test
    fun automaticReauthWithoutAStoredPinFailsBeforeAnyRequest() {
        var requests = 0
        val transport = FakeTransport { _, url, _ ->
            requests++
            error("must not request $url")
        }
        val client = AndroidVelaApiClient(server, null, transport, "test-device")
        var saved: ServerIdentity? = null
        val authenticator = AccountAuthenticator(
            loadIdentity = { null },
            getOrCreateIdentity = { error("EXISTING must never create an identity") },
            saveIdentity = { saved = it },
            updateIdentity = { transform ->
                saved = saved?.let(transform)
                saved
            },
            signChallenge = { _, _ -> error("must not sign") },
            registerAccount = { error("must not register") },
            getChallenge = client::getChallenge,
            verifySignature = client::verifySignature,
            updateKeyEpoch = { error("must not change the epoch") },
        )

        val error = assertThrows(IdentityBindingException::class.java) {
            authenticator.authenticate(IdentityBindingMode.EXISTING)
        }
        assertTrue(error.message!!.contains("no stored identity"))
        assertEquals(0, requests)
        assertNull(saved)
    }

    private fun settingsWithBaseline(token: String) = SyncSettingsState(
        SyncSettings(
            serverUrl = server,
            bearerToken = token,
            seenLamportByContext = mapOf(scopeKey to baseline),
        )
    ) { it }

    private fun aliceIdentity() = ServerIdentity(
        userId = "alice",
        deviceId = "device-alice",
        hybridEkB64 = "ek",
        hybridVkB64 = "vk",
        sealedB64 = "sealed",
    )

    private fun authenticator(
        client: AndroidVelaApiClient,
        load: () -> ServerIdentity?,
        save: (ServerIdentity) -> Unit,
    ) = AccountAuthenticator(
        loadIdentity = load,
        getOrCreateIdentity = { error("these tests use an already-registered device") },
        saveIdentity = save,
        updateIdentity = { transform ->
            load()?.let {
                val next = transform(it)
                save(next)
                next
            }
        },
        signChallenge = { _, _ -> "signature" },
        registerAccount = { error("must not register") },
        getChallenge = client::getChallenge,
        verifySignature = client::verifySignature,
        updateKeyEpoch = { error("must not change the epoch") },
    )

    private fun controller(
        state: SyncSettingsState,
        client: AndroidVelaApiClient,
        authenticator: AccountAuthenticator,
        commits: MutableList<String>,
    ) = SyncAuthController(
        currentSettings = { state.settings.value },
        commitToken = { token ->
            commits += token
            state.update { it.copy(bearerToken = token) }
        },
        latestResponseToken = client::latestSessionToken,
        clearResponseToken = client::clearLatestSessionToken,
        reauthenticate = { authenticator.authenticate(IdentityBindingMode.EXISTING) },
    )

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
