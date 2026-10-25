package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

/**
 * Focused happy-path tests for the two registrations the residual-coverage
 * note lists as untested:
 *
 *  - first identity registration pins the server-verified account id and makes
 *    the returned token usable (and does not ask for a challenge);
 *  - share-key registration reaches the real HTTP client with the device-signed
 *    binding and accepts the server's rotated token.
 *
 * Only the native signing call and the HTTP transport are faked here. The
 * account binding, response parsing and header handling are production code.
 */
class IdentityRegistrationSuccessTest {
    private val server = "https://vault.example"

    @Test
    fun firstRegistrationPinsTheAccountAndReturnsTheServerToken() {
        var stored: ServerIdentity? = ServerIdentity(
            userId = null,
            deviceId = null,
            hybridEkB64 = "ek",
            hybridVkB64 = "vk",
            shareEkB64 = "share-ek",
            sealedB64 = "sealed",
            shareEkRegistrationPending = true,
        )
        var registered = 0
        var epochUpdatedTo: Long? = null
        val authenticator = AccountAuthenticator(
            loadIdentity = { stored },
            getOrCreateIdentity = { stored!! },
            saveIdentity = { stored = it },
            updateIdentity = { transform ->
                stored?.let { transform(it).also { next -> stored = next } }
            },
            signChallenge = { _, _ -> error("a registration response already returned a token") },
            registerAccount = { _ ->
                registered++
                RegisterAccountResponse(
                    userId = "alice",
                    deviceId = "device-new",
                    token = "registered-token",
                )
            },
            getChallenge = { error("a successful registration must not request a challenge") },
            verifySignature = { _, _, _ -> error("must not verify after a successful registration") },
            updateKeyEpoch = { epochUpdatedTo = it },
        )

        assertEquals("registered-token", authenticator.authenticate(IdentityBindingMode.INITIAL))
        assertEquals(1, registered)
        assertEquals(1L, epochUpdatedTo)
        assertEquals("alice", stored!!.userId)
        assertEquals("device-new", stored!!.deviceId)
        // The initial share key is retained (and stays pending only until the
        // share-key registration below succeeds).
        assertEquals("share-ek", stored!!.shareEkB64)
        assertTrue(stored!!.shareEkRegistrationPending)
    }

    @Test
    fun existingReauthenticationConfirmsTheSamePinWithoutChangingTheEpoch() {
        val stored = ServerIdentity(
            userId = "alice",
            deviceId = "device-a",
            hybridEkB64 = "ek",
            hybridVkB64 = "vk",
            sealedB64 = "sealed",
        )
        var current = stored
        var challenges = 0
        val authenticator = AccountAuthenticator(
            loadIdentity = { current },
            getOrCreateIdentity = { error("EXISTING must never create an identity") },
            saveIdentity = { current = it },
            updateIdentity = { transform -> transform(current).also { current = it } },
            signChallenge = { deviceId, challenge ->
                assertEquals("device-a", deviceId)
                assertEquals("challenge", challenge)
                "signature"
            },
            registerAccount = { error("EXISTING must never register") },
            getChallenge = {
                challenges++
                ChallengeResponse("challenge")
            },
            verifySignature = { deviceId, challenge, signature ->
                assertEquals("device-a", deviceId)
                assertEquals("challenge", challenge)
                assertEquals("signature", signature)
                VerifyResponse(token = "renewed-token", userId = "alice")
            },
            updateKeyEpoch = { error("re-authentication must not reset the epoch") },
        )

        assertEquals("renewed-token", authenticator.authenticate(IdentityBindingMode.EXISTING))
        assertEquals(1, challenges)
        assertEquals("alice", current.userId)
        assertEquals("device-a", current.deviceId)
    }

    @Test
    fun shareKeyRegistrationCarriesTheSignedBindingAndAcceptsARotatedToken() {
        val transport = CapturingTransport(
            HttpResponse(
                code = 200,
                headers = mapOf("X-New-Token" to listOf("rotated-token")),
                body = ByteArray(0),
            )
        )
        val client = AndroidVelaApiClient(server, context = null, transport, "android-test")

        val newToken = client.putMyShareEk(
            token = "token-1",
            shareEkB64 = "share-ek-1",
            deviceId = "device-a",
            signedAt = "2026-01-01T00:00:00Z",
            signature = "signature-1",
        )

        assertEquals("rotated-token", newToken)
        assertEquals("PUT", transport.method)
        assertEquals("/share/my-ek", java.net.URI(transport.url!!).path)
        assertEquals("token-1", transport.token)
        val rawBody = transport.body
        assertNotNull(rawBody)
        val body = JSONObject(rawBody!!)
        assertEquals("share-ek-1", body.getString("share_ek"))
        assertEquals("device-a", body.getString("device_id"))
        assertEquals("2026-01-01T00:00:00Z", body.getString("signed_at"))
        assertEquals("signature-1", body.getString("signature"))
        // The client collected the rotated token from the successful response.
        assertEquals("rotated-token", client.latestSessionToken())
        assertFalse(body.has("hybrid_sk_b64"))
    }

    private class CapturingTransport(private val response: HttpResponse) : VelaHttpTransport {
        var method: String? = null
        var url: String? = null
        var token: String? = null
        var body: String? = null

        override fun request(
            method: String,
            url: String,
            token: String,
            body: ByteArray?,
            extraHeaders: Map<String, String>,
            contentType: String,
        ): HttpResponse {
            this.method = method
            this.url = url
            this.token = token
            this.body = body?.toString(Charsets.UTF_8)
            return response
        }
    }
}
