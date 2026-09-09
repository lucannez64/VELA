package com.vela.android.security.passkey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pure halves of the Android passkey ceremony, off-device: WebAuthn
 * request parsing, response envelopes, credential selection, and the
 * clientDataJSON the provider builds. The byte layouts themselves are pinned
 * in the Rust bridge (`vela-android-bridge/src/passkey.rs`), which mirrors the
 * desktop's `passkey.rs` — these tests pin the plumbing between them.
 */
class WebAuthnJsonTest {

    // ── Base64url ────────────────────────────────────────────────────────────

    @Test
    fun `base64url round trips without padding`() {
        val bytes = byteArrayOf(0, 1, 2, 250.toByte(), 251.toByte(), 252.toByte())
        assertArrayEquals(bytes, WebAuthnJson.b64urlDecode(WebAuthnJson.b64urlEncode(bytes)))
        assertFalse(WebAuthnJson.b64urlEncode(bytes).contains("="))
    }

    @Test
    fun `malformed base64url decodes to null rather than throwing`() {
        assertNull(WebAuthnJson.b64urlDecode("not base64!!"))
    }

    // ── Creation options ─────────────────────────────────────────────────────

    @Test
    fun `creation options parse from the standard dictionary`() {
        val options = WebAuthnJson.parseCreationOptions(
            """
            {"rp":{"id":"example.com","name":"Example"},
             "user":{"id":"AAEC","name":"ada","displayName":"Ada"},
             "challenge":"AQID",
             "pubKeyCredParams":[{"type":"public-key","alg":-7}],
             "excludeCredentials":[{"type":"public-key","id":"BAUF"}],
             "userVerification":"required"}
            """.trimIndent()
        )!!

        assertEquals("example.com", options.rpId)
        assertEquals("Example", options.rpName)
        assertEquals("ada", options.userName)
        assertEquals("Ada", options.userDisplayName)
        assertEquals("AQID", WebAuthnJson.b64urlEncode(options.challenge))
        assertEquals("AAEC", WebAuthnJson.b64urlEncode(options.userHandle))
        assertEquals(listOf(-7), options.algorithms)
        assertEquals(listOf("BAUF"), options.excludedCredentialIds)
        assertTrue(options.requireUserVerification)
    }

    @Test
    fun `user verification preferred is not required`() {
        val options = WebAuthnJson.parseCreationOptions(
            """{"rp":{"id":"example.com"},"user":{"id":"AA"},"challenge":"AA",
                 "userVerification":"preferred"}""".trimIndent()
        )!!
        assertFalse(options.requireUserVerification)
    }

    @Test
    fun `a creation request without an rp id is refused`() {
        assertNull(WebAuthnJson.parseCreationOptions("""{"rp":{},"user":{"id":"AA"},"challenge":"AA"}"""))
        assertNull(WebAuthnJson.parseCreationOptions("not json"))
    }

    @Test
    fun `relying parties without es256 are refused`() {
        assertFalse(WebAuthnJson.acceptsEs256(listOf(-8, -257)))
        assertTrue(WebAuthnJson.acceptsEs256(listOf(-7)))
        assertTrue(WebAuthnJson.acceptsEs256(emptyList()))
    }

    // ── Request options ──────────────────────────────────────────────────────

    @Test
    fun `request options parse with allowCredentials`() {
        val options = WebAuthnJson.parseRequestOptions(
            """
            {"rpId":"example.com","challenge":"AQID",
             "allowCredentials":[{"type":"public-key","id":"BAUF"},{"type":"public-key","id":"CA"}]}
            """.trimIndent()
        )!!

        assertEquals("example.com", options.rpId)
        assertEquals("AQID", WebAuthnJson.b64urlEncode(options.challenge))
        assertEquals(listOf("BAUF", "CA"), options.allowCredentialIds)
        assertFalse(options.requireUserVerification)
    }

    // ── Credential selection ─────────────────────────────────────────────────

    private data class Credential(val rpId: String, val credentialId: String)

    private fun select(
        credentials: List<Credential>,
        rpId: String,
        allow: List<String>,
    ) = WebAuthnJson.selectCredential(
        credentials,
        rpIdOf = { it.rpId },
        credentialIdOf = { it.credentialId },
        rpId = rpId,
        allowCredentialIds = allow,
    )

    @Test
    fun `an assertion is scoped to one relying party`() {
        val credentials = listOf(
            Credential("example.com", "one"),
            Credential("other.com", "two"),
        )
        assertEquals("one", select(credentials, "example.com", emptyList())?.credentialId)
        assertNull(select(credentials, "evil.com", emptyList()))
    }

    @Test
    fun `allowCredentials stops a request naming one account being answered with another`() {
        val credentials = listOf(
            Credential("example.com", "one"),
            Credential("example.com", "two"),
        )
        assertEquals("two", select(credentials, "example.com", listOf("two"))?.credentialId)
        assertNull(select(credentials, "example.com", listOf("three")))
        // A discoverable request takes any credential for the RP.
        assertEquals("one", select(credentials, "example.com", emptyList())?.credentialId)
    }

    // ── clientDataJSON ───────────────────────────────────────────────────────

    @Test
    fun `clientDataJson carries type challenge and origin`() {
        val json = WebAuthnJson.buildClientDataJson(
            WebAuthnJson.TYPE_GET, byteArrayOf(1, 2, 3), "https://example.com"
        )
        val parsed = org.json.JSONObject(json)
        assertEquals("webauthn.get", parsed.getString("type"))
        assertEquals("AQID", parsed.getString("challenge"))
        assertEquals("https://example.com", parsed.getString("origin"))
    }

    // ── Response envelopes ───────────────────────────────────────────────────

    @Test
    fun `the registration response carries the extended relying-party shape`() {
        val response = org.json.JSONObject(
            WebAuthnJson.registrationResponse(
                "AQ", "attestation".toByteArray(), "authData".toByteArray(),
                "spki", "{}"
            )
        )
        assertEquals("public-key", response.getString("type"))
        assertEquals("AQ", response.getString("id"))
        assertEquals(-7, response.getJSONObject("response").getInt("publicKeyAlgorithm"))
        assertEquals("spki", response.getJSONObject("response").getString("publicKey"))
        assertEquals(
            "authData",
            String(WebAuthnJson.b64urlDecode(response.getJSONObject("response").getString("authenticatorData"))!!),
        )
        assertEquals("internal", response.getJSONObject("response").getJSONArray("transports").getString(0))
        assertEquals(0, response.getJSONObject("clientExtensionResults").length())
        assertEquals("{}", String(
            WebAuthnJson.b64urlDecode(response.getJSONObject("response").getString("clientDataJSON"))!!
        ))
    }

    @Test
    fun `the assertion response carries the authenticator pieces`() {
        val response = org.json.JSONObject(
            WebAuthnJson.assertionResponse(
                "AQ", "authData".toByteArray(), "sig".toByteArray(),
                "handle".toByteArray(), "{}"
            )
        )
        val inner = response.getJSONObject("response")
        assertEquals("authData", String(WebAuthnJson.b64urlDecode(inner.getString("authenticatorData"))!!))
        assertEquals("sig", String(WebAuthnJson.b64urlDecode(inner.getString("signature"))!!))
        assertEquals("handle", String(WebAuthnJson.b64urlDecode(inner.getString("userHandle"))!!))
        assertEquals("{}", String(WebAuthnJson.b64urlDecode(inner.getString("clientDataJSON"))!!))
        assertEquals(0, response.getJSONObject("clientExtensionResults").length())
    }

    @Test
    fun `an empty user handle is omitted rather than nulled`() {
        val response = org.json.JSONObject(
            WebAuthnJson.assertionResponse(
                "AQ", "authData".toByteArray(), "sig".toByteArray(),
                ByteArray(0), "{}"
            )
        )
        assertEquals(false, response.getJSONObject("response").has("userHandle"))
        assertEquals(0, response.getJSONObject("clientExtensionResults").length())
    }
}
