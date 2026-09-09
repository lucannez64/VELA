package com.vela.android.security.passkey

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

/**
 * WebAuthn JSON plumbing for the passkey provider, kept free of Android and
 * native calls so it is unit-testable on the JVM.
 *
 * Credential Manager hands a provider the standard WebAuthn dictionaries
 * (the same JSON `navigator.credentials.create/get` takes) and expects the
 * standard `PublicKeyCredential` JSON back. The provider — unlike the desktop
 * shim — builds `clientDataJSON` itself, from the origin the platform
 * supplies, because there is no page context here to do it for us.
 */
object WebAuthnJson {

    // ── Base64url ────────────────────────────────────────────────────────────

    fun b64urlEncode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun b64urlDecode(value: String): ByteArray? = runCatching {
        Base64.getUrlDecoder().decode(value)
    }.getOrNull()

    fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    // ── Registration (navigator.credentials.create) ─────────────────────────

    data class CreationOptions(
        val rpId: String,
        val rpName: String,
        val userHandle: ByteArray,
        val userName: String,
        val userDisplayName: String,
        val challenge: ByteArray,
        val algorithms: List<Int>,
        val excludedCredentialIds: List<String>,
        val requireUserVerification: Boolean,
    )

    fun parseCreationOptions(requestJson: String): CreationOptions? {
        val json = runCatching { JSONObject(requestJson) }.getOrNull() ?: return null
        val rp = json.optJSONObject("rp") ?: return null
        val rpId = rp.optString("id").takeIf { it.isNotEmpty() } ?: return null
        val user = json.optJSONObject("user") ?: return null
        val challenge = b64urlDecode(json.optString("challenge")) ?: return null
        val userHandle = b64urlDecode(user.optString("id")) ?: return null

        val algorithms = json.optJSONArray("pubKeyCredParams")
            ?.let { params ->
                (0 until params.length()).mapNotNull { index ->
                    val param = params.optJSONObject(index) ?: return@mapNotNull null
                    if (param.optString("type") == "public-key") param.optInt("alg") else null
                }
            }
            .orEmpty()

        val excluded = json.optJSONArray("excludeCredentials")
            ?.let { list ->
                (0 until list.length()).mapNotNull { index ->
                    list.optJSONObject(index)?.optString("id")?.takeIf { it.isNotEmpty() }
                }
            }
            .orEmpty()

        return CreationOptions(
            rpId = rpId,
            rpName = rp.optString("name"),
            userHandle = userHandle,
            userName = user.optString("name"),
            userDisplayName = user.optString("displayName"),
            challenge = challenge,
            algorithms = algorithms,
            excludedCredentialIds = excluded,
            requireUserVerification = json.optString("userVerification") == "required",
        )
    }

    // ── Authentication (navigator.credentials.get) ───────────────────────────

    data class RequestOptions(
        val rpId: String,
        val challenge: ByteArray,
        val allowCredentialIds: List<String>,
        val requireUserVerification: Boolean,
    )

    fun parseRequestOptions(requestJson: String): RequestOptions? {
        val json = runCatching { JSONObject(requestJson) }.getOrNull() ?: return null
        val rpId = json.optString("rpId").takeIf { it.isNotEmpty() } ?: return null
        val challenge = b64urlDecode(json.optString("challenge")) ?: return null

        val allowed = json.optJSONArray("allowCredentials")
            ?.let { list ->
                (0 until list.length()).mapNotNull { index ->
                    list.optJSONObject(index)?.optString("id")?.takeIf { it.isNotEmpty() }
                }
            }
            .orEmpty()

        return RequestOptions(
            rpId = rpId,
            challenge = challenge,
            allowCredentialIds = allowed,
            requireUserVerification = json.optString("userVerification") == "required",
        )
    }

    // ── clientDataJSON ───────────────────────────────────────────────────────

    /**
     * The `clientDataJSON` the relying party will verify: type, challenge and
     * the origin the platform told us the request came from. The origin is
     * what makes this bound to the requesting site — a request without one is
     * refused by the caller, never guessed.
     */
    fun buildClientDataJson(type: String, challenge: ByteArray, origin: String): String {
        return JSONObject()
            .put("type", type)
            .put("challenge", b64urlEncode(challenge))
            .put("origin", origin)
            .put("crossOrigin", false)
            .toString()
    }

    const val TYPE_CREATE = "webauthn.create"
    const val TYPE_GET = "webauthn.get"

    // ── Response envelopes ───────────────────────────────────────────────────

    /** The `PublicKeyCredential` JSON a registration ceremony returns. */
    fun registrationResponse(
        credentialIdB64: String,
        attestationObject: ByteArray,
        clientDataJson: String,
    ): String = JSONObject()
        .put("id", credentialIdB64)
        .put("rawId", credentialIdB64)
        .put("type", "public-key")
        .put(
            "response",
            JSONObject()
                .put("attestationObject", b64urlEncode(attestationObject))
                .put("clientDataJSON", b64urlEncode(clientDataJson.toByteArray(Charsets.UTF_8))),
        )
        .toString()

    /** The `PublicKeyCredential` JSON an assertion ceremony returns. */
    fun assertionResponse(
        credentialIdB64: String,
        authenticatorData: ByteArray,
        signatureDer: ByteArray,
        userHandle: ByteArray,
        clientDataJson: String,
    ): String = JSONObject()
        .put("id", credentialIdB64)
        .put("rawId", credentialIdB64)
        .put("type", "public-key")
        .put(
            "response",
            JSONObject()
                .put("authenticatorData", b64urlEncode(authenticatorData))
                .put("signature", b64urlEncode(signatureDer))
                .put("userHandle", if (userHandle.isEmpty()) JSONObject.NULL else b64urlEncode(userHandle))
                .put("clientDataJSON", b64urlEncode(clientDataJson.toByteArray(Charsets.UTF_8))),
        )
        .toString()

    // ── Credential selection ─────────────────────────────────────────────────

    /**
     * Which stored credential may answer this request.
     *
     * Both narrowings are load-bearing (they are the desktop's, word for
     * word): the exact RP ID match is what makes an assertion origin-bound,
     * and the `allowCredentials` filter stops a request naming one account
     * being answered with another account's credential.
     */
    fun <T> selectCredential(
        credentials: List<T>,
        rpIdOf: (T) -> String,
        credentialIdOf: (T) -> String,
        rpId: String,
        allowCredentialIds: List<String>,
    ): T? {
        return credentials
            .filter { rpIdOf(it) == rpId }
            .firstOrNull { candidate ->
                allowCredentialIds.isEmpty() || credentialIdOf(candidate) in allowCredentialIds
            }
    }

    /** Whether the relying party accepts ES256. Empty means "anything". */
    fun acceptsEs256(algorithms: List<Int>): Boolean =
        algorithms.isEmpty() || algorithms.contains(-7)
}
