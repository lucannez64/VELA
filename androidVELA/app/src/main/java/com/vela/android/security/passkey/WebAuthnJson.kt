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
        /** `userVerification: "required"` — refuse unless a real verification ran. */
        val requireUserVerification: Boolean,
        /**
         * `userVerification` is not `"discouraged"`.
         *
         * WebAuthn's default is `"preferred"`: perform verification when the
         * device can. Android platform passkeys are device-lock backed and
         * relying parties (Uber, banks) check the `UV` flag at their server, so
         * presence-only creation is the anomaly — the credential is stored but
         * the server rejects the registration.
         */
        val preferUserVerification: Boolean,
        /** The RP asked for the `credProps` extension (to learn discoverability). */
        val requestedCredProps: Boolean,
    )

    fun parseCreationOptions(requestJson: String): CreationOptions? {
        // Credential Manager hands the provider the standard creation
        // dictionary, but some callers wrap it as `{"publicKey": {…}}` (and a
        // few stringify it), so unwrap before reading any field.
        val json = unwrapRequest(requestJson) ?: return null
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

        // `userVerification` lives under `authenticatorSelection` (WebAuthn
        // §5.4); a top-level copy is accepted as a fallback. Absent means
        // "preferred", which — unlike "discouraged" — wants UV when possible.
        val selection = json.optJsonObjectOrString("authenticatorSelection")
        val userVerification = (
            selection?.optString("userVerification")?.takeIf { it.isNotEmpty() }
                ?: json.optString("userVerification")
            ).lowercase()
        val extensions = json.optJsonObjectOrString("extensions")

        return CreationOptions(
            rpId = rpId,
            rpName = rp.optString("name"),
            userHandle = userHandle,
            userName = user.optString("name"),
            userDisplayName = user.optString("displayName"),
            challenge = challenge,
            algorithms = algorithms,
            excludedCredentialIds = excluded,
            requireUserVerification = userVerification == "required",
            preferUserVerification = userVerification != "discouraged",
            requestedCredProps = extensions?.opt("credProps").truthy() == true,
        )
    }

    /**
     * The request dictionary, unwrapping a `{"publicKey": {…}}` envelope.
     *
     * `navigator.credentials.create/get` take `{ publicKey: … }`; some callers
     * pass that whole object through Credential Manager instead of the inner
     * dictionary, which would otherwise fail every field lookup.
     */
    private fun unwrapRequest(requestJson: String): JSONObject? {
        val parsed = runCatching { JSONObject(requestJson) }.getOrNull() ?: return null
        return parsed.optJsonObjectOrString("publicKey") ?: parsed
    }

    /** `optJSONObject`, also accepting a stringified JSON object. */
    private fun JSONObject.optJsonObjectOrString(key: String): JSONObject? {
        optJSONObject(key)?.let { return it }
        val raw = optString(key)
        return raw.takeIf { it.startsWith("{") }
            ?.let { runCatching { JSONObject(it) }.getOrNull() }
    }

    /** JSON booleans, `"true"`, or a present object all mean "requested". */
    private fun Any?.truthy(): Boolean? = when (this) {
        null, JSONObject.NULL -> null
        is Boolean -> this
        is String -> equals("true", ignoreCase = true)
        is JSONObject -> true
        else -> null
    }

    // ── Authentication (navigator.credentials.get) ───────────────────────────

    data class RequestOptions(
        val rpId: String,
        val challenge: ByteArray,
        val allowCredentialIds: List<String>,
        val requireUserVerification: Boolean,
        /** See [CreationOptions.preferUserVerification]. */
        val preferUserVerification: Boolean,
    )

    fun parseRequestOptions(requestJson: String): RequestOptions? {
        val json = unwrapRequest(requestJson) ?: return null
        val rpId = json.optString("rpId").takeIf { it.isNotEmpty() } ?: return null
        val challenge = b64urlDecode(json.optString("challenge")) ?: return null

        val allowed = json.optJSONArray("allowCredentials")
            ?.let { list ->
                (0 until list.length()).mapNotNull { index ->
                    list.optJSONObject(index)?.optString("id")?.takeIf { it.isNotEmpty() }
                }
            }
            .orEmpty()

        val userVerification = json.optString("userVerification").lowercase()

        return RequestOptions(
            rpId = rpId,
            challenge = challenge,
            allowCredentialIds = allowed,
            requireUserVerification = userVerification == "required",
            preferUserVerification = userVerification != "discouraged",
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

    /** The `PublicKeyCredential` JSON a registration ceremony returns.
     *
     * Chromium-shaped verifiers (browsers routing through Credential Manager)
     * parse more than the spec minimum and cross-check consistency:
     * `authenticatorData` must equal the bytes inside the attestation,
     * `publicKeyAlgorithm` the algorithm parsed from it, and `publicKey` the
     * SubjectPublicKeyInfo DER of the attested key. `authenticatorAttachment`
     * and the requested `credProps.rk` are part of the shape relying-party
     * clients and browsers parse, so they are emitted too.
     *
     * [credentialProperties] is the `credProps.rk` value to report, or null
     * when the relying party did not request the extension.
     */
    fun registrationResponse(
        credentialIdB64: String,
        attestationObject: ByteArray,
        authenticatorData: ByteArray,
        publicKeySpkiDerB64: String,
        clientDataJson: String,
        credentialProperties: Boolean? = null,
    ): String {
        val clientExtensionResults = JSONObject()
        if (credentialProperties != null) {
            clientExtensionResults.put(
                "credProps",
                JSONObject().put("rk", credentialProperties),
            )
        }
        return JSONObject()
            .put("id", credentialIdB64)
            .put("rawId", credentialIdB64)
            .put("type", "public-key")
            .put("authenticatorAttachment", "platform")
            .put(
                "response",
                JSONObject()
                    .put("attestationObject", b64urlEncode(attestationObject))
                    .put("authenticatorData", b64urlEncode(authenticatorData))
                    .put("publicKeyAlgorithm", -7)
                    .put("publicKey", publicKeySpkiDerB64)
                    .put("clientDataJSON", b64urlEncode(clientDataJson.toByteArray(Charsets.UTF_8)))
                    .put("transports", JSONArray().put("internal")),
            )
            // Required by the relying party's parser, and carries credProps
            // when the relying party asked for it.
            .put("clientExtensionResults", clientExtensionResults)
            .toString()
    }

    /** The `PublicKeyCredential` JSON an assertion ceremony returns. */
    fun assertionResponse(
        credentialIdB64: String,
        authenticatorData: ByteArray,
        signatureDer: ByteArray,
        userHandle: ByteArray,
        clientDataJson: String,
    ): String {
        val response = JSONObject()
            .put("authenticatorData", b64urlEncode(authenticatorData))
            .put("signature", b64urlEncode(signatureDer))
            .put("clientDataJSON", b64urlEncode(clientDataJson.toByteArray(Charsets.UTF_8)))
        if (userHandle.isNotEmpty()) {
            response.put("userHandle", b64urlEncode(userHandle))
        }
        return JSONObject()
            .put("id", credentialIdB64)
            .put("rawId", credentialIdB64)
            .put("type", "public-key")
            .put("authenticatorAttachment", "platform")
            .put("response", response)
            // Required by the relying party's parser even when empty.
            .put("clientExtensionResults", JSONObject())
            .toString()
    }

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
