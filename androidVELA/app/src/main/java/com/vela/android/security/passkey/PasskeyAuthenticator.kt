package com.vela.android.security.passkey

import com.vela.android.core.NativeVelaCore
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import java.time.Instant
import java.util.UUID

/**
 * The WebAuthn ceremonies the Android passkey provider runs.
 *
 * This is the Kotlin mirror of the desktop core's `passkey.rs` ceremony,
 * composed from the same byte-level primitives the bridge exposes
 * (`NativeVelaCore.passkey*`, which are line-for-line ports of the desktop's
 * helpers). The invariants carry over:
 *
 * 1. **One ceremony per human action.** Every entry point here is called
 *    exactly once per user approval of the prompt activity — there is no API
 *    to mint an assertion without having shown the screen.
 * 2. **An assertion is bound to one RP.** The RP ID hash is inside
 *    `authenticatorData` ([WebAuthnJson.selectCredential] enforces the exact
 *    RP ID match before anything is signed).
 * 3. **The private key is used where it is stored.** The scalar goes to the
 *    native bridge as one call's input; only the DER signature comes back.
 *    It is never logged, rendered or returned.
 *
 * `verified` is the Kotlin stand-in for the desktop's `PresenceToken`: true
 * only when the prompt ran a real user verification (biometric/PIN), and it
 * alone decides whether the `UV` flag is set — never the relying party's
 * request by itself.
 */
object PasskeyAuthenticator {

    /** Everything that can go wrong, in terms the caller can show. */
    sealed class CeremonyException(message: String) : Exception(message) {
        object VaultLocked : CeremonyException("Vault is locked")
        object NoCredential : CeremonyException("No passkey for this site")
        object UserVerificationUnavailable :
            CeremonyException("This site requires biometric or PIN verification")

        object CredentialExcluded : CeremonyException("A passkey for this account already exists")
        object UnsupportedAlgorithm : CeremonyException("This site does not accept ES256")
        object MissingOrigin : CeremonyException("The requesting app did not declare an origin")
        class Malformed(what: String) : CeremonyException("Stored passkey is unusable: $what")
    }

    data class RegistrationResult(
        /** The vault item to store — the credential was created *for* the vault. */
        val item: VaultItem.Passkey,
        /** The `PublicKeyCredential` JSON to hand back to Credential Manager. */
        val responseJson: String,
    )

    /**
     * Run a registration ceremony for [options] and build the vault item for
     * the new credential. Call at most once per approval.
     *
     * `clientDataHash` is the relying party's own clientDataJSON hash, passed
     * through by Credential Manager when a privileged browser built the
     * envelope itself; when it is given, the signature covers it and the
     * response carries no clientDataJSON of ours. Otherwise `origin` is
     * required and the envelope is built here — a request that declares
     * neither is refused.
     */
    fun makeCredential(
        options: WebAuthnJson.CreationOptions,
        origin: String?,
        verified: Boolean,
        clientDataHash: ByteArray? = null,
    ): RegistrationResult {
        if (!WebAuthnJson.acceptsEs256(options.algorithms)) {
            throw CeremonyException.UnsupportedAlgorithm
        }
        if (options.requireUserVerification && !verified) {
            throw CeremonyException.UserVerificationUnavailable
        }
        val clientDataJson = clientDataHash?.let { null } ?: buildClientDataJson(
            WebAuthnJson.TYPE_CREATE, options.challenge, origin
        )
        // Registration does not sign: the relying party verifies the fresh
        // public key inside the attested credential data. The clientDataHash
        // (when the browser supplied one) only matters for assertions.

        val key = NativeVelaCore.passkeyKeygen(options.algorithms)
            ?: throw CeremonyException.Malformed("the native bridge is unavailable")

        // A freshly minted credential starts its counter at 1 for its own
        // registration, matching what the first assertion is compared against.
        val authenticatorDataB64 = NativeVelaCore.passkeyAuthenticatorData(
            rpId = options.rpId,
            flags = FLAG_UP or FLAG_AT or (if (verified) FLAG_UV else 0),
            signCount = 1,
            credentialIdB64 = key.credentialIdB64,
            cosePublicKeyB64 = key.cosePublicKeyB64,
        ) ?: throw CeremonyException.Malformed("the native bridge is unavailable")
        val attestationObject = NativeVelaCore.passkeyAttestationObject(authenticatorDataB64)
            ?: throw CeremonyException.Malformed("the native bridge is unavailable")
        val authenticatorData = WebAuthnJson.b64urlDecode(authenticatorDataB64)
            ?: throw CeremonyException.Malformed("authenticator data is not base64url")

        val item = VaultItem.Passkey(
            meta = VaultMeta(
                id = UUID.randomUUID().toString(),
                name = options.rpName.ifEmpty { options.rpId },
            ),
            rpId = options.rpId,
            rpName = options.rpName,
            credentialId = key.credentialIdB64,
            userHandle = WebAuthnJson.b64urlEncode(options.userHandle),
            userName = options.userName,
            userDisplayName = options.userDisplayName,
            privateKey = key.scalarB64,
            signCount = 1,
        )

        return RegistrationResult(
            item = item,
            responseJson = WebAuthnJson.registrationResponse(
                key.credentialIdB64,
                attestationObject,
                authenticatorData,
                key.spkiDerB64,
                // Empty when the relying party built its own clientDataJSON
                // and handed us the hash to sign over.
                clientDataJson ?: "",
            ),
        )
    }

    data class AssertionResult(
        /** The `PublicKeyCredential` JSON to hand back to Credential Manager. */
        val responseJson: String,
        /** The counter to persist after the response has been delivered. */
        val nextSignCount: Long,
    )

    /**
     * Sign one assertion with [item] for [options]. Call at most once per
     * approval. The caller persists [AssertionResult.nextSignCount] afterwards
     * — like the desktop, a counter that fails to persist is a future
     * "cloned authenticator" warning, not a refused login.
     *
     * See [makeCredential] for `origin` / `clientDataHash`.
     */
    fun getAssertion(
        item: VaultItem.Passkey,
        options: WebAuthnJson.RequestOptions,
        origin: String?,
        verified: Boolean,
        clientDataHash: ByteArray? = null,
    ): AssertionResult {
        if (options.requireUserVerification && !verified) {
            throw CeremonyException.UserVerificationUnavailable
        }
        if (item.privateKey.isEmpty()) {
            throw CeremonyException.NoCredential
        }

        val clientDataJson = clientDataHash?.let { null } ?: buildClientDataJson(
            WebAuthnJson.TYPE_GET, options.challenge, origin
        )
        val clientDataHashUsed = clientDataHash
            ?: WebAuthnJson.sha256(clientDataJson!!.toByteArray(Charsets.UTF_8))
        // WebAuthn §6.3.3: the signature covers authenticatorData ‖
        // clientDataHash. The RP ID hash is inside authenticatorData, which is
        // what binds this signature to this origin.
        val authenticatorDataB64 = NativeVelaCore.passkeyAuthenticatorData(
            rpId = options.rpId,
            flags = FLAG_UP or (if (verified) FLAG_UV else 0),
            signCount = (item.signCount + 1).coerceIn(0, Int.MAX_VALUE.toLong()).toInt(),
        ) ?: throw CeremonyException.Malformed("the native bridge is unavailable")
        val authenticatorData = WebAuthnJson.b64urlDecode(authenticatorDataB64)
            ?: throw CeremonyException.Malformed("authenticator data is not base64url")

        val message = authenticatorData + clientDataHashUsed
        val signature = NativeVelaCore.passkeySign(item.privateKey, message)
            ?: throw CeremonyException.Malformed("the native bridge is unavailable")

        val userHandle = WebAuthnJson.b64urlDecode(item.userHandle) ?: ByteArray(0)
        return AssertionResult(
            responseJson = WebAuthnJson.assertionResponse(
                item.credentialId, authenticatorData, signature, userHandle, clientDataJson ?: ""
            ),
            nextSignCount = item.signCount + 1,
        )
    }

    // WebAuthn §6.1 flags, duplicated from the bridge so callers need no native
    // call to compose them; the bridge treats them as an opaque byte.
    private const val FLAG_UP = 0x01
    private const val FLAG_UV = 0x04
    private const val FLAG_AT = 0x40

    /**
     * Build the clientDataJSON envelope from the origin we resolved — refused,
     * never guessed, when the request declared none and supplied no hash.
     */
    private fun buildClientDataJson(type: String, challenge: ByteArray, origin: String?): String {
        if (origin.isNullOrBlank()) throw CeremonyException.MissingOrigin
        return WebAuthnJson.buildClientDataJson(type, challenge, origin)
    }
}
