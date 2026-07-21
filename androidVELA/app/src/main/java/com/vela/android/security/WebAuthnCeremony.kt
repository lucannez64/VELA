package com.vela.android.security

import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import org.json.JSONObject

/**
 * Runs WebAuthn/FIDO2 registration and assertion ceremonies via Android's
 * Credential Manager (SPEC.md §4.3's "registered WebAuthn/FIDO2 recovery
 * credential"). Credential Manager's passkey APIs already speak the standard
 * WebAuthn JSON dictionary end-to-end, so the server's `public_key` options
 * object can be forwarded (after unwrapping) and its response JSON posted
 * straight back to the server — no manual base64url plumbing needed.
 */
class WebAuthnCeremony(private val context: Context) {
    private val credentialManager = CredentialManager.create(context)

    /**
     * `optionsJson` is the (already-unwrapped) PublicKeyCredentialCreationOptions
     * object from the server. Returns the attestation response JSON to POST
     * back to `/recovery/webauthn/register/finish`.
     */
    suspend fun register(optionsJson: JSONObject): JSONObject {
        val request = CreatePublicKeyCredentialRequest(requestJson = optionsJson.toString())
        val response = try {
            credentialManager.createCredential(context, request) as CreatePublicKeyCredentialResponse
        } catch (e: CreateCredentialException) {
            error("Recovery passkey registration failed: ${e.message}")
        }
        return JSONObject(response.registrationResponseJson)
    }

    /**
     * `optionsJson` is the (already-unwrapped) PublicKeyCredentialRequestOptions
     * object from the server. Returns the assertion response JSON to POST
     * back to `/recovery/recover`.
     */
    suspend fun assert(optionsJson: JSONObject): JSONObject {
        val option = GetPublicKeyCredentialOption(requestJson = optionsJson.toString())
        val request = GetCredentialRequest(listOf(option))
        val response = try {
            credentialManager.getCredential(context, request)
        } catch (e: GetCredentialException) {
            error("Recovery security key verification failed: ${e.message}")
        }
        val credential = response.credential as? PublicKeyCredential
            ?: error("No passkey credential was returned")
        return JSONObject(credential.authenticationResponseJson)
    }

    companion object {
        /**
         * The server wraps its WebAuthn options in a `publicKey` field
         * (mirroring what a browser would pass to
         * `navigator.credentials.create/get`), on top of our own `public_key`
         * HTTP response field — unwrap either shape.
         */
        fun unwrapPublicKey(json: JSONObject): JSONObject {
            json.optJSONObject("publicKey")?.let { return it }
            json.optJSONObject("public_key")?.let { return unwrapPublicKey(it) }
            return json
        }
    }
}
