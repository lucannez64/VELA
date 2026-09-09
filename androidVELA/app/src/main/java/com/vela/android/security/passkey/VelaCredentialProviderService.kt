package com.vela.android.security.passkey

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.vela.android.MainActivity
import com.vela.android.R
import com.vela.android.core.VelaRepositories
import com.vela.android.core.VaultItem

/**
 * VELA as a system-wide passkey provider (`security/passkey-android-provider-adr.md`).
 *
 * When any app or browser asks Android's Credential Manager for a passkey,
 * the platform binds this service and calls its begin-methods; VELA answers
 * with a [PendingIntent] so its own prompt screen — unlock, confirm, and when
 * the site requires it a real biometric/PIN step — stands between the request
 * and every signature. The ceremony itself runs in
 * [PasskeyPromptActivity]; this service only decides which credentials exist
 * for a relying party and hands the platform the intent that starts the
 * ceremony.
 *
 * Mirrors the desktop's `vela-win-passkey` provider: same invariants, thin
 * transport. Notably the *begin* phase sees only credential metadata that is
 * already in memory, and never a private key — keys are used where they are
 * stored, inside the native bridge, one signature at a time.
 */
class VelaCredentialProviderService : androidx.credentials.provider.CredentialProviderService() {

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        runCatching {
            val builder = BeginGetCredentialResponse.Builder()

            if (!VelaRepositories.security.session.value.unlocked) {
                // The vault is sealed; there is no honest way to enumerate
                // passkeys. Offer the unlock instead — the caller may retry.
                builder.addAuthenticationAction(
                    AuthenticationAction(
                        getString(R.string.passkey_provider_unlock_action),
                        unlockIntent(),
                    )
                )
                callback.onResult(builder.build())
                return
            }

            val passkeys = VelaRepositories.vault.items.value
                .filterIsInstance<VaultItem.Passkey>()
                .filter { it.privateKey.isNotEmpty() }

            for (option in request.beginGetCredentialOptions) {
                val publicKeyOption = option as? BeginGetPublicKeyCredentialOption
                val rpId = publicKeyOption?.let(::rpIdOf) ?: continue
                // Exact RP ID match — the same narrowing the desktop applies
                // before it signs anything.
                for (passkey in passkeys.filter { it.rpId == rpId }) {
                    builder.addCredentialEntry(
                        PublicKeyCredentialEntry(
                            this,
                            username = passkey.userName.ifEmpty {
                                passkey.userDisplayName.ifEmpty { passkey.rpId }
                            },
                            pendingIntent = promptIntent(),
                            beginGetPublicKeyCredentialOption = publicKeyOption,
                        )
                    )
                }
            }
            callback.onResult(builder.build())
        }.onFailure { error ->
            android.util.Log.e(TAG, "begin get failed", error)
            callback.onError(GetCredentialUnknownException())
        }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        runCatching {
            val creation = (request as? BeginCreatePublicKeyCredentialRequest)
                ?.let { WebAuthnJson.parseCreationOptions(it.requestJson) }

            val response = BeginCreateCredentialResponse.Builder()
            if (creation != null) {
                response.addCreateEntry(
                    CreateEntry.Builder(
                        creation.userName.ifEmpty { creation.rpId },
                        promptIntent(),
                    ).setAutoSelectAllowed(false).build()
                )
            }
            callback.onResult(response.build())
        }.onFailure { error ->
            android.util.Log.e(TAG, "begin create failed", error)
            callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onClearCredentialStateRequest(
        request: androidx.credentials.provider.ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, androidx.credentials.exceptions.ClearCredentialException>,
    ) {
        // Nothing to clear: credentials live in the sealed vault, not in any
        // provider-side cache keyed to a calling app.
        callback.onResult(null)
    }

    /** The relying party a get-option is asking about. */
    private fun rpIdOf(option: BeginGetPublicKeyCredentialOption): String? {
        // The request JSON is the standard WebAuthn dictionary and is the
        // authoritative source; the candidate-query bundle carries the same id
        // for the enumeration pass where no full JSON was sent.
        rpIdFromJson(option.requestJson)?.let { return it }
        return option.candidateQueryData.getString(BUNDLE_KEY_RP_ID)?.takeIf { it.isNotBlank() }
    }

    /**
     * The ceremony intent. [androidx.credentials.provider.PendingIntentHandler]
     * reads the request back out of the launching extras, so the intent must
     * stay mutable — the library mutates it to carry the request.
     */
    private fun promptIntent(): PendingIntent {
        val intent = Intent(this, PasskeyPromptActivity::class.java)
        return PendingIntent.getActivity(
            this,
            /* requestCode = */ 0,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    /** Plain launcher intent: opening the app is all "unlock" needs. */
    private fun unlockIntent(): PendingIntent {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return PendingIntent.getActivity(
            this,
            /* requestCode = */ 1,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    companion object {
        private const val TAG = "VelaPasskeyProvider"

        /** androidx.credentials' candidate-query key for the RP ID. */
        const val BUNDLE_KEY_RP_ID = "androidx.credentials.BUNDLE_KEY_RP_ID"
    }
}

private fun rpIdFromJson(requestJson: String): String? = runCatching {
    org.json.JSONObject(requestJson)
        .optString("rpId")
        .takeIf { it.isNotBlank() }
}.getOrNull()
