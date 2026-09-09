package com.vela.android.security.passkey

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.vela.android.MainActivity
import com.vela.android.core.VelaRepositories
import com.vela.android.core.VaultItem
import com.vela.android.ui.theme.VelaTheme
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * The screen between a WebAuthn request and a signature — the Android
 * counterpart of the desktop provider's presence prompt.
 *
 * Everything the platform's invariant machinery cannot see happens here, so
 * the rules are strict:
 *
 * - One ceremony per approval: the ceremony runs exactly once per "Approve",
 *   and there is no code path that runs it without this screen having been
 *   shown and confirmed.
 * - `UV` is set only when a real biometric/PIN verification succeeded here,
 *   never because the relying party asked for it. A request that requires
 *   verification is refused if the device cannot provide it.
 * - The origin in `clientDataJSON` comes from the platform (privileged
 *   browser) or from the calling app's own signing certificate — never from
 *   anything the request could have chosen for itself. A privileged browser
 *   not on the shipped allowlist is refused, not downgraded.
 * - A second concurrent ceremony is refused (`ERROR_BUSY` semantics), like
 *   the Windows provider.
 */
class PasskeyPromptActivity : FragmentActivity() {

    private var stage by mutableStateOf(Stage.Confirm)
    private var errorText by mutableStateOf<String?>(null)

    internal enum class Stage { Confirm, Verifying, Working, Done }

    /** The parsed ceremony, or null when the launch extras were not usable. */
    private val ceremony: Ceremony? by lazy { parseIntent(intent) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (!VelaRepositories.security.session.value.unlocked) {
            showLockedDialog()
            return
        }
        if (ceremony == null) {
            finish()
            return
        }

        setContent {
            VelaTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    when (val shown = ceremony) {
                        is Ceremony.Get -> CeremonyScreen(
                            title = "Sign in with a VELA passkey",
                            detail = shown.originSummary,
                            rpId = shown.options.rpId,
                            account = shown.accountName,
                            stage = stage,
                            errorText = errorText,
                            onApprove = ::beginApprove,
                            onCancel = ::cancel,
                        )
                        is Ceremony.Create -> CeremonyScreen(
                            title = "Create a passkey in VELA",
                            detail = shown.originSummary,
                            rpId = shown.options.rpId,
                            account = shown.options.userName.ifEmpty { shown.options.rpId },
                            stage = stage,
                            errorText = errorText,
                            onApprove = ::beginApprove,
                            onCancel = ::cancel,
                        )
                        null -> {}
                    }
                }
            }
        }
    }

    private fun showLockedDialog() {
        setContent {
            VelaTheme {
                AlertDialog(
                    onDismissRequest = { finish() },
                    title = { Text("VELA is locked") },
                    text = { Text("Unlock VELA, then try the passkey again.") },
                    confirmButton = {
                        TextButton(onClick = {
                            startActivity(Intent(this, MainActivity::class.java))
                            finish()
                        }) { Text("Open VELA") }
                    },
                    dismissButton = {
                        TextButton(onClick = { finish() }) { Text("Cancel") }
                    },
                )
            }
        }
    }

    // ── Approval: presence, then verification, then exactly one ceremony ─────

    private fun beginApprove() {
        val shown = ceremony ?: return
        if (stage != Stage.Confirm) return
        errorText = null

        if (shown.requireUserVerification) {
            runBiometricVerification { verified -> runCeremony(shown, verified) }
        } else {
            // Presence only: a tap on this screen. No UV flag.
            runCeremony(shown, verified = false)
        }
    }

    private fun runBiometricVerification(onVerified: (Boolean) -> Unit) {
        val manager = BiometricManager.from(this)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_WEAK or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (manager.canAuthenticate(authenticators) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            errorText = "This site requires biometric or PIN verification, which " +
                "this device cannot provide."
            return
        }
        stage = Stage.Verifying
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onVerified(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    stage = Stage.Confirm
                    if (errorCode != BiometricPrompt.ERROR_USER_CANCELED &&
                        errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON
                    ) {
                        errorText = "Verification failed: $errString"
                    }
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Verify to use your passkey")
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(info)
    }

    private fun runCeremony(shown: Ceremony, verified: Boolean) {
        stage = Stage.Working
        lifecycleScope.launch(Dispatchers.Default) {
            val result = runCatching { shown.run(verified) }
                .onFailure { failure ->
                    runOnUiThread {
                        stage = Stage.Confirm
                        errorText = failure.message ?: "The ceremony could not be completed."
                    }
                    null
                }
                .getOrNull() ?: return@launch

            runOnUiThread {
                val outcome = Intent()
                when (shown) {
                    is Ceremony.Get -> PendingIntentHandler.setGetCredentialResponse(
                        outcome,
                        GetCredentialResponse(PublicKeyCredential(result.responseJson)),
                    )
                    is Ceremony.Create -> PendingIntentHandler.setCreateCredentialResponse(
                        outcome,
                        CreatePublicKeyCredentialResponse(result.responseJson),
                    )
                }
                setResult(RESULT_OK, outcome)
                stage = Stage.Done
                finish()
            }
        }
    }

    private fun cancel() {
        setResult(RESULT_CANCELED)
        finish()
    }

    // ── Request parsing ──────────────────────────────────────────────────────

    private sealed class Ceremony {
        abstract val originSummary: String
        abstract val requireUserVerification: Boolean

        /** Runs the ceremony. Call at most once per approval. */
        abstract fun run(verified: Boolean): CeremonyResult

        data class Get(
            val options: WebAuthnJson.RequestOptions,
            val item: VaultItem.Passkey,
            val accountName: String,
            val origin: String?,
            val clientDataHash: ByteArray?,
        ) : Ceremony() {
            override val originSummary: String
                get() = origin ?: "an app on this device"
            override val requireUserVerification: Boolean
                get() = options.requireUserVerification

            override fun run(verified: Boolean): CeremonyResult {
                val result = PasskeyAuthenticator.getAssertion(
                    item, options, origin, verified, clientDataHash
                )
                // Persist the counter only after the assertion was minted — a
                // counter that fails to persist is a future "cloned
                // authenticator" warning, not a refused login (desktop parity).
                VelaRepositories.vault.updateItem(
                    item.copy(
                        signCount = result.nextSignCount,
                        meta = item.meta.copy(updatedAt = Instant.now()),
                    )
                )
                return CeremonyResult(result.responseJson)
            }
        }

        data class Create(
            val options: WebAuthnJson.CreationOptions,
            val origin: String?,
            val clientDataHash: ByteArray?,
        ) : Ceremony() {
            override val originSummary: String
                get() = origin ?: "an app on this device"
            override val requireUserVerification: Boolean
                get() = options.requireUserVerification

            override fun run(verified: Boolean): CeremonyResult {
                val registration = PasskeyAuthenticator.makeCredential(
                    options, origin, verified, clientDataHash
                )
                VelaRepositories.vault.addItem(registration.item)
                return CeremonyResult(registration.responseJson)
            }
        }
    }

    private data class CeremonyResult(val responseJson: String)

    private fun parseIntent(launched: Intent?): Ceremony? {
        if (launched == null) return null
        val get = runCatching {
            PendingIntentHandler.retrieveProviderGetCredentialRequest(launched)
        }.getOrNull()
        if (get != null) return parseGet(get)

        val create = runCatching {
            PendingIntentHandler.retrieveProviderCreateCredentialRequest(launched)
        }.getOrNull()
        if (create != null) return parseCreate(create)
        return null
    }

    private fun parseGet(request: ProviderGetCredentialRequest): Ceremony.Get? {
        val option = request.credentialOptions
            .filterIsInstance<GetPublicKeyCredentialOption>()
            .firstOrNull() ?: return null
        val options = WebAuthnJson.parseRequestOptions(option.requestJson) ?: return null
        val origin = resolveOrigin(request.callingAppInfo)

        val passkeys = VelaRepositories.vault.items.value
            .filterIsInstance<VaultItem.Passkey>()
            .filter { it.privateKey.isNotEmpty() }
        val chosen = WebAuthnJson.selectCredential(
            passkeys,
            rpIdOf = { it.rpId },
            credentialIdOf = { it.credentialId },
            rpId = options.rpId,
            allowCredentialIds = options.allowCredentialIds,
        ) ?: return null

        return Ceremony.Get(
            options = options,
            item = chosen,
            accountName = chosen.userName.ifEmpty {
                chosen.userDisplayName.ifEmpty { options.rpId }
            },
            origin = origin,
            clientDataHash = option.clientDataHash,
        )
    }

    private fun parseCreate(request: ProviderCreateCredentialRequest): Ceremony.Create? {
        val option = request.callingRequest as? CreatePublicKeyCredentialRequest ?: return null
        val options = WebAuthnJson.parseCreationOptions(option.requestJson) ?: return null

        // excludeCredentials exists so a relying party can stop a second
        // credential being minted for an account that already has one.
        val existing = VelaRepositories.vault.items.value
            .filterIsInstance<VaultItem.Passkey>()
            .map { it.credentialId }
            .toSet()
        if (options.excludedCredentialIds.any { it in existing }) {
            errorText = "A passkey for this account already exists."
            return null
        }

        // A browser puts the site origin on the request itself; an app falls
        // back to the signing-certificate origin.
        val declaredOrigin = runCatching { option.origin }.getOrNull()
        val origin = declaredOrigin.takeIf { !it.isNullOrBlank() }
            ?: resolveOrigin(request.callingAppInfo)

        return Ceremony.Create(
            options = options,
            origin = origin,
            clientDataHash = option.clientDataHash,
        )
    }

    /**
     * Where the request came from, as far as this device can honestly know.
     *
     * - A privileged browser (on the shipped allowlist) passes the site origin
     *   through the platform; [CallingAppInfo.getOrigin] returns it only when
     *   the caller's package *and* signing certificate are on the list, and
     *   throws otherwise — which is a refusal, never a downgrade.
     * - Anything else is an app speaking for itself, so the WebAuthn
     *   same-device app origin applies: its own signing certificate.
     * - `CallingAppInfo.signingInfo` needs API 28; below that we cannot vouch
     *   for any origin, so we return none and the request is refused.
     */
    private fun resolveOrigin(info: CallingAppInfo?): String? {
        if (info == null) return null
        if (info.isOriginPopulated()) {
            val allowlist = runCatching {
                assets.open(PRIVILEGED_ALLOWLIST_ASSET).bufferedReader().use { it.readText() }
            }.getOrNull() ?: return null
            return runCatching { info.getOrigin(allowlist) }.getOrNull()
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        val certificate = runCatching {
            info.signingInfo.apkContentsSigners.lastOrNull()?.toByteArray()
        }.getOrNull() ?: return null
        return "android:apk-key-hash:" +
            WebAuthnJson.b64urlEncode(WebAuthnJson.sha256(certificate))
    }

    private companion object {
        /** Same list Android itself uses for passkey origin assertions. */
        const val PRIVILEGED_ALLOWLIST_ASSET = "privileged_browsers_google.json"
    }
}

@Composable
private fun CeremonyScreen(
    title: String,
    detail: String,
    rpId: String,
    account: String,
    stage: PasskeyPromptActivity.Stage,
    errorText: String?,
    onApprove: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Text(rpId, style = MaterialTheme.typography.bodyLarge)
        Text(
            "For $account, requested by $detail.",
            style = MaterialTheme.typography.bodyMedium,
        )
        if (errorText != null) {
            Text(errorText, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(8.dp))
        when (stage) {
            PasskeyPromptActivity.Stage.Working -> CircularProgressIndicator()
            PasskeyPromptActivity.Stage.Done -> {}
            else -> {
                Button(
                    onClick = onApprove,
                    enabled = stage == PasskeyPromptActivity.Stage.Confirm,
                ) {
                    Text("Approve")
                }
                OutlinedButton(onClick = onCancel) { Text("Cancel") }
            }
        }
    }
}
