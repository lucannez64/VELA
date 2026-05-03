package com.vela.android

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.vela.android.core.VelaRepositories
import com.vela.android.core.SharedCore
import com.vela.android.ui.navigation.VelaNavHost
import com.vela.android.ui.theme.VelaTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.Arrays
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {
    private var pendingCreateRms: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            VelaTheme {
                val items by VelaRepositories.vault.items.collectAsState()
                val secureSession by VelaRepositories.security.session.collectAsState()
                val syncSettings by VelaRepositories.syncSettings.settings.collectAsState()
                val syncState by VelaRepositories.sync.state.collectAsState()
                val coreStatus = SharedCore.status()

                val isUnlocked = secureSession.unlocked

                VelaNavHost(
                    isUnlocked = isUnlocked,
                    hasBiometricVault = secureSession.hasBiometricVault,
                    hasPasswordVault = secureSession.hasPasswordVault,
                    itemCount = items.size,
                    items = items,
                    onAddItem = { item ->
                        VelaRepositories.vault.addItem(item)
                        VelaRepositories.audit.record("item_added", item.type.name.lowercase())
                    },
                    onUpdateItem = { item ->
                        VelaRepositories.vault.updateItem(item)
                        VelaRepositories.audit.record("item_updated", item.type.name.lowercase())
                    },
                    onDeleteItem = { id ->
                        VelaRepositories.vault.deleteItem(id)
                        VelaRepositories.audit.record("item_deleted", id.take(8))
                    },
                    onLock = {
                        VelaRepositories.audit.record("vault_locked")
                        VelaRepositories.security.lock()
                        VelaRepositories.vault.clearMemory()
                    },
                    onReset = {
                        VelaRepositories.security.resetLocalSecurity()
                        VelaRepositories.vault.clearMemory()
                    },
                    onCreateBiometricVault = ::createBiometricVault,
                    onUnlockBiometric = ::unlockBiometricVault,
                    onCreatePasswordVault = { password ->
                        runCatching {
                            VelaRepositories.security.createPasswordVault(password.toCharArray())
                            VelaRepositories.vault.loadFromUnlockedSession()
                        }.onFailure { VelaRepositories.security.setError(it.message ?: "Password vault creation failed") }
                    },
                    onUnlockPassword = { password ->
                        runCatching {
                            VelaRepositories.security.unlockWithPassword(password.toCharArray())
                            VelaRepositories.vault.loadFromUnlockedSession()
                        }.onFailure { VelaRepositories.security.setError("Invalid password or corrupted vault") }
                    },
                    onOpenAutofillSettings = {
                        // Primary: system dialog to pick autofill service for this package
                        val primary = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
                            data = Uri.parse("package:$packageName")
                        }
                        if (primary.resolveActivity(packageManager) != null) {
                            startActivity(primary)
                        } else {
                            // Secondary: try stock Android autofill settings page
                            val secondary = Intent(Settings.ACTION_SETTINGS).apply {
                                setClassName("com.android.settings", "com.android.settings.Settings\$AutofillPickerActivity")
                                putExtra("package_name", packageName)
                            }
                            val resolved = runCatching {
                                if (secondary.resolveActivity(packageManager) != null) {
                                    startActivity(secondary)
                                    true
                                } else false
                            }.getOrDefault(false)

                            if (!resolved) {
                                // Fallback: general settings so user can search for autofill
                                val fallback = Intent(Settings.ACTION_SETTINGS)
                                if (fallback.resolveActivity(packageManager) != null) {
                                    startActivity(fallback)
                                }
                            }
                        }
                    },
                    onSyncNow = {
                        CoroutineScope(Dispatchers.IO).launch {
                            VelaRepositories.sync.syncNow()
                            VelaRepositories.audit.record("vault_sync")
                        }
                    },
                    onResolveConflictUseLocal = {
                        CoroutineScope(Dispatchers.IO).launch {
                            VelaRepositories.sync.resolveConflictUseLocal()
                            VelaRepositories.audit.record("sync_conflict_resolved", "kept Android vault")
                        }
                    },
                    onResolveConflictUseRemote = {
                        CoroutineScope(Dispatchers.IO).launch {
                            VelaRepositories.sync.resolveConflictUseRemote()
                            VelaRepositories.audit.record("sync_conflict_resolved", "used server vault")
                        }
                    },
                    onUpdateSyncServer = { serverUrl, token ->
                        VelaRepositories.sync.updateServer(serverUrl, token)
                    },
                    onNavigateToEnroll = {},
                    onEnrollDevice = { serverUrl, enrollmentCode ->
                        val rms = VelaRepositories.sync.enrollWithCode(serverUrl, enrollmentCode)
                        VelaRepositories.security.adoptRms(rms)
                        VelaRepositories.sync.syncNow()
                    },
                    onProtectEnrolledBiometric = ::protectEnrolledBiometric,
                    onProtectEnrolledPassword = ::protectEnrolledPassword,
                    serverUrl = syncSettings.serverUrl,
                    syncState = syncState,
                    userId = VelaRepositories.serverIdentity.load()?.userId
                )
            }
        }
    }

    companion object {
        const val EXTRA_AUTOFILL_UNLOCK = "com.vela.android.extra.AUTOFILL_UNLOCK"
    }

    private fun createBiometricVault() {
        val rms = VelaRepositories.security.generateRms()
        val cipher = runCatching { VelaRepositories.security.beginBiometricVaultCreation() }
            .onFailure {
                rms.fill(0)
                VelaRepositories.security.setError(it.message ?: "Biometric vault creation failed")
            }
            .getOrNull() ?: return

        pendingCreateRms?.fill(0)
        pendingCreateRms = rms
        promptBiometric(
            title = "Create VELA vault",
            subtitle = "Authenticate to protect the vault key with Android Keystore",
            cipher = cipher,
            onCipher = { authenticatedCipher ->
                val generated = pendingCreateRms ?: return@promptBiometric
                try {
                    VelaRepositories.security.finishBiometricVaultCreation(authenticatedCipher, generated)
                    VelaRepositories.vault.loadFromUnlockedSession()
                } finally {
                    generated.fill(0)
                    pendingCreateRms = null
                }
            }
        )
    }

    private fun unlockBiometricVault() {
        val cipher = runCatching { VelaRepositories.security.beginBiometricUnlock() }
            .onFailure { VelaRepositories.security.setError(it.message ?: "Biometric unlock failed") }
            .getOrNull() ?: return

        promptBiometric(
            title = "Unlock VELA",
            subtitle = "Authenticate to unlock the local vault key",
            cipher = cipher,
            onCipher = { authenticatedCipher ->
                runCatching {
                    VelaRepositories.security.finishBiometricUnlock(authenticatedCipher)
                    VelaRepositories.vault.loadFromUnlockedSession()
                }.onFailure { VelaRepositories.security.setError(it.message ?: "Biometric unlock failed") }
            }
        )
    }

    private fun protectEnrolledBiometric() {
        val cipher = runCatching { VelaRepositories.security.beginBiometricVaultCreation() }
            .onFailure { VelaRepositories.security.setError(it.message ?: "Biometric protection failed") }
            .getOrNull() ?: return

        promptBiometric(
            title = "Secure VELA vault",
            subtitle = "Authenticate to protect the vault on this device",
            cipher = cipher,
            onCipher = { authenticatedCipher ->
                val rmsCopy = VelaRepositories.security.currentRmsCopy() ?: return@promptBiometric
                try {
                    VelaRepositories.security.finishBiometricVaultCreation(authenticatedCipher, rmsCopy)
                    VelaRepositories.vault.loadFromUnlockedSession()
                } finally {
                    rmsCopy.fill(0)
                }
            }
        )
    }

    private fun protectEnrolledPassword(password: String) {
        val rmsCopy = VelaRepositories.security.currentRmsCopy() ?: return
        try {
            VelaRepositories.security.createPasswordVaultFromRms(rmsCopy, password.toCharArray())
            VelaRepositories.vault.loadFromUnlockedSession()
        } finally {
            rmsCopy.fill(0)
        }
    }

    private fun promptBiometric(
        title: String,
        subtitle: String,
        cipher: Cipher,
        onCipher: (Cipher) -> Unit
    ) {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    pendingCreateRms?.let {
                        Arrays.fill(it, 0)
                        pendingCreateRms = null
                    }
                    VelaRepositories.security.setError(errString.toString())
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if (authenticatedCipher == null) {
                        VelaRepositories.security.setError("Biometric prompt did not return a cipher")
                        return
                    }
                    onCipher(authenticatedCipher)
                }

                override fun onAuthenticationFailed() {
                    VelaRepositories.security.setError("Biometric authentication failed")
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }
}
