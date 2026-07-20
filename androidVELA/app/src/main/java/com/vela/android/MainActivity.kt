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
import androidx.lifecycle.lifecycleScope
import com.vela.android.core.VelaRepositories
import com.vela.android.core.SharedCore
import com.vela.android.ui.navigation.VelaNavHost
import com.vela.android.ui.theme.VelaTheme
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.Arrays
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {
    private var pendingCreateRms: ByteArray? = null
    private var backgroundSyncJob: Job? = null
    private var onQrScanResult: ((String?) -> Unit)? = null

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
                        cancelBackgroundSync()
                    },
                    onReset = {
                        VelaRepositories.security.resetLocalSecurity()
                        VelaRepositories.vault.clearMemory()
                        cancelBackgroundSync()
                    },
                    onCreateBiometricVault = ::createBiometricVault,
                    onUnlockBiometric = ::unlockBiometricVault,
                    onCreatePasswordVault = { password ->
                        runCatching {
                            VelaRepositories.security.createPasswordVault(password.toCharArray())
                            VelaRepositories.vault.loadFromUnlockedSession()
                            startBackgroundSync()
                        }.onFailure { VelaRepositories.security.setError(it.message ?: "Password vault creation failed") }
                    },
                    onUnlockPassword = { password ->
                        runCatching {
                            VelaRepositories.security.unlockWithPassword(password.toCharArray())
                            VelaRepositories.vault.loadFromUnlockedSession()
                            onVaultUnlocked()
                        }.onFailure { VelaRepositories.security.setError("Invalid password or corrupted vault") }
                    },
                    onOpenAutofillSettings = {
                        val primary = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
                            data = Uri.parse("package:$packageName")
                        }
                        if (primary.resolveActivity(packageManager) != null) {
                            startActivity(primary)
                        } else {
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
                                val fallback = Intent(Settings.ACTION_SETTINGS)
                                if (fallback.resolveActivity(packageManager) != null) {
                                    startActivity(fallback)
                                }
                            }
                        }
                    },
                    onSyncNow = {
                        // lifecycleScope (not a bare CoroutineScope): ties this
                        // coroutine to the Activity so it's cancelled instead of
                        // running detached if the user navigates away mid-sync.
                        lifecycleScope.launch(Dispatchers.IO) {
                            VelaRepositories.sync.syncNow()
                            VelaRepositories.audit.record("vault_sync")
                        }
                    },
                    onResolveConflictUseLocal = {
                        lifecycleScope.launch(Dispatchers.IO) {
                            VelaRepositories.sync.resolveConflictUseLocal()
                            VelaRepositories.audit.record("sync_conflict_resolved", "kept Android vault")
                        }
                    },
                    onResolveConflictUseRemote = {
                        lifecycleScope.launch(Dispatchers.IO) {
                            VelaRepositories.sync.resolveConflictUseRemote()
                            VelaRepositories.audit.record("sync_conflict_resolved", "used server vault")
                        }
                    },
                    onUpdateSyncServer = { serverUrl, token ->
                        VelaRepositories.sync.updateServer(serverUrl, token)
                    },
                    onUpdateSyncPreferences = { syncOnStartup, backgroundSyncMinutes ->
                        VelaRepositories.syncSettings.updateSyncPreferences(syncOnStartup, backgroundSyncMinutes)
                        restartBackgroundSync()
                    },
                    onNavigateToEnroll = {},
                    onEnrollDevice = { serverUrl, enrollmentCode ->
                        // Was invoked directly on the caller's (UI) thread —
                        // enrollWithCode does blocking network I/O, so this
                        // froze the UI for the duration of enrollment + sync.
                        lifecycleScope.launch(Dispatchers.IO) {
                            val rms = VelaRepositories.sync.enrollWithCode(serverUrl, enrollmentCode)
                            VelaRepositories.security.adoptRms(rms)
                            VelaRepositories.sync.syncNow()
                            startBackgroundSync()
                        }
                    },
                    onProtectEnrolledBiometric = ::protectEnrolledBiometric,
                    onProtectEnrolledPassword = ::protectEnrolledPassword,
                    serverUrl = syncSettings.serverUrl,
                    syncSettings = syncSettings,
                    syncState = syncState,
                    userId = VelaRepositories.serverIdentity.load()?.userId
                )
            }
        }
    }

    private fun onVaultUnlocked() {
        val syncSettings = VelaRepositories.syncSettings.settings.value
        if (syncSettings.syncOnStartup && syncSettings.serverUrl.isNotBlank()) {
            lifecycleScope.launch(Dispatchers.IO) {
                VelaRepositories.sync.syncNow()
                VelaRepositories.audit.record("vault_sync", "sync on startup")
            }
        }
        startBackgroundSync()
    }

    private fun startBackgroundSync() {
        cancelBackgroundSync()
        val syncSettings = VelaRepositories.syncSettings.settings.value
        val intervalMinutes = syncSettings.backgroundSyncMinutes
        if (intervalMinutes <= 0) return
        backgroundSyncJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                delay(intervalMinutes * 60 * 1000L)
                val currentSettings = VelaRepositories.syncSettings.settings.value
                if (currentSettings.serverUrl.isNotBlank() &&
                    VelaRepositories.security.session.value.unlocked
                ) {
                    VelaRepositories.sync.syncNow()
                }
            }
        }
    }

    private fun restartBackgroundSync() {
        if (VelaRepositories.security.session.value.unlocked) {
            startBackgroundSync()
        }
    }

    private fun cancelBackgroundSync() {
        backgroundSyncJob?.cancel()
        backgroundSyncJob = null
    }

    override fun onDestroy() {
        cancelBackgroundSync()
        super.onDestroy()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            onQrScanResult?.invoke(result.contents?.trim())
            onQrScanResult = null
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    companion object {
        const val EXTRA_AUTOFILL_UNLOCK = "com.vela.android.extra.AUTOFILL_UNLOCK"
    }

    fun launchQrScanner(prompt: String, onResult: (String?) -> Unit) {
        onQrScanResult = onResult
        IntentIntegrator(this).apply {
            setCaptureActivity(VelaCaptureActivity::class.java)
            setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
            setPrompt(prompt)
            setBeepEnabled(false)
            setOrientationLocked(false)
            initiateScan()
        }
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
                    // Was calling startBackgroundSync() directly, unlike every
                    // sibling unlock/protect flow — skipped the sync-on-startup
                    // check onVaultUnlocked() also does.
                    onVaultUnlocked()
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
                    onVaultUnlocked()
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
                    onVaultUnlocked()
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
            onVaultUnlocked()
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
