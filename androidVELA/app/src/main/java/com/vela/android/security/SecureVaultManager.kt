package com.vela.android.security

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.security.SecureRandom
import javax.crypto.Cipher

class SecureVaultManager(context: Context) {
    private val storeDir = context.filesDir.resolve("security")
    private val vaultStore = EncryptedVaultStore(context.filesDir.resolve("vault"))
    private val biometricProtector = AndroidKeystoreRmsProtector(storeDir)
    private val passwordProtector = PasswordRmsProtector(storeDir)
    private val rms = RmsHolder()

    private val _session = MutableStateFlow(snapshot(null))
    val session: StateFlow<SecureSessionState> = _session

    // Notified on every lock() (manual or auto-lock), so the current Activity
    // can tear down Activity-scoped state (e.g. the background sync job) that
    // this manager has no reference to.
    var onLocked: (() -> Unit)? = null

    fun generateRms(): ByteArray = ByteArray(RMS_LEN).also { SecureRandom().nextBytes(it) }

    fun beginBiometricVaultCreation(): Cipher = biometricProtector.beginWrapCipher()

    fun finishBiometricVaultCreation(cipher: Cipher, generatedRms: ByteArray) {
        biometricProtector.finishWrap(cipher, generatedRms)
        unlockInMemory(generatedRms, UnlockProvider.Biometric)
    }

    fun beginBiometricUnlock(): Cipher = biometricProtector.beginUnwrapCipher()

    fun finishBiometricUnlock(cipher: Cipher) {
        unlockInMemory(biometricProtector.finishUnwrap(cipher), UnlockProvider.Biometric)
    }

    fun createPasswordVault(password: CharArray) {
        val generated = generateRms()
        try {
            passwordProtector.wrap(generated, password)
            unlockInMemory(generated, UnlockProvider.Password)
        } finally {
            generated.fill(0)
        }
    }

    /// Adopt an RMS recovered during enrollment. The vault is usable
    /// immediately (unlocked = true) but `provider = null` intentionally:
    /// the imported RMS has no local biometric/password protection configured
    /// yet — that happens next via `onProtectEnrolledBiometric`/
    /// `onProtectEnrolledPassword`. Not currently read by any caller, but if
    /// UI ever branches on `session.provider`, treat null-while-unlocked as
    /// "protect this device now", not as a bug.
    fun adoptRms(importedRms: ByteArray) {
        rms.replaceAndWipeInput(importedRms)
        _session.value = snapshot(null).copy(unlocked = true, provider = null)
    }

    fun createPasswordVaultFromRms(existingRms: ByteArray, password: CharArray) {
        try {
            passwordProtector.wrap(existingRms, password)
            unlockInMemory(existingRms, UnlockProvider.Password)
        } finally {
            existingRms.fill(0)
        }
    }

    fun unlockWithPassword(password: CharArray) {
        unlockInMemory(passwordProtector.unwrap(password), UnlockProvider.Password)
    }

    fun lock() {
        rms.clear()
        _session.value = snapshot(null)
        onLocked?.invoke()
    }

    fun resetLocalSecurity() {
        lock()
        biometricProtector.delete()
        passwordProtector.delete()
        vaultStore.delete()
        _session.value = snapshot(null)
    }

    fun setError(message: String?) {
        _session.update { current -> snapshot(current.provider).copy(error = message) }
    }

    fun currentRmsCopy(): ByteArray? = rms.copy()

    private fun unlockInMemory(unwrappedRms: ByteArray, provider: UnlockProvider) {
        rms.replaceAndWipeInput(unwrappedRms)
        _session.value = snapshot(provider).copy(unlocked = true, provider = provider, error = null)
    }

    private fun snapshot(provider: UnlockProvider?): SecureSessionState {
        val unlocked = rms.isUnlocked()
        return SecureSessionState(
            unlocked = unlocked,
            provider = if (!unlocked) null else provider,
            hasBiometricVault = runCatching { biometricProtector.hasWrappedRms() }.getOrDefault(false),
            hasPasswordVault = passwordProtector.hasWrappedRms(),
            error = null
        )
    }

    companion object {
        private const val RMS_LEN = 32
    }
}
