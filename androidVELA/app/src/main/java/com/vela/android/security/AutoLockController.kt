package com.vela.android.security

import android.content.Context
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.vela.android.core.VelaRepositories

/**
 * Locks the vault if it was left unlocked and backgrounded (app switched
 * away from / device asleep) for longer than [AutoLockStore.autoLockMinutes].
 * Registered on [androidx.lifecycle.ProcessLifecycleOwner] so it reflects the
 * whole app's foreground state rather than any single Activity's — the app
 * has more than one Activity (QR capture, and Autofill can relaunch
 * MainActivity in a new task), so per-Activity onStop/onStart would treat
 * switching between them as "backgrounded".
 *
 * The foreground-return check alone is lazy: while the app sits backgrounded
 * past the deadline, the unlocked RMS and decrypted items stay in live memory
 * until the user happens to return. [AutoLockReceiver] enforces the same
 * deadline from outside — scheduled here in `onStop`, cancelled in `onStart` —
 * so backgrounding itself eventually locks.
 */
internal class AutoLockController(
    private val appContext: Context,
    private val vaultManager: SecureVaultManager,
    private val autoLockStore: AutoLockStore
) : DefaultLifecycleObserver {
    private var backgroundedAtElapsedMs: Long? = null

    override fun onStop(owner: LifecycleOwner) {
        backgroundedAtElapsedMs = if (vaultManager.session.value.unlocked) {
            AutoLockReceiver.schedule(
                appContext,
                autoLockStore.autoLockMinutes.value * 60_000L,
            )
            SystemClock.elapsedRealtime()
        } else {
            null
        }
    }

    override fun onStart(owner: LifecycleOwner) {
        // The deadline was met or the user returned in time; either way the
        // alarm's job is done.
        AutoLockReceiver.cancel(appContext)
        val backgroundedAt = backgroundedAtElapsedMs ?: return
        backgroundedAtElapsedMs = null
        if (!vaultManager.session.value.unlocked) return

        val elapsedMs = SystemClock.elapsedRealtime() - backgroundedAt
        val timeoutMs = autoLockStore.autoLockMinutes.value * 60_000L
        if (elapsedMs >= timeoutMs) {
            vaultManager.lock()
            VelaRepositories.vault.clearMemory()
            VelaRepositories.audit.record("vault_locked", "auto-lock timeout")
        }
    }
}
