package com.vela.android.security

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import com.vela.android.core.VelaRepositories

/**
 * Fires the auto-lock deadline without waiting for the app to come back to the
 * foreground.
 *
 * [AutoLockController] only evaluates the deadline in `onStart`, so an unlocked
 * vault that sat backgrounded past its timeout stayed in memory — RMS, decrypted
 * items, clipboard secret and all — for as long as the user stayed away (the
 * Android analogue of desktop audit D-1). The alarm closes that gap: it is set
 * when the app backgrounds and cancelled on return, and fires even if the
 * process is cached or the device is dozing.
 *
 * `setAndAllowWhileIdle` is deliberately inexact: under Doze it may slip by a
 * few minutes, which is an acceptable cost for not requiring the
 * SCHEDULE_EXACT_ALARM permission. A late firing is harmless — the receiver
 * re-checks every precondition before locking.
 */
class AutoLockReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // VelaRepositories.init may not have run (early broadcast).
        if (!VelaRepositories::security.isInitialized || !VelaRepositories::vault.isInitialized) return
        // The user came back before the alarm fired: the lifecycle observer owns
        // the decision then, and locking under their fingers would be wrong.
        if (ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
        val security = VelaRepositories.security
        if (!security.session.value.unlocked) return

        security.lock()
        VelaRepositories.vault.clearMemory()
        VelaRepositories.audit.record("vault_locked", "auto-lock timeout")
    }

    companion object {
        private const val REQUEST_CODE = 4_100_1

        /** The existing alarm's PendingIntent, or null when none is scheduled. */
        private fun scheduledIntent(context: Context): PendingIntent? =
            PendingIntent.getBroadcast(
                context,
                REQUEST_CODE,
                Intent(context, AutoLockReceiver::class.java),
                PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE,
            )

        private fun freshIntent(context: Context): PendingIntent =
            PendingIntent.getBroadcast(
                context,
                REQUEST_CODE,
                Intent(context, AutoLockReceiver::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

        fun schedule(context: Context, delayMs: Long) {
            val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            manager.setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + delayMs,
                scheduledIntent(context) ?: freshIntent(context),
            )
        }

        fun cancel(context: Context) {
            scheduledIntent(context)?.let { pi ->
                val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
                manager.cancel(pi)
                pi.cancel()
            }
        }
    }
}
