package com.vela.android.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Copies a sensitive value (password, CVV, PIN, TOTP code, ...) to the system
 * clipboard, marks it EXTRA_IS_SENSITIVE so the OS doesn't preview it, and
 * clears it again after [CLEAR_DELAY_MS] so it doesn't sit there indefinitely
 * for any other app to read.
 */
object SecureClipboard {
    private const val CLEAR_DELAY_MS = 30_000L

    // Bumped on every copy so a stale delayed-clear from a previous copy
    // never wipes out a clip the user copied after it.
    private var generation = 0

    fun copy(context: Context, scope: CoroutineScope, label: String, value: String) {
        val clipboardManager =
            context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, value)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboardManager.setPrimaryClip(clip)

        val myGeneration = ++generation
        scope.launch {
            delay(CLEAR_DELAY_MS)
            if (myGeneration == generation) {
                clearIfStillOurs(clipboardManager, value)
            }
        }
    }

    private fun clearIfStillOurs(clipboardManager: ClipboardManager, value: String) {
        val current = clipboardManager.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text
        if (current?.toString() != value) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboardManager.clearPrimaryClip()
        } else {
            @Suppress("DEPRECATION")
            clipboardManager.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}
