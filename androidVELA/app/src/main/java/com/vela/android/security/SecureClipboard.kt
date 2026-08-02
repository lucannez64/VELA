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
 * clears it again after [clearDelayMillis] so it doesn't sit there indefinitely
 * for any other app to read.
 *
 * The clipboard is the largest live-secret surface on Android: while a password
 * sits there, every app with focus can read it, and on older releases the OS
 * itself previews it. Thirty seconds was the industry default and is longer than
 * pasting takes; fifteen is still comfortably enough and halves the window. It
 * is a setting because "long enough to paste" genuinely differs — someone typing
 * a code into a hardware terminal needs longer than someone pasting into the
 * next field.
 */
object SecureClipboard {
    /** Seconds the copied value may live. Bounds, not preferences: below the
     *  minimum the feature stops working, above the maximum it stops being a
     *  clearing clipboard. */
    const val MIN_CLEAR_SECONDS = 5
    const val MAX_CLEAR_SECONDS = 120
    const val DEFAULT_CLEAR_SECONDS = 15

    /// Set at startup from the user's setting; the default applies until then.
    @Volatile
    var clearDelaySeconds: Int = DEFAULT_CLEAR_SECONDS
        set(value) {
            field = value.coerceIn(MIN_CLEAR_SECONDS, MAX_CLEAR_SECONDS)
        }

    private val clearDelayMillis: Long get() = clearDelaySeconds * 1000L

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
            delay(clearDelayMillis)
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
