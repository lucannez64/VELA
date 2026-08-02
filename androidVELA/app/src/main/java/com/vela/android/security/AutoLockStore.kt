package com.vela.android.security

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * How long the vault may sit backgrounded before it's auto-locked. Not
 * secret, so it lives in plain SharedPreferences (same as the other
 * non-sensitive counters in this app, e.g. the audit log / sent-share
 * manifest prefs).
 */
class AutoLockStore(context: Context) {
    private val prefs = context.getSharedPreferences("vela_autolock", Context.MODE_PRIVATE)

    private val _autoLockMinutes = MutableStateFlow(
        prefs.getInt(KEY_MINUTES, DEFAULT_MINUTES).coerceIn(MIN_MINUTES, MAX_MINUTES)
    )
    val autoLockMinutes: StateFlow<Int> = _autoLockMinutes

    fun setAutoLockMinutes(minutes: Int) {
        val clamped = minutes.coerceIn(MIN_MINUTES, MAX_MINUTES)
        prefs.edit().putInt(KEY_MINUTES, clamped).apply()
        _autoLockMinutes.value = clamped
    }

    private val _clipboardClearSeconds = MutableStateFlow(
        prefs.getInt(KEY_CLIPBOARD_SECONDS, SecureClipboard.DEFAULT_CLEAR_SECONDS)
            .coerceIn(SecureClipboard.MIN_CLEAR_SECONDS, SecureClipboard.MAX_CLEAR_SECONDS)
    )
    val clipboardClearSeconds: StateFlow<Int> = _clipboardClearSeconds

    init {
        // Apply the stored value immediately: a copy can happen before any
        // screen that would set it has been opened.
        SecureClipboard.clearDelaySeconds = _clipboardClearSeconds.value
    }

    fun setClipboardClearSeconds(seconds: Int) {
        val clamped = seconds.coerceIn(
            SecureClipboard.MIN_CLEAR_SECONDS,
            SecureClipboard.MAX_CLEAR_SECONDS,
        )
        prefs.edit().putInt(KEY_CLIPBOARD_SECONDS, clamped).apply()
        _clipboardClearSeconds.value = clamped
        SecureClipboard.clearDelaySeconds = clamped
    }

    companion object {
        private const val KEY_MINUTES = "auto_lock_minutes"
        private const val KEY_CLIPBOARD_SECONDS = "clipboard_clear_seconds"
        const val DEFAULT_MINUTES = 5
        const val MIN_MINUTES = 1
        const val MAX_MINUTES = 1440
    }
}
