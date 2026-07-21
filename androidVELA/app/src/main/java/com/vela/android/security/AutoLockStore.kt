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

    companion object {
        private const val KEY_MINUTES = "auto_lock_minutes"
        const val DEFAULT_MINUTES = 5
        const val MIN_MINUTES = 1
        const val MAX_MINUTES = 1440
    }
}
