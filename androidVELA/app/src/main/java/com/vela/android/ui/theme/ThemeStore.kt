package com.vela.android.ui.theme

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Persists the user's theme choice. Not secret, so it lives in plain
 * SharedPreferences like [com.vela.android.security.AutoLockStore]. The
 * stored value is a [VelaThemeId] (or "system"); defaults to "system" so the
 * app follows the OS light/dark preference until the user overrides it —
 * matching the desktop app's behaviour.
 */
class ThemeStore(context: Context) {
    private val prefs = context.getSharedPreferences("vela_theme", Context.MODE_PRIVATE)

    private val _theme = MutableStateFlow(prefs.getString(KEY_THEME, VelaThemes.SYSTEM) ?: VelaThemes.SYSTEM)
    val theme: StateFlow<String> = _theme

    fun setTheme(themeId: String) {
        prefs.edit().putString(KEY_THEME, themeId).apply()
        _theme.value = themeId
    }

    companion object {
        private const val KEY_THEME = "theme_id"
    }
}
