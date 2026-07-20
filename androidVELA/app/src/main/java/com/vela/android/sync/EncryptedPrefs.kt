package com.vela.android.sync

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Opens a Keystore-backed EncryptedSharedPreferences file, migrating any data
 * from the legacy plaintext SharedPreferences file of the same base name (if
 * present) into it, then wiping the plaintext copy so the previously-stored
 * secret (server signing key, bearer token, ...) no longer sits in cleartext
 * on disk after the first run on an upgraded install.
 */
internal object EncryptedPrefs {
    fun open(context: Context, baseName: String): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val encrypted = EncryptedSharedPreferences.create(
            context,
            "${baseName}_enc",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        migrateLegacyPlaintext(context, baseName, encrypted)
        return encrypted
    }

    private fun migrateLegacyPlaintext(context: Context, baseName: String, encrypted: SharedPreferences) {
        val legacy = context.getSharedPreferences(baseName, Context.MODE_PRIVATE)
        val legacyEntries = legacy.all
        if (legacyEntries.isEmpty()) return

        val editor = encrypted.edit()
        for ((key, value) in legacyEntries) {
            when (value) {
                is String -> editor.putString(key, value)
                is Boolean -> editor.putBoolean(key, value)
                is Int -> editor.putInt(key, value)
                is Long -> editor.putLong(key, value)
                is Float -> editor.putFloat(key, value)
                is Set<*> -> {
                    @Suppress("UNCHECKED_CAST")
                    editor.putStringSet(key, value as Set<String>)
                }
            }
        }
        editor.apply()
        legacy.edit().clear().apply()
    }
}
