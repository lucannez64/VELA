package com.vela.android.sync

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

data class SyncSettings(
    val serverUrl: String = "",
    val bearerToken: String = "",
    val chunkId: String = "vault-data-000000",
    val localVersion: Long = 0,
    val lamportClock: Long = 0,
    val lastSyncedAt: String? = null,
    val hasLocalChanges: Boolean = false,
    val syncOnStartup: Boolean = true,
    val backgroundSyncMinutes: Int = 5
)

class SyncSettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("vela_sync", Context.MODE_PRIVATE)
    private val _settings = MutableStateFlow(read())
    val settings: StateFlow<SyncSettings> = _settings

    fun updateServer(serverUrl: String, bearerToken: String) {
        val updated = _settings.value.copy(
            serverUrl = normalizeServerUrl(serverUrl),
            bearerToken = bearerToken.trim()
        )
        write(updated)
    }

    fun updateMeta(localVersion: Long, lamportClock: Long, lastSyncedAt: String?, hasLocalChanges: Boolean = false) {
        write(
            _settings.value.copy(
                localVersion = localVersion,
                lamportClock = lamportClock,
                lastSyncedAt = lastSyncedAt,
                hasLocalChanges = hasLocalChanges
            )
        )
    }

    fun updateBearerToken(bearerToken: String) {
        write(_settings.value.copy(bearerToken = bearerToken.trim()))
    }

    fun markLocalChanged() {
        write(_settings.value.copy(hasLocalChanges = true))
    }

    fun updateSyncPreferences(syncOnStartup: Boolean, backgroundSyncMinutes: Int) {
        write(_settings.value.copy(syncOnStartup = syncOnStartup, backgroundSyncMinutes = backgroundSyncMinutes))
    }

    private fun read(): SyncSettings = SyncSettings(
        serverUrl = prefs.getString(KEY_SERVER_URL, "").orEmpty(),
        bearerToken = prefs.getString(KEY_BEARER_TOKEN, "").orEmpty(),
        chunkId = prefs.getString(KEY_CHUNK_ID, "vault-data-000000").orEmpty().ifBlank { "vault-data-000000" },
        localVersion = prefs.getLong(KEY_LOCAL_VERSION, 0),
        lamportClock = prefs.getLong(KEY_LAMPORT, 0),
        lastSyncedAt = prefs.getString(KEY_LAST_SYNCED, null),
        hasLocalChanges = prefs.getBoolean(KEY_HAS_LOCAL_CHANGES, false),
        syncOnStartup = prefs.getBoolean(KEY_SYNC_ON_STARTUP, true),
        backgroundSyncMinutes = prefs.getInt(KEY_BACKGROUND_SYNC_MINUTES, 5)
    )

    private fun write(settings: SyncSettings) {
        prefs.edit()
            .putString(KEY_SERVER_URL, settings.serverUrl)
            .putString(KEY_BEARER_TOKEN, settings.bearerToken)
            .putString(KEY_CHUNK_ID, settings.chunkId)
            .putLong(KEY_LOCAL_VERSION, settings.localVersion)
            .putLong(KEY_LAMPORT, settings.lamportClock)
            .putString(KEY_LAST_SYNCED, settings.lastSyncedAt)
            .putBoolean(KEY_HAS_LOCAL_CHANGES, settings.hasLocalChanges)
            .putBoolean(KEY_SYNC_ON_STARTUP, settings.syncOnStartup)
            .putInt(KEY_BACKGROUND_SYNC_MINUTES, settings.backgroundSyncMinutes)
            .apply()
        _settings.value = settings
    }

    private fun normalizeServerUrl(url: String): String {
        val trimmed = url.trim().trimEnd('/')
        if (trimmed.isEmpty()) return ""
        return if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) trimmed else "https://$trimmed"
    }

    companion object {
        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_BEARER_TOKEN = "bearer_token"
        private const val KEY_CHUNK_ID = "chunk_id"
        private const val KEY_LOCAL_VERSION = "local_version"
        private const val KEY_LAMPORT = "lamport"
        private const val KEY_LAST_SYNCED = "last_synced"
        private const val KEY_HAS_LOCAL_CHANGES = "has_local_changes"
        private const val KEY_SYNC_ON_STARTUP = "sync_on_startup"
        private const val KEY_BACKGROUND_SYNC_MINUTES = "background_sync_minutes"
    }
}
