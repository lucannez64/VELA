package com.vela.android.sync

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONObject

data class SyncSettings(
    val serverUrl: String = "",
    val bearerToken: String = "",
    val chunkId: String = "vault-data-000000",
    val localVersion: Long = 0,
    val lamportClock: Long = 0,
    val keyEpoch: Long = 1,
    val lastSyncedAt: String? = null,
    val hasLocalChanges: Boolean = false,
    val syncOnStartup: Boolean = true,
    val backgroundSyncMinutes: Int = 5,
    /**
     * Per-chunk admission baselines, namespaced by sync context
     * (`server ‖ account ‖ epoch`). Switching back to a context preserves its
     * own baseline, and adopting a new epoch starts a genuinely fresh one
     * instead of inheriting (or destroying) the old counter.
     */
    val seenLamportByContext: Map<String, Map<String, Long>> = emptyMap(),
    /** Whole-manifest rollback floor, namespaced the same way. */
    val manifestLamportByContext: Map<String, Long> = emptyMap(),
    /**
     * The persisted baseline could not be parsed. Sync must fail closed rather
     * than treat the unreadable file as "nothing recorded", which would drop
     * rollback protection for every chunk.
     */
    val baselineCorrupt: Boolean = false,
    /**
     * The original on-disk baseline strings. When [baselineCorrupt] is true they
     * are written back verbatim on unrelated updates (e.g. a token refresh), so
     * corruption can only be cleared by an explicit [SyncSettingsStore.clearBaselines]
     * and never silently turns into an empty, fail-open baseline.
     */
    val rawSeenBaselines: String? = null,
    val rawManifestBaselines: String? = null,
)

/**
 * One sync context: the normalized server, the authenticated account (if known)
 * and the account key epoch. A baseline only ever applies inside its own
 * context, so:
 *
 * - changing servers or signing into another account does not inherit a
 *   baseline from the previous one;
 * - switching back does not lose the baseline recorded before;
 * - adopting a rotated epoch restarts counters (the server's Lamports restart
 *   with the new RMS) without disarming the old epoch's record.
 *
 * A missing map entry is *first contact*, and that is deliberately explicit:
 * the bridge is told "no baseline" rather than being handed a zero.
 */
data class SyncBaselineScope(
    val serverUrl: String,
    val accountId: String,
    val keyEpoch: Long,
) {
    val key: String
        get() = listOf(serverUrl, accountId, keyEpoch.coerceAtLeast(0).toString())
            .joinToString(SEPARATOR)

    private companion object {
        const val SEPARATOR = "\u001f"
    }
}

internal fun syncBaselineScope(
    serverUrl: String,
    accountId: String?,
    keyEpoch: Long,
): SyncBaselineScope = SyncBaselineScope(
    serverUrl = normalizeSyncServerUrl(serverUrl),
    accountId = accountId?.trim().orEmpty(),
    keyEpoch = keyEpoch,
)

class SyncSettingsStore(context: Context) {
    // Holds the rotating server Bearer token and the rollback baselines, so it
    // must not sit in plaintext SharedPreferences.
    private val prefs = EncryptedPrefs.open(context, "vela_sync")

    // Every mutation, from whichever thread (UI, token renewal, sync), runs
    // through one serialized cell and commits synchronously. The published
    // `StateFlow` value is updated by [SyncSettingsState] while that same lock
    // is still held: see [SerializedSettings]. Publishing after releasing the
    // lock would let a slow T1 overwrite the flow with its older snapshot
    // after a newer T2 had already published, leaving memory behind disk.
    private val state = SyncSettingsState(read(), ::persist)
    val settings: StateFlow<SyncSettings> = state.settings

    fun updateServer(serverUrl: String, bearerToken: String) {
        update {
            it.copy(
                serverUrl = normalizeSyncServerUrl(serverUrl),
                bearerToken = bearerToken.trim(),
            )
        }
    }

    fun updateMeta(
        localVersion: Long,
        lamportClock: Long,
        lastSyncedAt: String?,
        hasLocalChanges: Boolean = false,
    ) {
        update {
            it.copy(
                localVersion = localVersion,
                lamportClock = lamportClock,
                lastSyncedAt = lastSyncedAt,
                hasLocalChanges = hasLocalChanges,
            )
        }
    }

    fun updateBearerToken(bearerToken: String) {
        update { it.copy(bearerToken = bearerToken.trim()) }
    }

    fun updateKeyEpoch(keyEpoch: Long) {
        require(keyEpoch >= 1) { "Vault key epoch must be positive" }
        update { it.copy(keyEpoch = keyEpoch) }
    }

    fun markLocalChanged() {
        update { it.copy(hasLocalChanges = true) }
    }

    fun updateSyncPreferences(syncOnStartup: Boolean, backgroundSyncMinutes: Int) {
        update {
            it.copy(
                syncOnStartup = syncOnStartup,
                backgroundSyncMinutes = backgroundSyncMinutes,
            )
        }
    }

    /**
     * This context's per-chunk baseline, or `null` on first contact. `null` and
     * an empty map are distinct: callers must pass "no baseline" to the native
     * gate explicitly instead of inventing clock 0.
     */
    fun baselineFor(scope: SyncBaselineScope): Map<String, Long>? =
        settings.value.seenLamportByContext[scope.key]

    /** This context's whole-manifest rollback floor, or `null` on first contact. */
    fun manifestBaselineFor(scope: SyncBaselineScope): Long? =
        settings.value.manifestLamportByContext[scope.key]

    /**
     * Advance the baselines of one context. Callers must invoke this only after
     * the downloaded/uploaded bytes were durably persisted; a failed or partial
     * batch must record nothing, or a retry would look like a rollback.
     *
     * Both maps are merged (max), never replaced, so a stale writer cannot lower
     * a baseline it did not observe.
     */
    fun recordAdmittedBaselines(
        scope: SyncBaselineScope,
        chunkClocks: Map<String, Long>,
        manifestClock: Long,
    ) {
        if (chunkClocks.isEmpty() && manifestClock <= 0) return
        update { current ->
            check(!current.baselineCorrupt) {
                "Refusing to overwrite an unreadable sync baseline"
            }
            val mergedChunks = mergeSeenLamports(
                current.seenLamportByContext[scope.key].orEmpty(),
                chunkClocks,
            )
            val mergedManifest = maxOf(
                current.manifestLamportByContext[scope.key] ?: 0,
                manifestClock,
            )
            current.copy(
                seenLamportByContext =
                    if (mergedChunks.isEmpty()) current.seenLamportByContext
                    else current.seenLamportByContext + (scope.key to mergedChunks),
                manifestLamportByContext =
                    if (mergedManifest <= 0) current.manifestLamportByContext
                    else current.manifestLamportByContext + (scope.key to mergedManifest),
            )
        }
    }

    /**
     * Deliberate context transition only: sign-out / local-security reset. This
     * is the recovery action the rollback error message points at — normal
     * server updates and epoch adoption must never call it.
     *
     * Today an install stores a single account, so clearing every context is
     * the same as clearing this account's contexts. If multi-account support
     * lands, this must become account-scoped: signing out one account must not
     * erase another account's rollback floors.
     */
    fun clearBaselines() {
        update {
            it.copy(
                seenLamportByContext = emptyMap(),
                manifestLamportByContext = emptyMap(),
                baselineCorrupt = false,
                rawSeenBaselines = null,
                rawManifestBaselines = null,
            )
        }
    }

    private fun update(transform: (SyncSettings) -> SyncSettings): SyncSettings =
        state.update(transform)

    private fun read(): SyncSettings {
        val rawSeen = prefs.getString(KEY_SEEN_LAMPORTS, null)
        val rawManifest = prefs.getString(KEY_MANIFEST_LAMPORTS, null)
        val seen = parseSeenLamportContexts(rawSeen)
        val manifest = parseManifestLamports(rawManifest)
        return SyncSettings(
            serverUrl = prefs.getString(KEY_SERVER_URL, "").orEmpty(),
            bearerToken = prefs.getString(KEY_BEARER_TOKEN, "").orEmpty(),
            chunkId = prefs.getString(KEY_CHUNK_ID, "vault-data-000000").orEmpty()
                .ifBlank { "vault-data-000000" },
            localVersion = prefs.getLong(KEY_LOCAL_VERSION, 0),
            lamportClock = prefs.getLong(KEY_LAMPORT, 0),
            keyEpoch = prefs.getLong(KEY_KEY_EPOCH, 1).coerceAtLeast(1),
            lastSyncedAt = prefs.getString(KEY_LAST_SYNCED, null),
            hasLocalChanges = prefs.getBoolean(KEY_HAS_LOCAL_CHANGES, false),
            syncOnStartup = prefs.getBoolean(KEY_SYNC_ON_STARTUP, true),
            backgroundSyncMinutes = prefs.getInt(KEY_BACKGROUND_SYNC_MINUTES, 5),
            seenLamportByContext = seen ?: emptyMap(),
            manifestLamportByContext = manifest ?: emptyMap(),
            baselineCorrupt = seen == null || manifest == null,
            rawSeenBaselines = rawSeen,
            rawManifestBaselines = rawManifest,
        )
    }

    /**
     * Write the whole snapshot synchronously. `commit` (not `apply`) matters:
     * the published `_settings.value` must never run ahead of what is on disk,
     * or a crash would restore a lower baseline than callers already acted on.
     */
    private fun persist(settings: SyncSettings): SyncSettings {
        // An unrelated update (token renewal, UI preference) must not launder an
        // unreadable baseline into `{}`; keep the original bytes so every later
        // sync still fails closed until an explicit reset.
        val seenJson = if (settings.baselineCorrupt) {
            settings.rawSeenBaselines
        } else {
            encodeSeenLamportContexts(settings.seenLamportByContext)
        }
        val manifestJson = if (settings.baselineCorrupt) {
            settings.rawManifestBaselines
        } else {
            encodeManifestLamports(settings.manifestLamportByContext)
        }
        val editor = prefs.edit()
            .putString(KEY_SERVER_URL, settings.serverUrl)
            .putString(KEY_BEARER_TOKEN, settings.bearerToken)
            .putString(KEY_CHUNK_ID, settings.chunkId)
            .putLong(KEY_LOCAL_VERSION, settings.localVersion)
            .putLong(KEY_LAMPORT, settings.lamportClock)
            .putLong(KEY_KEY_EPOCH, settings.keyEpoch)
            .putString(KEY_LAST_SYNCED, settings.lastSyncedAt)
            .putBoolean(KEY_HAS_LOCAL_CHANGES, settings.hasLocalChanges)
            .putBoolean(KEY_SYNC_ON_STARTUP, settings.syncOnStartup)
            .putInt(KEY_BACKGROUND_SYNC_MINUTES, settings.backgroundSyncMinutes)
        if (seenJson != null) editor.putString(KEY_SEEN_LAMPORTS, seenJson)
        if (manifestJson != null) editor.putString(KEY_MANIFEST_LAMPORTS, manifestJson)
        check(editor.commit()) { "Could not persist sync settings" }
        return settings
    }

    companion object {

        /**
         * Why an entered server URL is unusable, or null if it is fine.
         *
         * `http://` was accepted here and then blocked at runtime by the OS's
         * cleartext policy, so the sync simply failed with a network error and
         * nothing said why. Rejecting it at the point the user types it is the
         * difference between "this is not allowed, and here is the reason" and
         * an unexplained failure much later.
         */
        fun serverUrlProblem(url: String): String? {
            val trimmed = url.trim().trimEnd('/')
            if (trimmed.isEmpty()) return null
            if (trimmed.startsWith("http://", ignoreCase = true)) {
                return "VELA only syncs over HTTPS. Your vault is encrypted either way, " +
                    "but cleartext leaks which server you use and when."
            }
            val host = trimmed.removePrefix("https://").substringBefore('/').substringBefore(':')
            if (host.isBlank() || !host.contains('.')) {
                return "Enter a full server address, for example https://vault.example.com"
            }
            return null
        }

        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_BEARER_TOKEN = "bearer_token"
        private const val KEY_CHUNK_ID = "chunk_id"
        private const val KEY_LOCAL_VERSION = "local_version"
        private const val KEY_LAMPORT = "lamport"
        private const val KEY_KEY_EPOCH = "key_epoch"
        private const val KEY_LAST_SYNCED = "last_synced"
        private const val KEY_HAS_LOCAL_CHANGES = "has_local_changes"
        private const val KEY_SYNC_ON_STARTUP = "sync_on_startup"
        private const val KEY_BACKGROUND_SYNC_MINUTES = "background_sync_minutes"
        private const val KEY_SEEN_LAMPORTS = "seen_lamports_by_context"
        private const val KEY_MANIFEST_LAMPORTS = "manifest_lamports_by_context"
    }
}

/** Canonical form used for the baseline namespace. */
internal fun normalizeSyncServerUrl(url: String): String {
    val raw = url.trim()
    val stripped = when {
        raw.startsWith("https://", ignoreCase = true) -> raw.substring(8)
        raw.startsWith("http://", ignoreCase = true) -> raw.substring(7)
        else -> raw
    }.trimEnd('/')
    if (stripped.isEmpty()) return ""
    // Host (and port) are case-insensitive; the path is not.
    val host = stripped.substringBefore('/').lowercase()
    val path = stripped.substringAfter('/', "")
    return if (path.isEmpty()) "https://$host" else "https://$host/$path"
}

/**
 * The in-memory/persisted sync-settings cell used by [SyncSettingsStore].
 *
 * Extracted from that Android-backed store so tests can drive the exact
 * production publication path (a real [StateFlow] plus the same serialized
 * commit) under controlled interleavings. [persist] is responsible for the
 * platform write and must be synchronous.
 */
internal class SyncSettingsState(
    initial: SyncSettings,
    persist: (SyncSettings) -> SyncSettings,
) {
    private val _settings = MutableStateFlow(initial)
    val settings: StateFlow<SyncSettings> = _settings
    private val cell = SerializedSettings(initial, persist) { published ->
        // Called from inside SerializedSettings' lock, after the durable
        // commit and before that lock is released.
        _settings.value = published
    }

    val current: SyncSettings get() = cell.current

    fun update(transform: (SyncSettings) -> SyncSettings): SyncSettings =
        cell.update(transform)
}

/**
 * Serializes one read-modify-write cell.
 *
 * The store used to build `_settings.value.copy(...)` outside any lock and
 * persist with `apply()`. Two writers — a token renewal and a sync baseline
 * commit — could read the same snapshot, and whichever `apply()` landed last
 * would resurrect the older field (a lost update that can silently lower the
 * rollback baseline or drop a renewed token). Here every mutation runs under a
 * single lock, [persist] must commit synchronously, and [publish] runs *before
 * the lock is released*, so a slower older writer cannot overwrite a newer
 * value in the StateFlow after its own commit. If [persist] throws, neither the
 * cell nor the published value changes.
 */
internal class SerializedSettings<S>(
    initial: S,
    private val persist: (S) -> S,
    private val publish: (S) -> Unit = {},
) {
    private val lock = Any()

    @Volatile
    private var state: S = initial

    val current: S
        get() = state

    fun update(transform: (S) -> S): S = synchronized(lock) {
        val next = persist(transform(state))
        state = next
        publish(next)
        next
    }
}

/**
 * Parse the persisted `{context: {chunk_id: clock}}` baselines.
 *
 * `null` means the stored JSON is unreadable and every sync must fail closed;
 * an absent value is an empty map (a fresh install has simply recorded
 * nothing). Being strict here is the point: the old code collapsed both cases
 * into "no baseline" and thereby failed open on corruption.
 */
internal fun parseSeenLamportContexts(raw: String?): Map<String, Map<String, Long>>? {
    if (raw.isNullOrBlank()) return emptyMap()
    return runCatching {
        val root = JSONObject(raw)
        buildMap {
            for (context in root.keys()) {
                val chunkObject = root.getJSONObject(context)
                val clocks = mutableMapOf<String, Long>()
                for (chunkId in chunkObject.keys()) {
                    val clock = chunkObject.getLong(chunkId)
                    require(clock > 0) { "nonpositive clock for $chunkId" }
                    clocks[chunkId] = clock
                }
                put(context, clocks)
            }
        }
    }.getOrNull()
}

/** `null` on corrupt input, for the same fail-closed reason. */
internal fun parseManifestLamports(raw: String?): Map<String, Long>? {
    if (raw.isNullOrBlank()) return emptyMap()
    return runCatching {
        val root = JSONObject(raw)
        buildMap {
            for (context in root.keys()) {
                val clock = root.getLong(context)
                require(clock > 0) { "nonpositive manifest clock for $context" }
                put(context, clock)
            }
        }
    }.getOrNull()
}

internal fun encodeSeenLamportContexts(byContext: Map<String, Map<String, Long>>): String {
    val root = JSONObject()
    for ((context, clocks) in byContext) {
        val chunkObject = JSONObject()
        for ((chunkId, clock) in clocks) {
            if (clock > 0) chunkObject.put(chunkId, clock)
        }
        if (chunkObject.length() > 0) root.put(context, chunkObject)
    }
    return root.toString()
}

internal fun encodeManifestLamports(byContext: Map<String, Long>): String {
    val root = JSONObject()
    for ((context, clock) in byContext) {
        if (clock > 0) root.put(context, clock)
    }
    return root.toString()
}

/** Never let a stale write lower a baseline. */
internal fun mergeSeenLamports(
    existing: Map<String, Long>,
    updates: Map<String, Long>,
): Map<String, Long> {
    val merged = LinkedHashMap(existing)
    for ((chunkId, clock) in updates) {
        if (clock > (merged[chunkId] ?: 0)) merged[chunkId] = clock
    }
    return merged
}
