package com.vela.android.core

import android.content.Context
import android.util.Log
import com.vela.android.autofill.AppAssociations
import com.vela.android.autofill.AutofillMatcher
import com.vela.android.security.EncryptedVaultStore
import com.vela.android.security.SecureVaultManager
import com.vela.android.sync.SyncSettingsStore
import com.vela.android.sync.VaultSyncManager
import androidx.lifecycle.ProcessLifecycleOwner
import com.vela.android.security.AutoLockController
import com.vela.android.security.AutoLockStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

class LocalVaultRepository(
    private val secureVaultManager: SecureVaultManager,
    private val encryptedVaultStore: EncryptedVaultStore
) {
    var onLocalChange: (() -> Unit)? = null
    var onItemUpdated: ((VaultItem) -> Unit)? = null

    private val _items = MutableStateFlow<List<VaultItem>>(emptyList())
    val items: StateFlow<List<VaultItem>> = _items
    private var store = VaultStore()
    private val _organization = MutableStateFlow(VaultOrganization())
    val organization: StateFlow<VaultOrganization> = _organization
    private fun publish() { _items.value = store.items; _organization.value = VaultOrganization(store.schemaVersion == 2, store.richEnvelope) }


    fun loadFromUnlockedSession() {
        val rms = secureVaultManager.currentRmsCopy() ?: return
        try {
            store = encryptedVaultStore.load(rms)
            publish()
        } catch (error: Exception) {
            // An unreadable vault (corrupt, or written by a newer VELA) must not
            // leave an unlocked, empty vault behind: the first save would then
            // overwrite vault.enc. Lock again and surface the error.
            store = VaultStore()
            publish()
            secureVaultManager.lock()
            throw error
        } finally {
            rms.fill(0)
        }
    }

    fun snapshot(): VaultStore {
        return VaultStore(_items.value, store.tombstones, store.schemaVersion, store.richEnvelope, store.opaqueItems)
    }

    fun replaceAll(store: VaultStore) {
        this.store = store
        publish()
        persistIfUnlocked()
    }

    /**
     * Replace the vault for a path that has already accepted untrusted remote
     * bytes, and require a successful save before any rollback baseline may
     * advance. Power-loss durability is not established by this method.
     *
     * The normal [replaceAll] intentionally tolerates a concurrent AutoLock by
     * leaving the in-memory value ahead of disk (other UI callers rely on the
     * no-op). An admitted sync must not: if the RMS disappeared mid-download,
     * silently dropping the write and then recording the admitted clocks would
     * let a retry look like a rollback. [afterPersist] runs only after
     * [EncryptedVaultStore.save] succeeded, so a locked or failing store leaves
     * the baselines untouched when unavailable at the key snapshot or when
     * save fails. A coherent snapshot captured before a later lock may finish;
     * lock does not cancel in-flight I/O.
     */
    fun <T> replaceAllAdmitted(candidate: VaultStore, afterPersist: () -> T): T =
        persistVaultThenRecord(
            rms = secureVaultManager.currentRmsCopy(),
            save = { rms -> encryptedVaultStore.save(rms, candidate) },
            afterPersist = {
                store = candidate
                publish()
                afterPersist()
            },
        )

    fun encryptSnapshotForSync(
        rms: ByteArray,
        chunkId: String,
        lamportClock: Long,
        keyEpoch: Long,
    ): ByteArray {
        val vaultJson = VaultJson.encode(snapshot()).toString(Charsets.UTF_8)
        val ciphertextB64 = NativeVelaCore.encryptVaultChunkJson(
            rms, chunkId, vaultJson, lamportClock, keyEpoch
        )
            ?: error("Native VELA bridge is required for server sync")
        return java.util.Base64.getDecoder().decode(ciphertextB64)
    }

    fun decryptSyncedVault(
        rms: ByteArray,
        chunkId: String,
        ciphertext: ByteArray,
        lamportClock: Long,
        keyEpoch: Long,
    ): VaultStore {
        val vaultJson = NativeVelaCore.decryptVaultChunkJson(
            rms, chunkId, ciphertext, lamportClock, keyEpoch
        )
            ?: error("Native VELA bridge could not decrypt server vault")
        return VaultJson.decode(vaultJson.toByteArray(Charsets.UTF_8))
    }

    val richerVaultReadOnly: Boolean get() = store.schemaVersion > 2
    private fun ensureWritable() { check(!richerVaultReadOnly) { "Upgrade VELA to edit this vault" }; check(secureVaultManager.currentRmsCopy()?.also { it.fill(0) } != null) { "Unlock the vault first" } }
    private fun commit(candidate: VaultStore) {
        val rms = secureVaultManager.currentRmsCopy() ?: error("Unlock the vault first")
        try { encryptedVaultStore.save(rms, candidate) } finally { rms.fill(0) }
        store = candidate; publish(); onLocalChange?.invoke()
    }
    private fun candidate() = VaultStore(store.items, store.tombstones, store.schemaVersion, store.richEnvelope, store.opaqueItems)
    fun enableRichItems() {
        ensureWritable()
        NativeVelaCore.richItems(org.json.JSONObject().put("operation","capabilities"))
        persistIfUnlocked(); encryptedVaultStore.safetyBackup()
        commit(VaultStore(store.items,store.tombstones,2,store.richEnvelope,store.opaqueItems))
    }
    fun mutateOrganization(action: org.json.JSONObject) {
        ensureWritable(); check(store.schemaVersion == 2) { "Enable collections first" }
        val organization = _organization.value.mutate(action, encryptedVaultStore.organizationWriterId())
        val now = Instant.now()
        val repaired = store.items.map { item ->
            val rich = organization.repair(item.rich)
            if (rich == item.rich) item else item.withRich(rich).withUpdatedAt(now)
        }
        commit(VaultStore(repaired,store.tombstones,2,organization.data,store.opaqueItems))
    }
    /**
     * Import a password-manager export (JSON, CSV, .1pif or .1pux). Parsing runs
     * in the shared Rust crate; this maps the neutral entries onto the Android
     * vault and writes them in one transaction, creating folders and tags when
     * collections are enabled and folding them into notes otherwise.
     */
    fun importVaultBytes(bytes: ByteArray): ImportReport {
        ensureWritable()
        val response = VaultImport.parse(bytes)
        val entries = response.optJSONArray("entries") ?: JSONArray()
        val collections = store.schemaVersion == 2
        val device = encryptedVaultStore.organizationWriterId()
        var organization = _organization.value
        val folderCache = mutableMapOf<String, String>()
        val tagCache = mutableMapOf<String, String>()
        val seenLogins = store.items.filterIsInstance<VaultItem.Login>()
            .map { VaultImport.loginKey(it.url, it.name, it.username) }.toMutableSet()
        val seenCards = store.items.filterIsInstance<VaultItem.CreditCard>()
            .map { VaultImport.cardKey(it.cardNumber, it.name) }.toMutableSet()
        val seenIdentities = store.items.filterIsInstance<VaultItem.Identity>()
            .map { VaultImport.identityKey(it.name, it.notes.orEmpty()) }.toMutableSet()
        val next = candidate()
        val now = Instant.now()
        var added = 0
        var duplicates = 0
        var preserved = 0
        var converted = 0

        fun ensureFolder(path: String): String? {
            var parent: String? = null
            var accumulated = ""
            for (segment in path.split('/').map(String::trim).filter(String::isNotEmpty)) {
                accumulated = if (accumulated.isEmpty()) segment else "$accumulated/$segment"
                val cached = folderCache[accumulated]
                if (cached != null) { parent = cached; continue }
                val existing = organization.folders.map(::JSONObject)
                    .firstOrNull { it.optString("name").equals(segment, true) && it.optString("parentId") == (parent ?: "") }
                    ?.optString("id")
                val id = existing ?: runCatching {
                    val action = JSONObject().put("operation", "createFolder").put("name", segment)
                    if (parent != null) action.put("parentId", parent)
                    organization = organization.mutate(action, device)
                    organization.folders.map(::JSONObject)
                        .first { it.optString("name").equals(segment, true) && it.optString("parentId") == (parent ?: "") }
                        .optString("id")
                }.getOrNull() ?: return null
                folderCache[accumulated] = id
                parent = id
            }
            return parent
        }

        fun ensureTag(name: String): String? {
            val trimmed = name.trim()
            val key = trimmed.lowercase(Locale.US)
            tagCache[key]?.let { return it }
            val existing = organization.tags.map(::JSONObject)
                .firstOrNull { it.optString("name").equals(trimmed, true) }?.optString("id")
            val id = existing ?: runCatching {
                organization = organization.mutate(
                    JSONObject().put("operation", "createTag").put("name", trimmed), device)
                organization.tags.map(::JSONObject)
                    .first { it.optString("name").equals(trimmed, true) }.optString("id")
            }.getOrNull() ?: return null
            tagCache[key] = id
            return id
        }

        for (index in 0 until entries.length()) {
            val entry = entries.optJSONObject(index) ?: continue
            val kind = entry.optString("kind")
            val name = entry.optString("name").ifBlank {
                entry.optString("url").ifBlank {
                    entry.optString("username").ifBlank { "Imported item" }
                }
            }
            var rich = JSONObject()
            var entryPreserved = false
            if (collections) {
                entry.optString("folder").takeIf { it.isNotBlank() }?.let { path ->
                    val id = ensureFolder(path)
                    if (id != null) { rich.put("folderId", id); entryPreserved = true } else converted++
                }
                val tags = entry.optJSONArray("tags")
                if (tags != null && tags.length() > 0) {
                    val ids = mutableListOf<String>()
                    for (tagIndex in 0 until tags.length()) {
                        val id = ensureTag(tags.optString(tagIndex))
                        if (id != null) ids += id else converted++
                    }
                    if (ids.isNotEmpty()) { rich.put("tagIds", JSONArray(ids)); entryPreserved = true }
                }
                val (fields, dropped) = VaultImport.customFieldRecords(entry)
                converted += dropped
                if (fields.length() > 0) { rich.put("customFields", fields); entryPreserved = true }
                val urls = VaultImport.additionalUrlRecords(entry)
                if (urls.length() > 0) { rich.put("additionalUrls", urls); entryPreserved = true }
                VaultImport.identityDetails(entry)?.let {
                    rich.put("identityDetails", it)
                    entryPreserved = true
                }
                if (entryPreserved && runCatching { organization.validate(RichData.from(rich), RichData()) }.isFailure) {
                    rich = JSONObject()
                    entryPreserved = false
                    converted++
                }
            }
            var notes = entry.optString("notes")
            if (!collections || !entryPreserved) {
                val folded = VaultImport.foldIntoNotes(entry)
                if (folded.isNotEmpty()) {
                    notes = if (notes.isBlank()) folded else "$notes\n$folded"
                    converted++
                }
            }
            val favorite = entry.optBoolean("favorite")
            val richFields = RichData.from(rich).fields
            when (kind) {
                "login" -> {
                    val url = entry.optString("url")
                    val username = entry.optString("username")
                    if (!seenLogins.add(VaultImport.loginKey(url, name, username))) { duplicates++; continue }
                    next.addItem(
                        VaultItem.Login(
                            VaultMeta(name = name, notes = notes.ifBlank { null }, favorite = favorite,
                                updatedAt = now, richFields = richFields),
                            url = url,
                            username = username,
                            password = entry.optString("password"),
                            totp = entry.optString("totp").ifBlank { null },
                        ),
                    )
                    added++
                }
                "note" -> {
                    next.addItem(
                        VaultItem.SecureNote(
                            VaultMeta(name = name, favorite = favorite, updatedAt = now, richFields = richFields),
                            content = notes,
                        ),
                    )
                    added++
                }
                "card" -> {
                    val number = entry.optJSONObject("card")?.optString("number").orEmpty()
                    if (!seenCards.add(VaultImport.cardKey(number, name))) { duplicates++; continue }
                    val card = entry.optJSONObject("card") ?: JSONObject()
                    next.addItem(
                        VaultItem.CreditCard(
                            VaultMeta(name = name, notes = notes.ifBlank { null }, favorite = favorite,
                                updatedAt = now, richFields = richFields),
                            cardholderName = card.optString("cardholder"),
                            cardNumber = number,
                            expiration = card.optString("expiry"),
                            cvv = card.optString("cvv"),
                            pin = card.optString("pin").ifBlank { null },
                        ),
                    )
                    added++
                }
                "identity" -> {
                    if (!seenIdentities.add(VaultImport.identityKey(name, notes))) { duplicates++; continue }
                    val identity = entry.optJSONObject("identity") ?: JSONObject()
                    next.addItem(
                        VaultItem.Identity(
                            VaultMeta(name = name, notes = notes.ifBlank { null }, favorite = favorite,
                                updatedAt = now, richFields = richFields),
                            firstName = identity.optString("first"),
                            lastName = identity.optString("last"),
                            ssn = identity.optString("ssn"),
                        ),
                    )
                    added++
                }
            }
            if (entryPreserved) preserved++

            val attachments = entry.optJSONArray("attachments")
            if (attachments != null) {
                for (attachmentIndex in 0 until attachments.length()) {
                    val attachment = attachments.optJSONObject(attachmentIndex) ?: continue
                    next.addItem(
                        VaultItem.SecureNote(
                            VaultMeta(name = "$name — ${attachment.optString("fileName")}", updatedAt = now),
                            content = attachment.optString("note"),
                        ),
                    )
                    added++
                    preserved++
                }
            }
        }

        commit(
            VaultStore(
                next.items,
                next.tombstones,
                next.schemaVersion,
                if (collections) organization.data else next.richEnvelope,
                next.opaqueItems,
            ),
        )
        return VaultImport.reportFrom(response, added, duplicates, preserved, converted)
    }

    private fun checked(item: VaultItem) {
        val old = store.getItem(item.id)
        if (item.rich.hasData || store.schemaVersion == 2) {
            check(store.schemaVersion == 2) { "Enable collections first" }
            _organization.value.validate(item.rich,old?.rich ?: RichData())
        }
    }
    fun addItem(item: VaultItem) {
        ensureWritable(); checked(item)
        check(store.getItem(item.id) == null) { "Item already exists" }
        val next = candidate(); next.addItem(item); commit(next)
    }
    fun updateItem(item: VaultItem) {
        ensureWritable(); checked(item)
        val next = candidate(); next.updateItem(item); commit(next); onItemUpdated?.invoke(item)
    }
    fun deleteItem(id: String) {
        ensureWritable(); val next = candidate(); next.deleteItem(id); commit(next)
    }
    fun clearMemory() { store = VaultStore(); publish() }

    fun search(query: String): List<VaultItem> {
        val normalized = query.trim().lowercase(Locale.US)
        if (normalized.isEmpty()) return _items.value
        return _items.value.filter { item ->
            item.name.lowercase(Locale.US).contains(normalized) ||
                item.notes?.lowercase(Locale.US)?.contains(normalized) == true ||
                when (item) {
                    is VaultItem.Login -> item.url.lowercase(Locale.US).contains(normalized) ||
                        item.username.lowercase(Locale.US).contains(normalized)
                    is VaultItem.Identity -> (item.firstName + " " + item.lastName).lowercase(Locale.US).contains(normalized)
                    is VaultItem.CreditCard -> item.cardholderName.lowercase(Locale.US).contains(normalized)
                    is VaultItem.SecureNote -> item.content.lowercase(Locale.US).contains(normalized)
                    is VaultItem.FileBlob -> item.fileName.lowercase(Locale.US).contains(normalized) ||
                        item.mimeType.lowercase(Locale.US).contains(normalized)
                    is VaultItem.BreachMonitor -> item.email.lowercase(Locale.US).contains(normalized) ||
                        item.breaches.any { breach ->
                            breach.title.lowercase(Locale.US).contains(normalized) ||
                                breach.domain.lowercase(Locale.US).contains(normalized)
                        }
                    is VaultItem.Passkey -> item.rpId.lowercase(Locale.US).contains(normalized) ||
                        item.rpName.lowercase(Locale.US).contains(normalized) ||
                        item.userName.lowercase(Locale.US).contains(normalized)
                }
        }
    }

    fun findAutofillCandidates(webDomain: String?, packageName: String?): List<AutofillCandidate> {
        return findAutofillLogins(webDomain, packageName).map { login ->
            AutofillCandidate(
                itemId = login.id,
                label = login.name,
                username = login.username,
                domain = hostOf(login.url),
                hasTotp = login.totp != null,
                itemType = VaultItemType.Login
            )
        }
    }

    /**
     * Logins that may be offered for an autofill request.
     *
     * The rules live in [AutofillMatcher]; [assetLinksVerifier] supplies the
     * network half (Digital Asset Links) when a verifier has been installed.
     */
    fun findAutofillLogins(webDomain: String?, packageName: String?): List<VaultItem.Login> {
        val verifier = assetLinksVerifier
        val browsers = browserAllowlist
        return AutofillMatcher.match(
            logins = _items.value.filterIsInstance<VaultItem.Login>(),
            webDomain = webDomain,
            packageName = packageName,
            isTrustedBrowser = browsers ?: { false },
            installedSignatures = installedSignatures ?: { emptySet() },
            verifyAssetLinks = verifier ?: { _, _ -> false },
        )
    }

    /**
     * Signing certificates of an installed app, for links that pinned one.
     * Installed alongside the other autofill lookups; absent means no signature
     * is ever confirmed, so pinned links fail closed.
     */
    var installedSignatures: ((String) -> Set<String>)? = null

    /**
     * Grant [packageName] the right to be offered [itemId].
     *
     * This is the user speaking, so it is the strongest signal the matcher has —
     * which is why [pinSigningKey] exists. Pinning records the certificate the
     * app is signed with today, so the grant does not transfer if the package
     * later ships from someone else's key. Leaving it off keeps the grant on the
     * package name, which is what a user running the same app from a different
     * store needs (F-Droid and Play sign differently).
     */
    fun linkApp(itemId: String, packageName: String, pinSigningKey: Boolean): Boolean {
        val login = _items.value.filterIsInstance<VaultItem.Login>().firstOrNull { it.id == itemId }
            ?: return false
        val fingerprint = if (pinSigningKey) {
            installedSignatures?.invoke(packageName)?.firstOrNull() ?: return false
        } else {
            null
        }
        val link = AppAssociations.appUri(packageName, fingerprint)

        // Replace any existing link for this package: the user is restating the
        // grant, not adding a second one.
        val kept = login.appIds.filter {
            !AppAssociations.packageFromUri(it).equals(packageName.lowercase(Locale.US), ignoreCase = true)
        }
        // A rejected write (e.g. validation) reports failure instead of crashing the UI.
        return runCatching {
            updateItem(
                login.copy(
                    appIds = kept + link,
                    meta = login.meta.copy(updatedAt = Instant.now(), lastModifiedDevice = "android-local"),
                )
            )
        }.isSuccess
    }

    /** Revoke a grant. The link string is what the UI listed, so it round-trips. */
    fun unlinkApp(itemId: String, link: String) {
        val login = _items.value.filterIsInstance<VaultItem.Login>().firstOrNull { it.id == itemId }
            ?: return
        if (link !in login.appIds) return
        runCatching {
            updateItem(
                login.copy(
                    appIds = login.appIds - link,
                    meta = login.meta.copy(updatedAt = Instant.now(), lastModifiedDevice = "android-local"),
                )
            )
        }
    }

    /**
     * Asks a site whether it vouches for an app. Installed at startup, where
     * there is a Context; null in tests, so the matcher simply falls back to
     * locally-known associations.
     */
    var assetLinksVerifier: ((String, String) -> Boolean)? = null

    /**
     * Whether a package is a browser whose claimed `webDomain` may be believed —
     * signing certificate checked, not just the name. Installed alongside
     * [assetLinksVerifier]; absent means "nothing is a browser", which is the
     * safe direction.
     */
    var browserAllowlist: ((String) -> Boolean)? = null

    /** See [browserAllowlist]. */
    fun isTrustedBrowser(packageName: String?): Boolean {
        val check = browserAllowlist ?: return false
        val pkg = packageName?.takeIf { it.isNotBlank() } ?: return false
        return check(pkg)
    }

    private fun hostOf(value: String): String? = AutofillMatcher.hostOf(value)

    private fun persistIfUnlocked() {
        val rms = secureVaultManager.currentRmsCopy() ?: return
        try {
            store.pruneTombstones()
            encryptedVaultStore.save(rms, VaultStore(store.items, store.tombstones, store.schemaVersion, store.richEnvelope, store.opaqueItems))
        } finally {
            rms.fill(0)
        }
    }
}

/**
 * Persist an admitted replacement before running [afterPersist], which is where
 * rollback baselines are recorded.
 *
 * Kept outside [LocalVaultRepository] so it can be unit-tested without an
 * Android context: a missing RMS (AutoLock raced the sync) or a storage
 * failure must throw before [afterPersist] runs, leaving the baseline
 * untouched. Android's SharedPreferences/keystore durability guarantees are
 * taken as trusted OS behavior, not proved here.
 */
internal fun <T> persistVaultThenRecord(
    rms: ByteArray?,
    save: (ByteArray) -> Unit,
    afterPersist: () -> T,
): T {
    val unlockedRms = rms ?: error(
        "The vault locked while downloaded data was being applied. Unlock VELA and " +
            "sync again; no rollback baseline was advanced."
    )
    try {
        save(unlockedRms)
    } finally {
        unlockedRms.fill(0)
    }
    return afterPersist()
}

object VelaRepositories {
    lateinit var security: SecureVaultManager
        private set

    lateinit var vault: LocalVaultRepository
        private set

    lateinit var syncSettings: SyncSettingsStore
        private set

    lateinit var serverIdentity: com.vela.android.sync.ServerIdentityStore
        private set

    lateinit var sync: VaultSyncManager
        private set

    lateinit var sharing: SharingRepository
        private set

    lateinit var audit: AuditLogRepository
        private set

    lateinit var recent: RecentItemStore
        private set

    lateinit var autoLock: AutoLockStore
        private set

    lateinit var theme: com.vela.android.ui.theme.ThemeStore
        private set

    // Tied to the process, not any one Activity, so callers (e.g. the share-push
    // hook below) keep running if the launching Activity is torn down, but a
    // failure in one launch can't take the whole process down like a bare
    // Thread's default uncaught-exception handler would.
    private val backgroundScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun init(context: Context) {
        security = SecureVaultManager(context.applicationContext)
        vault = LocalVaultRepository(
            secureVaultManager = security,
            encryptedVaultStore = EncryptedVaultStore(context.applicationContext.filesDir.resolve("vault"))
        )
        // Autofill decides where credentials may go; both answers need a Context,
        // and neither belongs in the repository itself (audit A-2).
        val appContext = context.applicationContext
        vault.assetLinksVerifier = com.vela.android.autofill.AssetLinksVerifier(appContext)::verify
        vault.browserAllowlist = com.vela.android.autofill.BrowserAllowlist(appContext)::isTrustedBrowser
        vault.installedSignatures = { pkg -> com.vela.android.autofill.AppSignatures.sha256(appContext, pkg) }
        syncSettings = SyncSettingsStore(context.applicationContext)
        vault.onLocalChange = { syncSettings.markLocalChanged() }
        serverIdentity = com.vela.android.sync.ServerIdentityStore(context.applicationContext)
        sync = VaultSyncManager(context.applicationContext, syncSettings, serverIdentity, security, vault)
        sharing = SharingRepository(vault, security, sync, serverIdentity, context.applicationContext)
        vault.onItemUpdated = { item ->
            backgroundScope.launch {
                runCatching { sharing.pushShareUpdates(item) }
                    .onFailure { Log.e("VelaRepositories", "pushShareUpdates failed", it) }
            }
        }
        audit = AuditLogRepository(context.applicationContext)
        recent = RecentItemStore(context.applicationContext)

        autoLock = AutoLockStore(context.applicationContext)
        theme = com.vela.android.ui.theme.ThemeStore(context.applicationContext)
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            AutoLockController(context.applicationContext, security, autoLock)
        )
    }
}
