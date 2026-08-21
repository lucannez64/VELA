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

class LocalVaultRepository(
    private val secureVaultManager: SecureVaultManager,
    private val encryptedVaultStore: EncryptedVaultStore
) {
    var onLocalChange: (() -> Unit)? = null
    var onItemUpdated: ((VaultItem) -> Unit)? = null

    private val _items = MutableStateFlow<List<VaultItem>>(emptyList())
    val items: StateFlow<List<VaultItem>> = _items
    private var store = VaultStore()

    fun loadFromUnlockedSession() {
        val rms = secureVaultManager.currentRmsCopy() ?: return
        try {
            store = encryptedVaultStore.load(rms)
            _items.value = store.items
        } finally {
            rms.fill(0)
        }
    }

    fun snapshot(): VaultStore {
        return VaultStore(_items.value, store.tombstones)
    }

    fun replaceAll(store: VaultStore) {
        this.store = store
        _items.value = store.items
        persistIfUnlocked()
    }

    fun encryptSnapshotForSync(rms: ByteArray, chunkId: String, lamportClock: Long): ByteArray {
        val vaultJson = VaultJson.encode(snapshot()).toString(Charsets.UTF_8)
        val ciphertextB64 = NativeVelaCore.encryptVaultChunkJson(rms, chunkId, vaultJson, lamportClock)
            ?: error("Native VELA bridge is required for server sync")
        return java.util.Base64.getDecoder().decode(ciphertextB64)
    }

    fun decryptSyncedVault(rms: ByteArray, chunkId: String, ciphertext: ByteArray): VaultStore {
        val vaultJson = NativeVelaCore.decryptVaultChunkJson(rms, chunkId, ciphertext)
            ?: error("Native VELA bridge could not decrypt server vault")
        return VaultJson.decode(vaultJson.toByteArray(Charsets.UTF_8))
    }

    fun addItem(item: VaultItem) {
        store.addItem(item)
        _items.value = store.items
        onLocalChange?.invoke()
        persistIfUnlocked()
    }

    fun updateItem(item: VaultItem) {
        store.updateItem(item)
        _items.value = store.items
        onLocalChange?.invoke()
        onItemUpdated?.invoke(item)
        persistIfUnlocked()
    }

    fun deleteItem(id: String) {
        store.deleteItem(id)
        _items.value = store.items
        onLocalChange?.invoke()
        persistIfUnlocked()
    }

    fun clearMemory() {
        _items.value = emptyList()
    }

    fun search(query: String): List<VaultItem> {
        val normalized = query.trim().lowercase(Locale.US)
        if (normalized.isEmpty()) return _items.value
        return _items.value.filter { item ->
            item.name.lowercase(Locale.US).contains(normalized) ||
                item.notes?.lowercase(Locale.US)?.contains(normalized) == true ||
                when (item) {
                    is VaultItem.Login -> item.url.lowercase(Locale.US).contains(normalized) ||
                        item.username.lowercase(Locale.US).contains(normalized)
                    is VaultItem.CreditCard -> item.cardholderName.lowercase(Locale.US).contains(normalized)
                    is VaultItem.SecureNote -> item.content.lowercase(Locale.US).contains(normalized)
                    is VaultItem.FileBlob -> item.fileName.lowercase(Locale.US).contains(normalized) ||
                        item.mimeType.lowercase(Locale.US).contains(normalized)
                    is VaultItem.BreachMonitor -> item.email.lowercase(Locale.US).contains(normalized) ||
                        item.breaches.any { breach ->
                            breach.title.lowercase(Locale.US).contains(normalized) ||
                                breach.domain.lowercase(Locale.US).contains(normalized)
                        }
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
        updateItem(
            login.copy(
                appIds = kept + link,
                meta = login.meta.copy(updatedAt = Instant.now(), lastModifiedDevice = "android-local"),
            )
        )
        return true
    }

    /** Revoke a grant. The link string is what the UI listed, so it round-trips. */
    fun unlinkApp(itemId: String, link: String) {
        val login = _items.value.filterIsInstance<VaultItem.Login>().firstOrNull { it.id == itemId }
            ?: return
        if (link !in login.appIds) return
        updateItem(
            login.copy(
                appIds = login.appIds - link,
                meta = login.meta.copy(updatedAt = Instant.now(), lastModifiedDevice = "android-local"),
            )
        )
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
            encryptedVaultStore.save(rms, VaultStore(store.items, store.tombstones))
        } finally {
            rms.fill(0)
        }
    }
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

        autoLock = AutoLockStore(context.applicationContext)
        theme = com.vela.android.ui.theme.ThemeStore(context.applicationContext)
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            AutoLockController(context.applicationContext, security, autoLock)
        )
    }
}
