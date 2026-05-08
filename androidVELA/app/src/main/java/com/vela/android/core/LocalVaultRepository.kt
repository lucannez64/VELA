package com.vela.android.core

import android.content.Context
import com.vela.android.security.EncryptedVaultStore
import com.vela.android.security.SecureVaultManager
import com.vela.android.sync.SyncSettingsStore
import com.vela.android.sync.VaultSyncManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.net.URI
import java.time.Instant
import java.util.Locale

class LocalVaultRepository(
    private val secureVaultManager: SecureVaultManager,
    private val encryptedVaultStore: EncryptedVaultStore
) {
    var onLocalChange: (() -> Unit)? = null

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

    fun encryptSnapshotForSync(rms: ByteArray, chunkId: String): ByteArray {
        val vaultJson = VaultJson.encode(snapshot()).toString(Charsets.UTF_8)
        val ciphertextB64 = NativeVelaCore.encryptVaultChunkJson(rms, chunkId, vaultJson)
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

    fun findAutofillLogins(webDomain: String?, packageName: String?): List<VaultItem.Login> {
        val domains = buildSet {
            webDomain?.takeIf { it.isNotBlank() }?.let { add(it) }
            packageName?.takeIf { it.isNotBlank() }?.let {
                add(it)
                domainFromPackageName(it)?.let { d -> add(d) }
            }
        }
        val logins = _items.value.filterIsInstance<VaultItem.Login>()
        return if (domains.isEmpty()) logins else logins.filter { login ->
            domains.any { domain -> domainsMatch(domain, login.url) }
        }
    }

    private fun domainsMatch(current: String, stored: String): Boolean {
        val currentHost = hostOf(current) ?: current.lowercase(Locale.US)
        val storedHost = hostOf(stored) ?: stored.lowercase(Locale.US)
        if (currentHost == storedHost) return true
        if (currentHost.isIpAddress()) return false
        val currentParts = currentHost.split(".")
        val storedParts = storedHost.split(".")
        if (storedParts.size < 2 || storedParts.size > currentParts.size) return false
        return currentParts.takeLast(storedParts.size) == storedParts
    }

    private fun domainFromPackageName(pkg: String): String? {
        val known = mapOf(
            "com.instagram.android" to "instagram.com",
            "com.zhiliaoapp.musically" to "tiktok.com",
            "com.whatsapp" to "whatsapp.com",
            "com.facebook.orca" to "facebook.com",
            "com.facebook.katana" to "facebook.com",
            "com.snapchat.android" to "snapchat.com",
            "com.linkedin.android" to "linkedin.com",
            "com.pinterest" to "pinterest.com",
            "com.reddit.frontpage" to "reddit.com",
            "com.spotify.music" to "spotify.com",
            "com.netflix.mediaclient" to "netflix.com",
            "com.amazon.mShop.android.shopping" to "amazon.com",
            "com.paypal.android.p2pmobile" to "paypal.com",
            "com.ubercab" to "uber.com",
            "com.airbnb.android" to "airbnb.com",
            "com.discord" to "discord.com",
            "com.twitch.android.app" to "twitch.tv",
            "com.ebay.mobile" to "ebay.com",
            "com.dropbox.android" to "dropbox.com",
            "com.slack" to "slack.com",
            "com.skype.raider" to "skype.com",
            "com.vkontakte.android" to "vk.com",
            "com.telegram.messenger" to "telegram.org"
        )
        known[pkg]?.let { return it }

        val parts = pkg.split(".")
        if (parts.size >= 3 && parts[0] == "com") {
            return "${parts[1]}.com"
        }
        return null
    }

    private fun hostOf(value: String): String? {
        val normalized = if (value.startsWith("http://") || value.startsWith("https://")) {
            value
        } else {
            "https://$value"
        }
        return runCatching { URI(normalized).host?.removePrefix("www.")?.lowercase(Locale.US) }.getOrNull()
    }

    private fun String.isIpAddress(): Boolean = split(".").all { it.toIntOrNull() in 0..255 }

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

    fun init(context: Context) {
        security = SecureVaultManager(context.applicationContext)
        vault = LocalVaultRepository(
            secureVaultManager = security,
            encryptedVaultStore = EncryptedVaultStore(context.applicationContext.filesDir.resolve("vault"))
        )
        syncSettings = SyncSettingsStore(context.applicationContext)
        vault.onLocalChange = { syncSettings.markLocalChanged() }
        serverIdentity = com.vela.android.sync.ServerIdentityStore(context.applicationContext)
        sync = VaultSyncManager(context.applicationContext, syncSettings, serverIdentity, security, vault)
        sharing = SharingRepository(vault, security, sync)
        audit = AuditLogRepository(context.applicationContext)
    }
}
