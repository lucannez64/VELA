package com.vela.android.sync

import com.vela.android.core.LocalVaultRepository
import com.vela.android.core.NativeVelaCore
import com.vela.android.core.Tombstone
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultJson
import com.vela.android.core.VaultStore
import com.vela.android.security.SecureVaultManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONObject
import java.time.Instant
import java.util.Base64

data class SyncState(
    val syncing: Boolean = false,
    val lastSyncedAt: String? = null,
    val error: String? = null,
    val conflict: String? = null,
    val canResolveConflict: Boolean = false
)

class VaultSyncManager(
    private val settingsStore: SyncSettingsStore,
    private val identityStore: ServerIdentityStore,
    private val security: SecureVaultManager,
    private val vault: LocalVaultRepository
) {
    private val _state = MutableStateFlow(SyncState(lastSyncedAt = settingsStore.settings.value.lastSyncedAt))
    val state: StateFlow<SyncState> = _state

    fun updateServer(serverUrl: String, bearerToken: String) {
        settingsStore.updateServer(serverUrl, bearerToken)
    }

    fun <T> withAuthenticatedClient(block: (AndroidVelaApiClient, String) -> T): T {
        val settings = settingsStore.settings.value
        require(settings.serverUrl.isNotBlank()) { "Server URL is not configured" }
        val client = AndroidVelaApiClient(settings.serverUrl)
        val token = authenticatedToken(client, settings.bearerToken)
        if (token != settings.bearerToken) {
            settingsStore.updateBearerToken(token)
        }
        return try {
            block(client, token)
        } catch (e: ServerUnauthorizedException) {
            if (!e.isRecoverableTokenFailure() || settings.bearerToken.isBlank()) throw e
            settingsStore.updateBearerToken("")
            val freshToken = authenticatedToken(client, "")
            settingsStore.updateBearerToken(freshToken)
            block(client, freshToken)
        }
    }

    fun enrollWithCode(serverUrl: String, enrollmentCode: String): ByteArray {
        val payload = EnrollmentCodePayload.fromCode(enrollmentCode)
        val effectiveServerUrl = serverUrl.ifBlank { payload.serverUrl }
        if (effectiveServerUrl.isBlank()) {
            error("Enrollment requires a server URL")
        }

        updateServer(effectiveServerUrl, "")
        val client = AndroidVelaApiClient(settingsStore.settings.value.serverUrl)
        identityStore.save(
            ServerIdentity(
                userId = null,
                deviceId = payload.deviceId,
                hybridEkB64 = payload.hybridEkB64,
                hybridVkB64 = payload.hybridVkB64,
                cycloPkB64 = payload.cycloPkB64,
                cycloSkB64 = payload.cycloSkB64,
                hybridSkB64 = payload.hybridSkB64
            )
        )

        val token = authenticateOrRegister(client)
        val capsule = client.getCapsule(token)
        capsule.newToken?.let { updateServer(settingsStore.settings.value.serverUrl, it) }
        return NativeVelaCore.decryptRmsCapsule(payload.transferKeyB64, capsule.capsuleB64)
            ?: error("Native VELA bridge could not decrypt enrollment capsule")
    }

    fun syncNow(): SyncState {
        if (security.session.value.unlocked.not()) {
            return publish(error = "Unlock VELA before syncing")
        }

        val settings = settingsStore.settings.value
        if (settings.serverUrl.isBlank()) {
            return publish(error = "Configure server URL before syncing")
        }

        val rms = security.currentRmsCopy() ?: return publish(error = "No unlocked vault key")
        _state.value = _state.value.copy(syncing = true, error = null, conflict = null)
        return try {
            syncUnlocked(settings, rms)
        } catch (e: Exception) {
            publish(error = e.message ?: "Sync failed")
        } finally {
            rms.fill(0)
        }
    }

    fun resolveConflictUseRemote(): SyncState {
        if (security.session.value.unlocked.not()) {
            return publish(error = "Unlock VELA before resolving conflict")
        }
        val settings = settingsStore.settings.value
        if (settings.serverUrl.isBlank()) {
            return publish(error = "Configure server URL before resolving conflict")
        }
        val rms = security.currentRmsCopy() ?: return publish(error = "No unlocked vault key")
        _state.value = _state.value.copy(syncing = true, error = null)
        return try {
            val client = AndroidVelaApiClient(settings.serverUrl)
            var token = authenticatedToken(client, settings.bearerToken)
            val manifestResult = getManifestWithTokenRetry(client, token, settings)
            val manifest = manifestResult.manifest
            token = manifestResult.token
            val manifestToken = manifestResult.newToken
            manifestToken?.let { token = it }
            val downloadChunkIds = recognizedVaultChunkIds(manifest)
            if (downloadChunkIds.isEmpty()) {
                publish(error = "Server has no recognized vault data chunk")
            } else {
                val remoteResult = downloadRemoteVault(client, token, rms, downloadChunkIds, manifest)
                vault.replaceAll(remoteResult.vault)
                markSynced(remoteResult.token, remoteResult.version, remoteResult.lamportClock, null)
            }
        } catch (e: Exception) {
            publish(error = e.message ?: "Conflict resolution failed")
        } finally {
            rms.fill(0)
        }
    }

    fun resolveConflictUseLocal(): SyncState {
        if (security.session.value.unlocked.not()) {
            return publish(error = "Unlock VELA before resolving conflict")
        }
        val settings = settingsStore.settings.value
        if (settings.serverUrl.isBlank()) {
            return publish(error = "Configure server URL before resolving conflict")
        }
        val rms = security.currentRmsCopy() ?: return publish(error = "No unlocked vault key")
        _state.value = _state.value.copy(syncing = true, error = null)
        return try {
            val client = AndroidVelaApiClient(settings.serverUrl)
            var token = authenticatedToken(client, settings.bearerToken)
            val manifestResult = getManifestWithTokenRetry(client, token, settings)
            val manifest = manifestResult.manifest
            token = manifestResult.token
            val manifestToken = manifestResult.newToken
            manifestToken?.let { token = it }
            val remote = manifest.chunks.firstOrNull { it.chunkId == VAULT_DATA_CHUNK_ID }
            val nextLamport = maxOf(settings.lamportClock, remote?.lamportClock ?: 0) + 1
            val uploaded = uploadVaultChunks(
                client = client,
                startToken = token,
                rms = rms,
                manifest = manifest,
                baseLamport = nextLamport
            )
            markSynced(uploaded.token, uploaded.version, uploaded.lamportClock, null)
        } catch (e: Exception) {
            publish(error = e.message ?: "Conflict resolution failed")
        } finally {
            rms.fill(0)
        }
    }

    private fun syncUnlocked(settings: SyncSettings, rms: ByteArray): SyncState {
        val client = AndroidVelaApiClient(settings.serverUrl)
        var token = authenticatedToken(client, settings.bearerToken)
        if (token != settings.bearerToken) {
            settingsStore.updateBearerToken(token)
        }
        val manifestResult = getManifestWithTokenRetry(client, token, settings)
        val manifest = manifestResult.manifest
        token = manifestResult.token
        val manifestToken = manifestResult.newToken
        manifestToken?.let { token = it }
        val downloadChunkIds = recognizedVaultChunkIds(manifest)
        val uploadChunkId = VAULT_DATA_CHUNK_ID
        val remote = manifest.chunks.firstOrNull { it.chunkId == uploadChunkId }

        if (downloadChunkIds.isEmpty() && manifest.chunks.isNotEmpty()) {
            return publish(conflict = "Server has no recognized vault data chunk. Cross-platform merge is not enabled yet; refusing to upload.")
        }

        val localSnapshot = vault.snapshot()
        if (downloadChunkIds.isNotEmpty() &&
            (settings.localVersion == 0L && localSnapshot.items.isEmpty() || localSnapshot.hasIncompleteCards())
        ) {
            val remoteResult = downloadRemoteVault(client, token, rms, downloadChunkIds, manifest)
            token = remoteResult.token
            vault.replaceAll(remoteResult.vault)
            return markSynced(
                token = token,
                version = remoteResult.version,
                lamportClock = remoteResult.lamportClock,
                message = null
            )
        }

        if (remote != null && remote.version > settings.localVersion && settings.localVersion > 0) {
            val remoteResult = downloadRemoteVault(client, token, rms, downloadChunkIds, manifest)
            token = remoteResult.token
            val mergedVault = mergeVaultStores(localSnapshot, remoteResult.vault)
            vault.replaceAll(mergedVault)

            val nextLamport = maxOf(settings.lamportClock, remoteResult.lamportClock) + 1
            val uploaded = uploadVaultChunks(
                client = client,
                startToken = token,
                rms = rms,
                manifest = manifest,
                baseLamport = nextLamport
            )
            return markSynced(uploaded.token, uploaded.version, uploaded.lamportClock, null)
        }

        if (downloadChunkIds.isNotEmpty() && remote != null && remote.version > settings.localVersion) {
            val remoteResult = downloadRemoteVault(client, token, rms, downloadChunkIds, manifest)
            token = remoteResult.token
            val mergedVault = mergeVaultStores(localSnapshot, remoteResult.vault)
            vault.replaceAll(mergedVault)
            val nextLamport = maxOf(settings.lamportClock, remoteResult.lamportClock) + 1
            val uploaded = uploadVaultChunks(
                client = client,
                startToken = token,
                rms = rms,
                manifest = manifest,
                baseLamport = nextLamport
            )
            return markSynced(uploaded.token, uploaded.version, uploaded.lamportClock, null)
        }

        val nextLamport = maxOf(settings.lamportClock, remote?.lamportClock ?: 0) + 1
        val uploaded = uploadVaultChunks(
            client = client,
            startToken = token,
            rms = rms,
            manifest = manifest,
            baseLamport = nextLamport
        )
        return markSynced(uploaded.token, uploaded.version, uploaded.lamportClock, null)
    }

    private fun getManifestWithTokenRetry(
        client: AndroidVelaApiClient,
        startToken: String,
        settings: SyncSettings
    ): ManifestDownload {
        return try {
            val (manifest, newToken) = client.getSyncManifest(startToken)
            ManifestDownload(manifest = manifest, token = startToken, newToken = newToken)
        } catch (e: ServerUnauthorizedException) {
            if (!e.isRecoverableTokenFailure() || settings.bearerToken.isBlank()) throw e
            settingsStore.updateBearerToken("")
            val freshToken = authenticatedToken(client, "")
            settingsStore.updateBearerToken(freshToken)
            val (manifest, newToken) = client.getSyncManifest(freshToken)
            ManifestDownload(manifest = manifest, token = freshToken, newToken = newToken)
        }
    }

    private fun recognizedVaultChunkIds(manifest: SyncManifest): List<String> {
        val vaultChunkIds = manifest.chunks
            .map { it.chunkId }
            .filter { it.startsWith(VAULT_DATA_PREFIX) }
            .sorted()
        return when {
            vaultChunkIds.isNotEmpty() -> vaultChunkIds
            manifest.chunks.any { it.chunkId == LEGACY_VAULT_MAIN_CHUNK_ID } -> listOf(LEGACY_VAULT_MAIN_CHUNK_ID)
            else -> emptyList()
        }
    }

    private fun authenticateOrRegister(client: AndroidVelaApiClient): String {
        var identity = identityStore.getOrCreate()
        if (identity.deviceId.isNullOrBlank()) {
            val registered = client.registerAccount(identity)
            identity = identity.copy(userId = registered.userId, deviceId = registered.deviceId)
            identityStore.save(identity)
            registered.token?.takeIf { it.isNotBlank() }?.let { return it }
        }

        val deviceId = identity.deviceId ?: error("Server identity has no device id")
        val challenge = client.getChallenge()
        val proofJson = com.vela.android.core.NativeVelaCore.createAuthProofJson(
            cycloPkB64 = identity.cycloPkB64,
            cycloSkB64 = identity.cycloSkB64,
            challengeB64 = challenge.challengeB64,
            deviceId = deviceId
        ) ?: error("Native VELA bridge cannot create server auth proof")
        val proof = org.json.JSONObject(proofJson)
        val verified = client.verifyProof(
            deviceId = deviceId,
            challengeB64 = challenge.challengeB64,
            committedHash = proof.getString("committed_hash"),
            proof = proof.getString("proof")
        )
        identityStore.save(identity.copy(userId = verified.userId))
        return verified.token
    }

    private fun authenticatedToken(client: AndroidVelaApiClient, cachedToken: String): String =
        cachedToken.ifBlank { authenticateOrRegister(client) }

    private fun downloadRemoteVault(
        client: AndroidVelaApiClient,
        startToken: String,
        rms: ByteArray,
        chunkIds: List<String>,
        manifest: SyncManifest
    ): RemoteVaultDownload {
        var token = startToken
        val decodedJson = buildString {
            for (chunkId in chunkIds) {
                val downloaded = client.getChunk(token, chunkId)
                downloaded.newToken?.let { token = it }
                append(
                    NativeVelaCore.decryptVaultChunkJson(rms, chunkId, downloaded.ciphertext)
                        ?: error("Native VELA bridge could not decrypt server vault chunk $chunkId")
                )
            }
        }
        val remoteVault = com.vela.android.core.VaultJson.decode(decodedJson.toByteArray(Charsets.UTF_8))
        val latestRemote = chunkIds
            .mapNotNull { chunkId -> manifest.chunks.firstOrNull { it.chunkId == chunkId } }
            .maxByOrNull { it.version }
        return RemoteVaultDownload(
            vault = remoteVault,
            token = token,
            version = latestRemote?.version ?: 0,
            lamportClock = latestRemote?.lamportClock ?: 0
        )
    }

    private fun uploadVaultChunks(
        client: AndroidVelaApiClient,
        startToken: String,
        rms: ByteArray,
        manifest: SyncManifest,
        baseLamport: Long
    ): RemoteVaultUpload {
        var token = startToken
        var lamport = baseLamport
        var firstChunkVersion = 0L
        val chunks = splitUtf8Chunks(VaultJson.encode(vault.snapshot()).toString(Charsets.UTF_8))
        val manifestById = manifest.chunks.associateBy { it.chunkId }

        chunks.forEachIndexed { index, chunk ->
            val chunkId = vaultChunkId(index)
            val remote = manifestById[chunkId]
            val ciphertextB64 = NativeVelaCore.encryptVaultChunkJson(rms, chunkId, chunk)
                ?: error("Native VELA bridge is required for server sync")
            val uploaded = client.putChunk(
                token = token,
                chunkId = chunkId,
                ifMatch = remote?.version ?: 0,
                lamportClock = lamport,
                ciphertext = Base64.getDecoder().decode(ciphertextB64)
            )
            uploaded.newToken?.let { token = it }
            if (index == 0) {
                firstChunkVersion = uploaded.version
            }
            lamport += 1
        }

        manifest.chunks
            .filter { it.chunkId.startsWith(VAULT_DATA_PREFIX) }
            .forEach { entry ->
                val index = entry.chunkId.removePrefix(VAULT_DATA_PREFIX).toIntOrNull() ?: return@forEach
                if (index >= chunks.size) {
                    runCatching { client.deleteChunk(token, entry.chunkId, entry.version) }
                        .getOrNull()
                        ?.let { token = it }
                }
            }

        return RemoteVaultUpload(
            token = token,
            version = firstChunkVersion,
            lamportClock = (lamport - 1).coerceAtLeast(baseLamport)
        )
    }

    private fun markSynced(token: String, version: Long, lamportClock: Long, message: String?): SyncState {
        val now = Instant.now().toString()
        settingsStore.updateServer(settingsStore.settings.value.serverUrl, token)
        settingsStore.updateMeta(version, lamportClock, now)
        return publish(lastSyncedAt = now, error = message)
    }

    private fun publish(
        lastSyncedAt: String? = _state.value.lastSyncedAt,
        error: String? = null,
        conflict: String? = null,
        canResolveConflict: Boolean = false
    ): SyncState {
        val next = SyncState(
            syncing = false,
            lastSyncedAt = lastSyncedAt,
            error = error,
            conflict = conflict,
            canResolveConflict = canResolveConflict
        )
        _state.value = next
        return next
    }

    companion object {
        private const val LEGACY_VAULT_MAIN_CHUNK_ID = "vault-main"
        private const val VAULT_DATA_PREFIX = "vault-data-"
        private const val VAULT_DATA_CHUNK_ID = "vault-data-000000"
    }
}

private data class RemoteVaultDownload(
    val vault: VaultStore,
    val token: String,
    val version: Long,
    val lamportClock: Long
)

private data class RemoteVaultUpload(
    val token: String,
    val version: Long,
    val lamportClock: Long
)

private data class ManifestDownload(
    val manifest: SyncManifest,
    val token: String,
    val newToken: String?
)

private fun vaultChunkId(index: Int): String = "vault-data-${index.toString().padStart(6, '0')}"

private fun splitUtf8Chunks(value: String): List<String> {
    if (value.isEmpty()) return listOf("")
    val chunks = mutableListOf<String>()
    val current = StringBuilder()
    var currentBytes = 0
    value.forEach { char ->
        val charBytes = char.toString().toByteArray(Charsets.UTF_8).size
        if (current.isNotEmpty() && currentBytes + charBytes > VAULT_CHUNK_PLAINTEXT_SIZE) {
            chunks += current.toString()
            current.clear()
            currentBytes = 0
        }
        current.append(char)
        currentBytes += charBytes
    }
    if (current.isNotEmpty()) chunks += current.toString()
    return chunks
}

private const val VAULT_CHUNK_PLAINTEXT_SIZE = 1024 * 1024 - 4096

private fun mergeVaultStores(local: VaultStore, remote: VaultStore): VaultStore {
    val tombstones = mergeTombstones(local.tombstones + remote.tombstones)
    val tombstoneById = tombstones.associateBy { it.id }
    val mergedItems = linkedMapOf<String, VaultItem>()

    fun applyItem(item: VaultItem) {
        val tombstone = tombstoneById[item.id]
        if (tombstone != null && tombstone.deletedAt >= item.updatedAt) {
            mergedItems.remove(item.id)
            return
        }

        val existing = mergedItems[item.id]
        if (existing == null || item.updatedAt >= existing.updatedAt) {
            mergedItems[item.id] = item
        }
    }

    local.items.forEach(::applyItem)
    remote.items.forEach(::applyItem)

    return VaultStore(
        items = mergedItems.values.sortedBy { it.name.lowercase() },
        tombstones = pruneTombstones(tombstones)
    )
}

private fun mergeTombstones(values: List<Tombstone>): List<Tombstone> =
    values.groupBy { it.id }.map { (_, tombstones) -> tombstones.maxBy { it.deletedAt } }

private fun pruneTombstones(values: List<Tombstone>): List<Tombstone> {
    val cutoff = Instant.now().minus(java.time.Duration.ofDays(30))
    return values.filter { it.deletedAt >= cutoff }
}

private fun VaultStore.hasIncompleteCards(): Boolean =
    items.any { it is VaultItem.CreditCard && (it.cardNumber.isBlank() || it.expiration.isBlank()) }

private fun ServerUnauthorizedException.isRecoverableTokenFailure(): Boolean {
    val text = message.orEmpty()
    return text.contains("token has been revoked", ignoreCase = true) ||
        text.contains("token verification failed", ignoreCase = true) ||
        text.contains("malformed token", ignoreCase = true) ||
        text.contains("session hard cap exceeded", ignoreCase = true)
}

private data class EnrollmentCodePayload(
    val deviceId: String,
    val hybridEkB64: String,
    val hybridVkB64: String,
    val cycloPkB64: String,
    val cycloSkB64: String,
    val hybridSkB64: String,
    val transferKeyB64: String,
    val serverUrl: String
) {
    companion object {
        fun fromCode(code: String): EnrollmentCodePayload {
            val normalized = code.filterNot { it.isWhitespace() }
            val jsonText = String(Base64.getDecoder().decode(normalized), Charsets.UTF_8)
            val json = JSONObject(jsonText)
            return EnrollmentCodePayload(
                deviceId = json.getString("device_id"),
                hybridEkB64 = json.getString("hybrid_ek"),
                hybridVkB64 = json.getString("hybrid_vk"),
                cycloPkB64 = json.getString("cyclo_pk"),
                cycloSkB64 = json.getString("cyclo_sk"),
                hybridSkB64 = json.getString("hybrid_sk"),
                transferKeyB64 = json.getString("transfer_key"),
                serverUrl = json.optString("server_url")
            )
        }
    }
}
