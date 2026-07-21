package com.vela.android.sync

import android.content.Context
import com.vela.android.core.LocalVaultRepository
import com.vela.android.core.NativeVelaCore
import com.vela.android.core.Tombstone
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultJson
import com.vela.android.core.VaultStore
import com.vela.android.security.SecureVaultManager
import com.vela.android.security.WebAuthnCeremony
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    private val context: Context,
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
        val client = AndroidVelaApiClient(settings.serverUrl, context)
        val token = authenticatedToken(client, settings.bearerToken)
        if (token != settings.bearerToken) {
            settingsStore.updateBearerToken(token)
        }
        ensureShareKey(client, token)
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
        val payload = EnrollmentCodePayload.fromCode(serverUrl, enrollmentCode)
        val effectiveServerUrl = serverUrl.ifBlank { payload.serverUrl }
        if (effectiveServerUrl.isBlank()) {
            error("Enrollment requires a server URL")
        }

        updateServer(effectiveServerUrl, "")
        val client = AndroidVelaApiClient(settingsStore.settings.value.serverUrl, context)
        identityStore.save(
            ServerIdentity(
                userId = null,
                deviceId = payload.deviceId,
                hybridEkB64 = payload.hybridEkB64,
                hybridVkB64 = payload.hybridVkB64,
                hybridSkB64 = payload.hybridSkB64
            )
        )

        val token = authenticateOrRegister(client)
        val capsule = client.getCapsule(token)
        capsule.newToken?.let { updateServer(settingsStore.settings.value.serverUrl, it) }
        return NativeVelaCore.decryptRmsCapsule(payload.transferKeyB64, capsule.capsuleB64)
            ?: error("Native VELA bridge could not decrypt enrollment capsule")
    }

    /// Split the RMS into recovery shares (SPEC.md §4.3), register a WebAuthn
    /// recovery passkey via `performRegistration` (a physical security key,
    /// independent of this device's own biometrics — see `WebAuthnCeremony`),
    /// then deliver Share 2 to the server gated behind that passkey. Returns
    /// Share 1 (cloud) and Share 3 (trusted contact) for the caller to
    /// distribute. `performRegistration` is supplied by the caller so this
    /// sync layer doesn't need an Activity context for the Credential Manager
    /// UI — it receives the already-unwrapped creation options and returns
    /// the attestation response JSON.
    suspend fun setupRecovery(performRegistration: suspend (JSONObject) -> JSONObject): List<String> {
        check(security.session.value.unlocked) { "Unlock VELA before setting up recovery" }
        val rms = security.currentRmsCopy() ?: error("No unlocked vault key")
        val shares = try {
            NativeVelaCore.splitRecovery(rms, threshold = 2, n = 3)
                ?: error("Native VELA bridge could not split recovery shares")
        } finally {
            rms.fill(0)
        }
        check(shares.size == 3) { "Unexpected share count from split" }

        val settings = settingsStore.settings.value
        require(settings.serverUrl.isNotBlank()) { "Server URL is not configured" }
        val client = AndroidVelaApiClient(settings.serverUrl, context)
        var token = authenticatedToken(client, settings.bearerToken)
        if (token != settings.bearerToken) settingsStore.updateBearerToken(token)

        val (startJson, tokenAfterStart) = client.startRecoveryWebAuthnRegistration(token)
        tokenAfterStart?.let { token = it; settingsStore.updateBearerToken(it) }

        val requestOptions = WebAuthnCeremony.unwrapPublicKey(startJson)
        val credentialJson = performRegistration(requestOptions)

        val (registered, tokenAfterFinish) = client.finishRecoveryWebAuthnRegistration(token, credentialJson)
        tokenAfterFinish?.let { token = it; settingsStore.updateBearerToken(it) }
        check(registered) { "Recovery passkey registration was not confirmed by the server" }

        client.putRecoveryShare(token, shares[1])?.let { settingsStore.updateBearerToken(it) }

        // Share 1 (cloud) and Share 3 (trusted contact) are handed back to
        // the caller to distribute — there is no cloud-storage integration
        // yet, so both are shown as plain text to copy/store manually.
        return listOf(shares[0], shares[2])
    }

    /// Reconstruct the RMS on a brand-new device from Share 1 (pasted from
    /// wherever the user stored it) + Share 2 (released by the server after
    /// the WebAuthn assertion run by `performAssertion`), then register this
    /// device against the existing account — mirrors `enrollWithCode`'s
    /// bootstrap sequence, minus the RMS-capsule step since the RMS is
    /// already in hand once the two shares are combined. Returns the
    /// reconstructed RMS for the caller to adopt via
    /// `SecureVaultManager.adoptRms` and protect locally.
    suspend fun recoverAccount(
        serverUrl: String,
        userId: String,
        share1B64: String,
        deviceName: String?,
        performAssertion: suspend (JSONObject) -> JSONObject
    ): ByteArray {
        val effectiveServerUrl = serverUrl.ifBlank { settingsStore.settings.value.serverUrl }
        require(effectiveServerUrl.isNotBlank()) { "Recovery requires a server URL" }
        updateServer(effectiveServerUrl, "")
        val client = AndroidVelaApiClient(effectiveServerUrl, context)

        val initiate = client.initiateRecovery(userId)
        val requestOptions = WebAuthnCeremony.unwrapPublicKey(initiate.publicKeyJson)
        val credentialJson = performAssertion(requestOptions)
        val recovered = client.recoverAccount(userId, initiate.recoveryId, credentialJson)

        val rms = NativeVelaCore.combineRecovery(listOf(share1B64, recovered.shareB64))
            ?: error("Native VELA bridge could not reconstruct the vault key")

        val identityJson = NativeVelaCore.generateServerIdentityJson()
            ?: error("Native VELA bridge cannot generate device identity")
        val identity = JSONObject(identityJson)
        val hybridEk = identity.getString("hybrid_ek_b64")
        val hybridVk = identity.getString("hybrid_vk_b64")
        val hybridSk = identity.getString("hybrid_sk_b64")

        val deviceId = client.enrollDeviceViaRecovery(userId, recovered.recoveryGrant, hybridEk, hybridVk, deviceName)

        identityStore.save(
            ServerIdentity(
                userId = userId,
                deviceId = deviceId,
                hybridEkB64 = hybridEk,
                hybridVkB64 = hybridVk,
                hybridSkB64 = hybridSk,
                shareEkB64 = identity.optString("share_ek_b64"),
                shareDkB64 = identity.optString("share_dk_b64")
            )
        )

        val token = authenticateOrRegister(client)
        updateServer(effectiveServerUrl, token)
        return rms
    }

    // suspend, not a runBlocking-wrapped plain fun: the previous version
    // called runBlocking(Dispatchers.IO) from inside a function that's
    // itself always invoked from a coroutine already running on
    // Dispatchers.IO (see MainActivity), which blocks one of that shared,
    // size-limited dispatcher's threads for the whole sync — under load,
    // enough of these nested blocking calls can exhaust the pool. Making
    // this a genuine suspend fun lets it cooperate with the dispatcher
    // instead of blocking a thread out of it.
    suspend fun syncNow(): SyncState {
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

    suspend fun resolveConflictUseRemote(): SyncState {
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
            val client = AndroidVelaApiClient(settings.serverUrl, context)
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

    suspend fun resolveConflictUseLocal(): SyncState {
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
            val client = AndroidVelaApiClient(settings.serverUrl, context)
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

    private suspend fun syncUnlocked(settings: SyncSettings, rms: ByteArray): SyncState {
        val client = AndroidVelaApiClient(settings.serverUrl, context)
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

    /// Backfill a share keypair for identities created before sharing existed.
    /// Generates the keypair locally, persists it, and registers the public half
    /// with the server. A no-op once the identity already has a share key.
    private fun ensureShareKey(client: AndroidVelaApiClient, token: String) {
        val identity = identityStore.load() ?: return
        if (identity.shareEkB64.isNotBlank()) return
        val json = com.vela.android.core.NativeVelaCore.generateShareKeypairJson() ?: return
        val parsed = org.json.JSONObject(json)
        val shareEk = parsed.optString("share_ek_b64")
        val shareDk = parsed.optString("share_dk_b64")
        if (shareEk.isBlank() || shareDk.isBlank()) return
        runCatching {
            client.putMyShareEk(token, shareEk)
            identityStore.save(identity.copy(shareEkB64 = shareEk, shareDkB64 = shareDk))
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
        val signatureJson = com.vela.android.core.NativeVelaCore.createAuthSignatureJson(
            hybridSkB64 = identity.hybridSkB64,
            challengeB64 = challenge.challengeB64,
            deviceId = deviceId
        ) ?: error("Native VELA bridge cannot create server auth signature")
        val signature = org.json.JSONObject(signatureJson)
        val verified = client.verifySignature(
            deviceId = deviceId,
            challengeB64 = challenge.challengeB64,
            signature = signature.getString("signature")
        )
        identityStore.save(identity.copy(userId = verified.userId))
        return verified.token
    }

    private fun authenticatedToken(client: AndroidVelaApiClient, cachedToken: String): String =
        cachedToken.ifBlank { authenticateOrRegister(client) }

    private suspend fun downloadRemoteVault(
        client: AndroidVelaApiClient,
        startToken: String,
        rms: ByteArray,
        chunkIds: List<String>,
        manifest: SyncManifest
    ): RemoteVaultDownload = coroutineScope {
        var tokenRef = startToken
        val tokenMutex = Mutex()

        val results = chunkIds.mapIndexed { index, chunkId ->
            async {
                val token = tokenMutex.withLock { tokenRef }
                val downloaded = client.getChunk(token, chunkId)
                downloaded.newToken?.let { newToken ->
                    tokenMutex.withLock { tokenRef = newToken }
                }
                val json = NativeVelaCore.decryptVaultChunkJson(rms, chunkId, downloaded.ciphertext)
                    ?: error("Native VELA bridge could not decrypt server vault chunk $chunkId")
                Triple(index, json, Pair(
                    chunkId,
                    manifest.chunks.firstOrNull { it.chunkId == chunkId }
                ))
            }
        }.awaitAll()

        val orderedResults = results.sortedBy { it.first }
        val decodedJson = StringBuilder()
        var maxVersion = 0L
        var maxLamport = 0L
        for ((_, json, chunkMeta) in orderedResults) {
            decodedJson.append(json)
            val (_, entry) = chunkMeta
            if (entry != null) {
                maxVersion = maxOf(maxVersion, entry.version)
                maxLamport = maxOf(maxLamport, entry.lamportClock)
            }
        }

        val token = tokenMutex.withLock { tokenRef }
        val remoteVault = VaultJson.decode(decodedJson.toString().toByteArray(Charsets.UTF_8))
        RemoteVaultDownload(
            vault = remoteVault,
            token = token,
            version = maxVersion,
            lamportClock = maxLamport
        )
    }

    private suspend fun uploadVaultChunks(
        client: AndroidVelaApiClient,
        startToken: String,
        rms: ByteArray,
        manifest: SyncManifest,
        baseLamport: Long
    ): RemoteVaultUpload = coroutineScope {
        val chunks = splitUtf8Chunks(VaultJson.encode(vault.snapshot()).toString(Charsets.UTF_8))
        val manifestById = manifest.chunks.associateBy { it.chunkId }

        var lamport = baseLamport
        val lamportAssignments = chunks.mapIndexed { index, _ ->
            val chunkId = vaultChunkId(index)
            val previousLamport = manifestById[chunkId]?.lamportClock ?: 0
            lamport = maxOf(lamport, previousLamport) + 1
            lamport
        }

        var tokenRef = startToken
        val tokenMutex = Mutex()

        val results = chunks.mapIndexed { index, chunk ->
            val chunkId = vaultChunkId(index)
            val chunkLamport = lamportAssignments[index]
            val remote = manifestById[chunkId]
            val ciphertextB64 = NativeVelaCore.encryptVaultChunkJson(rms, chunkId, chunk)
                ?: error("Native VELA bridge is required for server sync")
            async {
                val token = tokenMutex.withLock { tokenRef }
                val uploaded = client.putChunk(
                    token = token,
                    chunkId = chunkId,
                    ifMatch = remote?.version ?: 0,
                    lamportClock = chunkLamport,
                    ciphertext = Base64.getDecoder().decode(ciphertextB64)
                )
                uploaded.newToken?.let { newToken ->
                    tokenMutex.withLock { tokenRef = newToken }
                }
                if (index == 0) uploaded.version else null
            }
        }.awaitAll()

        val firstChunkVersion = results.firstOrNull() ?: 0L

        val token = tokenMutex.withLock { tokenRef }

        val staleChunks = manifest.chunks
            .filter { it.chunkId.startsWith(VAULT_DATA_PREFIX) }
            .mapNotNull { entry ->
                val idx = entry.chunkId.removePrefix(VAULT_DATA_PREFIX).toIntOrNull()
                if (idx != null && idx >= chunks.size) entry.chunkId to entry.version else null
            }

        if (staleChunks.isNotEmpty()) {
            var deleteTokenRef = token
            val deleteTokenMutex = Mutex()
            staleChunks.map { (chunkId, version) ->
                async {
                    val t = deleteTokenMutex.withLock { deleteTokenRef }
                    runCatching { client.deleteChunk(t, chunkId, version) }
                        .getOrNull()?.let { newToken ->
                            deleteTokenMutex.withLock { deleteTokenRef = newToken }
                        }
                }
            }.awaitAll()
            tokenMutex.withLock { tokenRef = deleteTokenMutex.withLock { deleteTokenRef } }
        }

        val finalToken = tokenMutex.withLock { tokenRef }
        val finalLamport = lamportAssignments.lastOrNull() ?: baseLamport

        RemoteVaultUpload(
            token = finalToken,
            version = firstChunkVersion,
            lamportClock = (finalLamport).coerceAtLeast(baseLamport)
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
    val hybridSkB64: String,
    val transferKeyB64: String,
    val serverUrl: String
) {
    companion object {
        private const val V2_PREFIX = "VELA-ENROLL:v2:"

        fun fromCode(serverUrlOverride: String, code: String): EnrollmentCodePayload {
            val normalized = code.filterNot { it.isWhitespace() }
            val jsonText = if (normalized.startsWith(V2_PREFIX)) {
                resolveV2Package(serverUrlOverride, normalized)
            } else {
                String(Base64.getDecoder().decode(normalized), Charsets.UTF_8)
            }
            val json = JSONObject(jsonText)
            return EnrollmentCodePayload(
                deviceId = json.getString("device_id"),
                hybridEkB64 = json.getString("hybrid_ek"),
                hybridVkB64 = json.getString("hybrid_vk"),
                hybridSkB64 = json.getString("hybrid_sk"),
                transferKeyB64 = json.getString("transfer_key"),
                serverUrl = json.optString("server_url")
            )
        }

        private fun resolveV2Package(serverUrlOverride: String, code: String): String {
            val locatorText = String(
                Base64.getUrlDecoder().decode(code.removePrefix(V2_PREFIX)),
                Charsets.UTF_8
            )
            val locator = JSONObject(locatorText)
            if (locator.optInt("v") != 2) {
                error("Unsupported enrollment code version")
            }
            val packageServerUrl = serverUrlOverride.ifBlank { locator.getString("u") }
            if (packageServerUrl.isBlank()) {
                error("Enrollment requires a server URL")
            }

            val client = AndroidVelaApiClient(packageServerUrl, null)
            val packageResponse = client.getEnrollmentPackage(locator.getString("t"))
            val packageKey = Base64.getUrlDecoder().decode(locator.getString("k"))
            val ciphertext = Base64.getUrlDecoder().decode(packageResponse.ciphertext)
            return NativeVelaCore.decryptEnrollmentPackage(packageKey, ciphertext)
                ?: error("Native VELA bridge could not decrypt enrollment package")
        }
    }
}
