import Foundation

/// Pushes/pulls the encrypted vault to the server via the chunk protocol. Phase 4
/// stores the whole vault as a single `vault` chunk (per-item chunking is a later
/// refinement); the blob is sealed by the core under the RMS, so the server only
/// ever holds opaque ciphertext.
struct SyncEngine {
    static let chunkID = "vault"

    let client: VelaClient
    let repo: VaultRepository

    enum SyncError: LocalizedError {
        case crypto
        var errorDescription: String? { "vault encryption failed" }
    }

    /// Two-way sync: pull the remote chunk, merge with local, persist, and push
    /// the merged result. Returns the merged item list.
    @discardableResult
    func sync(rms: Data, localItems: [VaultItem]) async throws -> [VaultItem] {
        let rmsB64 = rms.base64EncodedString()

        // 1. Find the remote chunk version (0 if absent).
        let manifest = try await client.syncManifest()
        let meta = manifest.chunks.first { $0.chunk_id == Self.chunkID }

        // 2. Pull + decrypt remote items, if any.
        var remoteItems: [VaultItem] = []
        if meta != nil {
            let fetched = try await client.getChunk(Self.chunkID)
            if let json = VelaCoreFFI.decryptVaultChunk(
                rmsBase64: rmsB64, chunkID: Self.chunkID, ciphertextBase64: fetched.ciphertextBase64),
               let store = try? JSONDecoder().decode(VaultStore.self, from: Data(json.utf8)) {
                remoteItems = store.items
            }
        }

        // 3. Merge and persist locally.
        let merged = VaultMerge.merge(local: localItems, remote: remoteItems)
        try repo.save(VaultStore(items: merged), rms: rms)

        // 4. Push the merged blob (skip if the remote already equals merged).
        if meta == nil || merged != remoteItems {
            let vaultJSON = String(decoding: try JSONEncoder().encode(VaultStore(items: merged)), as: UTF8.self)
            guard let cipherB64 = VelaCoreFFI.encryptVaultChunk(
                rmsBase64: rmsB64, chunkID: Self.chunkID, vaultJSON: vaultJSON) else {
                throw SyncError.crypto
            }
            let ifMatch = meta?.version ?? 0
            let lamport = (meta?.lamport_clock ?? 0) + 1
            _ = try await client.putChunk(Self.chunkID, ciphertextBase64: cipherB64, ifMatch: ifMatch, lamportClock: lamport)
        }

        return merged
    }
}
