import Foundation

/// Pushes/pulls the encrypted vault via the chunk protocol, using the **same
/// chunk scheme as the Android and desktop clients** so all platforms sync the
/// same vault: the serialized vault is split across `vault-data-NNNNNN` chunks
/// (≤ 1 MiB − 4 KiB each), each sealed by the core under the RMS. `vault-main`
/// (legacy) and `vault` (the old iOS single chunk) are read for migration and
/// deleted on the next push. The server only ever holds opaque ciphertext.
struct SyncEngine {
    static let dataPrefix = "vault-data-"
    static let legacyMainID = "vault-main"
    static let legacyIOSID = "vault"
    static let chunkPlaintextSize = 1024 * 1024 - 4096

    let client: VelaClient
    let repo: VaultRepository

    enum SyncError: LocalizedError {
        case crypto
        var errorDescription: String? { "vault encryption failed" }
    }

    static func dataChunkID(_ index: Int) -> String {
        dataPrefix + String(format: "%06d", index)
    }

    /// Split a string into pieces of at most `maxBytes` UTF-8 bytes, never cutting
    /// a character (matches Android `splitUtf8Chunks`).
    static func splitUtf8(_ value: String, _ maxBytes: Int) -> [String] {
        var out: [String] = []
        var current = ""
        var currentBytes = 0
        for ch in value {
            let bytes = String(ch).utf8.count
            if !current.isEmpty && currentBytes + bytes > maxBytes {
                out.append(current)
                current = ""
                currentBytes = 0
            }
            current.append(ch)
            currentBytes += bytes
        }
        if !current.isEmpty || out.isEmpty { out.append(current) }
        return out
    }

    /// Two-way sync: pull remote chunks, merge with local, persist, and push the
    /// merged vault back as `vault-data-*` chunks. Returns the merged item list.
    @discardableResult
    func sync(rms: Data, localItems: [VaultItem]) async throws -> [VaultItem] {
        let rmsB64 = rms.base64EncodedString()

        let manifest = try await client.syncManifest()
        let byID = Dictionary(manifest.chunks.map { ($0.chunk_id, $0) }, uniquingKeysWith: { a, _ in a })

        // ── 1. Read remote: prefer vault-data-*, else legacy main, else old iOS.
        let dataIDs = manifest.chunks.map { $0.chunk_id }.filter { $0.hasPrefix(Self.dataPrefix) }.sorted()
        let readIDs: [String]
        if !dataIDs.isEmpty {
            readIDs = dataIDs
        } else if byID[Self.legacyMainID] != nil {
            readIDs = [Self.legacyMainID]
        } else if byID[Self.legacyIOSID] != nil {
            readIDs = [Self.legacyIOSID]
        } else {
            readIDs = []
        }

        var remoteJSON = ""
        for id in readIDs {
            let fetched = try await client.getChunk(id)
            if let piece = VelaCoreFFI.decryptVaultChunk(
                rmsBase64: rmsB64, chunkID: id, ciphertextBase64: fetched.ciphertextBase64) {
                remoteJSON += piece
            }
        }
        var remoteItems: [VaultItem] = []
        if !remoteJSON.isEmpty,
           let store = try? JSONDecoder().decode(VaultStore.self, from: Data(remoteJSON.utf8)) {
            remoteItems = store.items
        }

        // ── 2. Merge and persist locally.
        let merged = VaultMerge.merge(local: localItems, remote: remoteItems)
        try repo.save(VaultStore(items: merged), rms: rms)

        // ── 3. Push when the vault changed, or to migrate off a legacy layout.
        let alreadyDataLayout = !dataIDs.isEmpty
        if !alreadyDataLayout || merged != remoteItems {
            let full = String(decoding: try JSONEncoder().encode(VaultStore(items: merged)), as: UTF8.self)
            let pieces = Self.splitUtf8(full, Self.chunkPlaintextSize)
            var lamport = manifest.chunks.map { $0.lamport_clock }.max() ?? 0

            for (index, piece) in pieces.enumerated() {
                let id = Self.dataChunkID(index)
                guard let cipherB64 = VelaCoreFFI.encryptVaultChunk(
                    rmsBase64: rmsB64, chunkID: id, vaultJSON: piece) else {
                    throw SyncError.crypto
                }
                let existing = byID[id]
                lamport = max(lamport, existing?.lamport_clock ?? 0) + 1
                _ = try await client.putChunk(
                    id, ciphertextBase64: cipherB64, ifMatch: existing?.version ?? 0, lamportClock: lamport)
            }

            // Drop stale data chunks (vault shrank) and any legacy single chunks.
            for chunk in manifest.chunks {
                if chunk.chunk_id.hasPrefix(Self.dataPrefix) {
                    if let idx = Int(chunk.chunk_id.dropFirst(Self.dataPrefix.count)), idx >= pieces.count {
                        try? await client.deleteChunk(chunk.chunk_id, ifMatch: chunk.version)
                    }
                } else if chunk.chunk_id == Self.legacyMainID || chunk.chunk_id == Self.legacyIOSID {
                    try? await client.deleteChunk(chunk.chunk_id, ifMatch: chunk.version)
                }
            }
        }

        return merged
    }
}
