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
    /// Epoch authenticated by the RMS supplied to `sync`.
    let keyEpoch: Int

    enum SyncError: LocalizedError {
        case crypto
        case rollback(serverClock: Int, lastSeen: Int)
        /// A chunk the server served could not be decrypted/verified against
        /// its sealed clock. Aborting beats proceeding with a truncated vault:
        /// the partial result would otherwise be pushed back and make the loss
        /// durable on every device.
        case unreadableChunk(chunkID: String)

        var errorDescription: String? {
            switch self {
            case .crypto:
                return "vault encryption failed"
            case let .rollback(serverClock, lastSeen):
                return "The server returned an older revision of this vault "
                    + "(clock \(serverClock), last seen \(lastSeen)). Refusing to "
                    + "overwrite newer local data. If you reset this vault on "
                    + "another device, sign out and back in here."
            case let .unreadableChunk(chunkID):
                return "The server returned a chunk that could not be decrypted "
                    + "(\(chunkID)). The sync was aborted rather than continue "
                    + "with incomplete vault data."
            }
        }
    }

    /// Highest chunk revision this device has accepted, kept in the App Group so
    /// the extension shares the same baseline.
    private static let lastSeenClockKey = "vela.sync.lastSeenLamport"
    /// Highest revision accepted *per chunk id* — JSON `{chunk_id: clock}`. A
    /// manifest-max check alone lets a hostile server roll back individual
    /// chunks as long as one other chunk stays ahead.
    private static let lastSeenByChunkKey = "vela.sync.lastSeenLamportByChunk"

    private static func sharedDefaults() -> UserDefaults {
        UserDefaults(suiteName: AppGroup.identifier) ?? .standard
    }

    /// Refuse a manifest that puts the whole vault behind the revision this
    /// device already synced.
    ///
    /// The sync server is untrusted, and replaying older ciphertexts used to be
    /// invisible: deleted credentials reappear and rotated passwords revert
    /// (audit C-2). Lamport clocks only ever increase, so a maximum below the
    /// recorded one is a rollback, not a stale read. A vault reset and
    /// re-created elsewhere legitimately restarts its clocks, which is why the
    /// message says how to clear the local baseline.
    private func rejectRollback(manifest: VelaClient.SyncManifest) throws {
        let defaults = Self.sharedDefaults()
        let lastSeen = defaults.integer(forKey: Self.lastSeenClockKey)
        guard lastSeen > 0 else { return }
        let serverMax = manifest.chunks.map { $0.lamport_clock }.max() ?? 0
        if serverMax < lastSeen {
            throw SyncError.rollback(serverClock: serverMax, lastSeen: lastSeen)
        }

        // Per-chunk baseline: one stale chunk must not hide behind a fresh one.
        // Legacy single-chunk layouts predate this tracking; only chunks we have
        // actually recorded are checked.
        guard let stored = defaults.string(forKey: Self.lastSeenByChunkKey),
              let recorded = try? JSONDecoder().decode([String: Int].self, from: Data(stored.utf8)),
              !recorded.isEmpty else { return }
        for chunk in manifest.chunks {
            if let seen = recorded[chunk.chunk_id], chunk.lamport_clock < seen {
                throw SyncError.rollback(serverClock: chunk.lamport_clock,
                                         lastSeen: seen)
            }
        }
    }

    private func recordSeenClock(_ clock: Int) {
        let defaults = Self.sharedDefaults()
        if clock > defaults.integer(forKey: Self.lastSeenClockKey) {
            defaults.set(clock, forKey: Self.lastSeenClockKey)
        }
    }

    /// Record every chunk's current revision after it has been read or written.
    private func recordSeenClocks(_ chunks: [VelaClient.ChunkMeta]) {
        guard !chunks.isEmpty else { return }
        recordWrittenChunks(chunks.map { (id: $0.chunk_id, clock: $0.lamport_clock) })
    }

    private func recordWrittenChunks(_ written: [(id: String, clock: Int)]) {
        guard !written.isEmpty else { return }
        let defaults = Self.sharedDefaults()
        var recorded: [String: Int] = [:]
        if let stored = defaults.string(forKey: Self.lastSeenByChunkKey),
           let existing = try? JSONDecoder().decode([String: Int].self, from: Data(stored.utf8)) {
            recorded = existing
        }
        for entry in written where entry.clock > (recorded[entry.id] ?? 0) {
            recorded[entry.id] = entry.clock
        }
        if let data = try? JSONEncoder().encode(recorded) {
            defaults.set(String(decoding: data, as: UTF8.self), forKey: Self.lastSeenByChunkKey)
        }
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
    /// merged vault back as `vault-data-*` chunks. Returns the merged store.
    @discardableResult
    func sync(rms: Data, localStore: VaultStore) async throws -> VaultStore {
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

        try rejectRollback(manifest: manifest)
        recordSeenClock(manifest.chunks.map { $0.lamport_clock }.max() ?? 0)

        var remoteJSON = ""
        for id in readIDs {
            let fetched = try await client.getChunk(id)
            guard let piece = VelaCoreFFI.decryptVaultChunk(
                rms: rms,
                chunkID: id,
                ciphertextBase64: fetched.ciphertextBase64,
                lamportClock: Int64(byID[id]?.lamport_clock ?? 0),
                keyEpoch: keyEpoch) else {
                // A failed decrypt used to be skipped silently; the truncated
                // merge was then pushed back, making the loss durable. Fail the
                // sync instead — the local vault stays intact and usable.
                throw SyncError.unreadableChunk(chunkID: id)
            }
            remoteJSON += piece
        }
        recordSeenClocks(manifest.chunks.filter { readIDs.contains($0.chunk_id) })
        var remoteStore = VaultStore(items: [])
        if !remoteJSON.isEmpty,
           let store = try? JSONDecoder().decode(VaultStore.self, from: Data(remoteJSON.utf8)) {
            remoteStore = store
        }

        // ── 2. Merge (tombstone-aware) and persist locally.
        let merged = VaultMerge.mergeStores(local: localStore, remote: remoteStore)
        try repo.save(merged, rms: rms)

        // ── 3. Push when the vault changed, or to migrate off a legacy layout.
        let alreadyDataLayout = !dataIDs.isEmpty
        if !alreadyDataLayout || merged != remoteStore {
            let full = String(decoding: try JSONEncoder().encode(merged), as: UTF8.self)
            let pieces = Self.splitUtf8(full, Self.chunkPlaintextSize)
            var lamport = manifest.chunks.map { $0.lamport_clock }.max() ?? 0
            var written: [(id: String, clock: Int)] = []

            for (index, piece) in pieces.enumerated() {
                let id = Self.dataChunkID(index)
                // The clock has to be settled *before* sealing: it is bound into
                // the ciphertext, so encrypting first and numbering afterwards
                // would produce a chunk nothing can read (audit C-2).
                let existing = byID[id]
                lamport = max(lamport, existing?.lamport_clock ?? 0) + 1
                guard let cipherB64 = VelaCoreFFI.encryptVaultChunk(
                    rms: rms, chunkID: id, vaultJSON: piece, lamportClock: lamport,
                    keyEpoch: keyEpoch) else {
                    throw SyncError.crypto
                }
                _ = try await client.putChunk(
                    id, ciphertextBase64: cipherB64, ifMatch: existing?.version ?? 0,
                    lamportClock: lamport, keyEpoch: keyEpoch)
                written.append((id: id, clock: lamport))
            }
            recordSeenClock(lamport)
            // Baseline what we wrote per chunk too — otherwise a rollback to
            // this push's *predecessor* would pass the recorded baseline.
            recordWrittenChunks(written)

            // Drop stale data chunks (vault shrank) and any legacy single chunks.
            for chunk in manifest.chunks {
                if chunk.chunk_id.hasPrefix(Self.dataPrefix) {
                    if let idx = Int(chunk.chunk_id.dropFirst(Self.dataPrefix.count)), idx >= pieces.count {
                        try? await client.deleteChunk(
                            chunk.chunk_id, ifMatch: chunk.version, keyEpoch: keyEpoch)
                    }
                } else if chunk.chunk_id == Self.legacyMainID || chunk.chunk_id == Self.legacyIOSID {
                    try? await client.deleteChunk(
                        chunk.chunk_id, ifMatch: chunk.version, keyEpoch: keyEpoch)
                }
            }
        }

        return merged
    }
}
