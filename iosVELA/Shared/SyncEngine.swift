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
    /// Server user id this device authenticated as. Part of the baseline
    /// namespace, so two accounts on one server never share counters.
    let accountID: String

    enum SyncError: LocalizedError {
        case crypto
        case rollback(serverClock: Int, lastSeen: Int)
        /// The manifest advertises an epoch this device has not authenticated.
        /// Mobile sync deliberately refuses to adopt automatically.
        case epochMismatch(serverEpoch: Int, localEpoch: Int)
        /// A chunk the server served could not be decrypted/verified against
        /// its sealed clock. Aborting beats proceeding with a truncated vault:
        /// the partial result would otherwise be pushed back and make the loss
        /// durable on every device.
        case unreadableChunk(chunkID: String)
        /// The persisted rollback baseline cannot be decoded. Continuing would
        /// silently drop rollback protection for every chunk, so sync refuses
        /// until the user performs a deliberate reset.
        case baselineCorrupt
        /// A pre-C-2 unsealed chunk cannot be admitted: it binds neither chunk
        /// id nor clock, so the rollback decision would be meaningless. This is
        /// distinct from a generic unreadable chunk because it needs the
        /// explicit migration path, not a retry.
        case legacyChunkNeedsMigration(chunkID: String)

        var errorDescription: String? {
            switch self {
            case .crypto:
                return "vault encryption failed"
            case let .rollback(serverClock, lastSeen):
                return "The server returned an older revision of this vault "
                    + "(clock \(serverClock), last seen \(lastSeen)). Refusing to "
                    + "overwrite newer local data. If you reset this vault on "
                    + "another device, sign out and back in here."
            case let .epochMismatch(serverEpoch, localEpoch):
                return "This device has vault key epoch \(localEpoch), but the sync "
                    + "manifest is for epoch \(serverEpoch); adopt the current vault "
                    + "key before syncing."
            case let .unreadableChunk(chunkID):
                return "The server returned a chunk that could not be decrypted "
                    + "(\(chunkID)). The sync was aborted rather than continue "
                    + "with incomplete vault data."
            case .baselineCorrupt:
                return "The saved sync rollback baseline is unreadable, so VELA "
                    + "cannot tell a replay from a new revision. Sign out and back "
                    + "in (or reset local security) to start a fresh baseline."
            case let .legacyChunkNeedsMigration(chunkID):
                return "The server returned a legacy unsealed vault chunk "
                    + "(\(chunkID)) that carries no chunk or revision binding, so "
                    + "VELA cannot detect a rollback. Sync was refused. Re-seal the "
                    + "vault through the explicit migration path on a trusted "
                    + "device before syncing again."
            }
        }
    }

    // ── Baselines ───────────────────────────────────────────────────────────
    //
    // Every recorded clock is namespaced by the sync context
    // (`server ‖ account ‖ epoch`). Switching servers/accounts, or adopting a
    // rotated epoch, therefore starts a genuinely fresh counter instead of
    // inheriting (or destroying) another context's baseline — and switching
    // back preserves the baseline that context had recorded.
    //
    // The previous un-namespaced keys cannot be attributed to a context after
    // the fact, so they are ignored (first contact is explicit) and removed on
    // the deliberate reset below rather than guessed into the current context.

    private static let baselineByContextKey = "vela.sync.baselinesByContext.v2"
    private static let manifestLamportByContextKey = "vela.sync.manifestLamportByContext.v2"
    private static let legacyLastSeenClockKey = "vela.sync.lastSeenLamport"
    private static let legacyLastSeenByChunkKey = "vela.sync.lastSeenLamportByChunk"

    /// Serializes this process's read-modify-write cycles, so two engines (a
    /// user-triggered sync and the periodic one) cannot lose each other's
    /// advances: every update re-reads the latest committed JSON under the lock.
    ///
    /// This is a **single-syncing-writer-process** guarantee only. Today the
    /// app's `AccountViewModel` is the only sync writer; the AutoFill extension
    /// reads the vault but does not run sync. App Group `UserDefaults` has no
    /// cross-process transaction, so if a second process ever writes these
    /// whole-map keys, its get/set can interleave with this one and:
    ///
    /// - lower a recorded chunk or manifest clock (a stale map replaces a newer
    ///   one), and
    /// - erase baselines for other chunks or sync contexts that were added
    ///   between its read and write.
    ///
    /// No "never lower" or "re-admit once" property is claimed under that
    /// unsupported second-writer configuration. Cross-process safety requires
    /// an App Group file lock or a transactional store, neither of which is
    /// implemented here.
    private static let baselineLock = NSLock()

    private static func sharedDefaults() -> UserDefaults {
        UserDefaults(suiteName: AppGroup.identifier) ?? .standard
    }

    private static func withBaselineLock<T>(_ body: () throws -> T) rethrows -> T {
        baselineLock.lock()
        defer { baselineLock.unlock() }
        return try body()
    }

    /// Internal so tests can build the exact persisted namespace.
    var baselineContext: String {
        let url = client.baseURL
        let scheme = (url.scheme ?? "https").lowercased()
        let host = (url.host ?? "").lowercased()
        let port = url.port.map { ":\($0)" } ?? ""
        var path = url.path
        while path.hasSuffix("/") { path.removeLast() }
        return ["\(scheme)://\(host)\(port)\(path)", accountID, String(keyEpoch)]
            .joined(separator: "\u{1F}")
    }

    private static func decodeChunkBaselines() throws -> [String: [String: Int]] {
        let defaults = sharedDefaults()
        guard let stored = defaults.string(forKey: baselineByContextKey), !stored.isEmpty else {
            return [:]
        }
        guard let data = stored.data(using: .utf8),
              let decoded = try? JSONDecoder().decode([String: [String: Int]].self, from: data) else {
            throw SyncError.baselineCorrupt
        }
        return decoded
    }

    private static func decodeManifestBaselines() throws -> [String: Int] {
        let defaults = sharedDefaults()
        guard let stored = defaults.string(forKey: manifestLamportByContextKey), !stored.isEmpty else {
            return [:]
        }
        guard let data = stored.data(using: .utf8),
              let decoded = try? JSONDecoder().decode([String: Int].self, from: data) else {
            throw SyncError.baselineCorrupt
        }
        return decoded
    }

    /// Last revision this device admitted for a specific chunk **in this
    /// context**, if it has recorded one. `nil` is first contact and is passed
    /// to the native gate explicitly rather than being turned into clock 0.
    func recordedSeenClock(for chunkID: String) throws -> Int64? {
        guard let recorded = try Self.decodeChunkBaselines()[baselineContext]?[chunkID] else {
            return nil
        }
        return Int64(recorded)
    }

    /// Highest manifest clock this context has seen, if any.
    func recordedManifestClock() throws -> Int? {
        try Self.decodeManifestBaselines()[baselineContext]
    }

    /// Commit baselines for this context. Callers must invoke this only after
    /// the bytes are durably persisted locally; a failed or partial batch must
    /// record nothing, or a retry would look like a rollback. Merges (max),
    /// never replaces, so a stale writer **within this process** cannot lower a
    /// baseline. This is not a cross-process guarantee; see `baselineLock`.
    func recordAdmitted(chunks: [(id: String, clock: Int)], manifestClock: Int) throws {
        guard !chunks.isEmpty || manifestClock > 0 else { return }
        try Self.withBaselineLock {
            let defaults = Self.sharedDefaults()
            if !chunks.isEmpty {
                var byContext = try Self.decodeChunkBaselines()
                var recorded = byContext[baselineContext] ?? [:]
                for entry in chunks where entry.clock > (recorded[entry.id] ?? 0) {
                    recorded[entry.id] = entry.clock
                }
                if !recorded.isEmpty {
                    byContext[baselineContext] = recorded
                    let data = try JSONEncoder().encode(byContext)
                    defaults.set(String(decoding: data, as: UTF8.self),
                                 forKey: Self.baselineByContextKey)
                }
            }
            if manifestClock > 0 {
                var byContext = try Self.decodeManifestBaselines()
                byContext[baselineContext] =
                    max(byContext[baselineContext] ?? 0, manifestClock)
                let data = try JSONEncoder().encode(byContext)
                defaults.set(String(decoding: data, as: UTF8.self),
                             forKey: Self.manifestLamportByContextKey)
            }
        }
    }

    /// Deliberate sign-out / local-security reset only. This is the recovery
    /// action the rollback message points at; routine server changes and epoch
    /// adoption must never call it.
    ///
    /// Today each install holds one account, so clearing every context is the
    /// same as clearing the signing-out account's contexts. If multi-account
    /// support lands, sign-out must clear only the departing account's
    /// namespace; otherwise signing out one account would erase another
    /// account's rollback floors.
    static func clearBaselines() {
        withBaselineLock {
            let defaults = sharedDefaults()
            defaults.removeObject(forKey: baselineByContextKey)
            defaults.removeObject(forKey: manifestLamportByContextKey)
            defaults.removeObject(forKey: legacyLastSeenClockKey)
            defaults.removeObject(forKey: legacyLastSeenByChunkKey)
        }
    }

    /// Refuse a manifest that puts the whole vault behind the revision this
    /// device already synced in this context.
    ///
    /// The sync server is untrusted, and replaying older ciphertexts used to be
    /// invisible: deleted credentials reappear and rotated passwords revert
    /// (audit C-2). Lamport clocks only ever increase inside a context, so a
    /// maximum below the recorded one is a rollback, not a stale read.
    private func rejectRollback(manifest: VelaClient.SyncManifest) throws {
        let lastSeen = try recordedManifestClock() ?? 0
        let serverMax = manifest.chunks.map { $0.lamport_clock }.max() ?? 0
        if lastSeen > 0, serverMax < lastSeen {
            throw SyncError.rollback(serverClock: serverMax, lastSeen: lastSeen)
        }

        // Per-chunk baseline: one stale chunk must not hide behind a fresh one.
        // Legacy single-chunk layouts predate this tracking; only chunks this
        // context actually recorded are checked.
        let recorded = try Self.decodeChunkBaselines()[baselineContext] ?? [:]
        for chunk in manifest.chunks {
            if let seen = recorded[chunk.chunk_id], chunk.lamport_clock < seen {
                throw SyncError.rollback(serverClock: chunk.lamport_clock, lastSeen: seen)
            }
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

        // The manifest epoch is a server claim. It must equal the epoch this
        // device authenticated before any chunk is read; the native admission
        // gate repeats the integer comparison on every chunk.
        guard manifest.epoch >= 1, manifest.epoch == keyEpoch else {
            throw SyncError.epochMismatch(
                serverEpoch: manifest.epoch, localEpoch: keyEpoch)
        }
        try rejectRollback(manifest: manifest)

        var remoteJSON = ""
        var admitted: [(id: String, clock: Int)] = []
        for id in readIDs {
            let fetched = try await client.getChunk(id)
            let serverClock = Int64(byID[id]?.lamport_clock ?? 0)
            let piece: VelaCoreFFI.AdmittedChunk
            do {
                piece = try VelaCoreFFI.decryptVaultChunkAdmittedOrThrow(
                    rms: rms,
                    chunkID: id,
                    ciphertextBase64: fetched.ciphertextBase64,
                    lamportClock: serverClock,
                    keyEpoch: manifest.epoch,
                    localKeyEpoch: keyEpoch,
                    lastSeenLamport: try recordedSeenClock(for: id))
            } catch VelaCoreFFI.AdmissionError.refused(let reason) where reason.contains("legacy unsealed chunk ciphertext cannot be admitted") {
                // The bridge still refuses admission (the gate is unchanged);
                // only the caller's error becomes actionable: this needs the
                // explicit migration path, not a sync retry.
                throw SyncError.legacyChunkNeedsMigration(chunkID: id)
            } catch {
                // A failed decrypt or a refused rollback used to be skipped
                // silently; the truncated merge was then pushed back, making
                // the loss durable. Fail the sync instead — the local vault
                // stays intact and usable.
                throw SyncError.unreadableChunk(chunkID: id)
            }
            remoteJSON += piece.vaultJSON
            admitted.append((id: id, clock: Int(piece.lamportClock)))
        }
        var remoteStore = VaultStore(items: [])
        if !remoteJSON.isEmpty {
            remoteStore = try JSONDecoder().decode(VaultStore.self, from: Data(remoteJSON.utf8))
        }

        // ── 2. Merge (tombstone-aware) and persist locally.
        let merged = try VaultMerge.mergeStores(local: localStore, remote: remoteStore)
        try repo.save(merged, rms: rms)

        // Only after the decoded bytes are durably in the local vault do we
        // baseline the revisions the verified gate admitted. A decode/merge/
        // persist failure above therefore records nothing.
        try recordAdmitted(chunks: admitted, manifestClock: admitted.map { $0.clock }.max() ?? 0)

        // ── 3. Push when the vault changed, or to migrate off a legacy layout.
        let alreadyDataLayout = !dataIDs.isEmpty
        if !alreadyDataLayout || merged != remoteStore {
            // A schema-2 vault (folders, custom fields) first raises the
            // account floor so older clients cannot overwrite it.
            if merged.schemaVersion >= 2 { try await client.activateRichSchema() }
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
            // Baseline what we wrote per chunk too — otherwise a rollback to
            // this push's *predecessor* would pass the recorded baseline.
            try recordAdmitted(chunks: written, manifestClock: lamport)

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
