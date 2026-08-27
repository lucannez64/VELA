import Foundation

/// Stores/retrieves Share 1 of the recovery split (SPEC.md §4.3) via iCloud
/// Key-Value Storage. The blob is a few dozen bytes — well under the 1 MB /
/// 1024-key ubiquitous KVS limit — so this needs no CloudKit container or
/// Drive-style file management, just the iCloud (Key-Value storage)
/// capability enabled for the app (see `iosVELA.entitlements`).
enum CloudRecoveryBackup {
    private static let legacyStorageKey = "vela.recovery.share1.v1"
    private static let storageKeyPrefix = "vela.recovery.share1.v2."
    private static let candidateKeyPrefix = "vela.recovery.share1.v3.candidate."
    private static let activeKeyPrefix = "vela.recovery.share1.v3.active."

    struct Backup: Equatable {
        let userID: String
        let shareBase64: String
        let keyEpoch: Int
        let splitID: String?
    }

    private struct Envelope: Codable {
        let version: Int
        let userID: String
        let shareB64: String
        let keyEpoch: Int?
        let splitID: String?
        let status: String?

        enum CodingKeys: String, CodingKey {
            case version
            case userID = "user_id"
            case shareB64 = "share_b64"
            case keyEpoch = "key_epoch"
            case splitID = "split_id"
            case status
        }

        var backup: Backup? {
            let epoch = keyEpoch ?? (version == 1 ? 1 : 0)
            guard epoch >= 1 else { return nil }
            guard status != "candidate" else { return nil }
            guard (1...3).contains(version) else { return nil }
            var canonicalSplitID: String? = nil
            if let splitID {
                guard let uuid = UUID(uuidString: splitID) else { return nil }
                canonicalSplitID = uuid.uuidString.lowercased()
            }
            if version == 3 {
                guard status == "active" else { return nil }
                guard canonicalSplitID != nil else { return nil }
            }
            return Backup(
                userID: userID, shareBase64: shareB64,
                keyEpoch: epoch, splitID: canonicalSplitID)
        }
    }

    /// Backs up Share 1 under an epoch-specific key. A delayed epoch-N device
    /// therefore cannot overwrite the epoch-N+1 envelope in the shared iCloud
    /// store; readers select the highest valid epoch for the account.
    static func uploadCandidate(
        userID: String, shareBase64: String, keyEpoch: Int, splitID: String
    ) throws {
        guard let splitID = UUID(uuidString: splitID)?.uuidString.lowercased() else {
            throw BackupError.invalidSplitID
        }
        try upload(
            userID: userID, shareBase64: shareBase64, keyEpoch: keyEpoch,
            splitID: splitID, status: "candidate",
            key: "\(candidateKeyPrefix)\(userID).\(keyEpoch).\(splitID)")
    }

    /// Re-publishes Share 1 as the active envelope under an epoch-scoped key
    /// (`v3.active.<userID>.<epoch>`), so a delayed older-epoch promotion
    /// cannot overwrite a newer epoch's envelope. Readers select the highest
    /// valid epoch for the account via `newest(in:)`. Superseded artifacts —
    /// the legacy unprefixed v1 key, v3 single-user active keys from before
    /// this scheme, and lower-epoch actives for this user — are removed.
    static func promote(
        userID: String, shareBase64: String, keyEpoch: Int, splitID: String
    ) throws {
        guard let splitID = UUID(uuidString: splitID)?.uuidString.lowercased() else {
            throw BackupError.invalidSplitID
        }
        try upload(
            userID: userID, shareBase64: shareBase64, keyEpoch: keyEpoch,
            splitID: splitID, status: "active",
            key: "\(activeKeyPrefix)\(userID).\(keyEpoch)")
        cleanupSupersededActive(userID: userID, keyEpoch: keyEpoch)
    }

    /// Best-effort removal of envelopes the new active supersedes. Failure is
    /// harmless: stale keys are simply ignored by the newest-epoch reader.
    /// The legacy (un-scoped) key may belong to ANY account — it is removed
    /// only after decoding its envelope and confirming the userID matches;
    /// another account's legacy backup is left untouched.
    private static func cleanupSupersededActive(userID: String, keyEpoch: Int) {
        let store = NSUbiquitousKeyValueStore.default
        for (key, _) in store.dictionaryRepresentation {
            if key == "\(activeKeyPrefix)\(userID)" {   // pre-epoch-scoped v3 key
                store.removeObject(forKey: key)
                continue
            }
            if key == legacyStorageKey {
                // The legacy key is un-scoped: it may belong to any account.
                // Decode it and remove only if this promotion's userID owns
                // it — otherwise leave another account's backup alone.
                if let data = store.data(forKey: key),
                   let envelope = try? JSONDecoder().decode(Envelope.self, from: data),
                   envelope.userID == userID {
                    store.removeObject(forKey: key)
                }
                continue
            }
            let scopedPrefix = "\(activeKeyPrefix)\(userID)."
            guard key.hasPrefix(scopedPrefix),
                  let epoch = Int(key.dropFirst(scopedPrefix.count)),
                  epoch < keyEpoch else { continue }
            store.removeObject(forKey: key)
        }
        store.synchronize()
    }

    private static func upload(
        userID: String, shareBase64: String, keyEpoch: Int,
        splitID: String, status: String, key: String
    ) throws {
        guard keyEpoch >= 1 else { throw BackupError.invalidEpoch }
        guard UUID(uuidString: splitID) != nil else { throw BackupError.invalidSplitID }
        let envelope = Envelope(
            version: 3, userID: userID, shareB64: shareBase64,
            keyEpoch: keyEpoch, splitID: splitID, status: status)
        let data = try JSONEncoder().encode(envelope)
        let store = NSUbiquitousKeyValueStore.default
        store.set(data, forKey: key)
        store.synchronize()
    }

    enum BackupError: LocalizedError {
        case invalidEpoch, invalidSplitID
        var errorDescription: String? {
            switch self {
            case .invalidEpoch: return "recovery backup epoch must be positive"
            case .invalidSplitID: return "recovery backup split ID is invalid"
            }
        }
    }

    /// Downloads the newest epoch-bound Share 1 for `userID`. A legacy v1
    /// envelope is accepted only as epoch 1.
    static func download(userID: String) -> Backup? {
        newest(in: allBackups().filter { $0.userID == userID })
    }

    /// The account id of whatever backup is currently stored, if any — lets
    /// the recovery screen pre-fill the account id without the user typing
    /// their UUID, mirroring desktop's cloud envelope.
    static func storedUserID() -> String? {
        newest(in: allBackups())?.userID
    }

    private static func newest(in backups: [Backup]) -> Backup? {
        backups.max { lhs, rhs in
            if lhs.keyEpoch != rhs.keyEpoch { return lhs.keyEpoch < rhs.keyEpoch }
            return lhs.splitID == nil && rhs.splitID != nil
        }
    }

    private static func storageKey(userID: String, keyEpoch: Int) -> String {
        "\(storageKeyPrefix)\(userID).\(keyEpoch)"
    }

    private static func allBackups() -> [Backup] {
        let store = NSUbiquitousKeyValueStore.default
        store.synchronize()
        return store.dictionaryRepresentation.compactMap { key, value in
            guard key == legacyStorageKey || key.hasPrefix(storageKeyPrefix)
                    || key.hasPrefix(activeKeyPrefix),
                  let data = value as? Data,
                  let envelope = try? JSONDecoder().decode(Envelope.self, from: data) else {
                return nil
            }
            return envelope.backup
        }
    }
}
