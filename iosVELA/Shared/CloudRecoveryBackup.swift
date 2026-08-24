import Foundation

/// Stores/retrieves Share 1 of the recovery split (SPEC.md §4.3) via iCloud
/// Key-Value Storage. The blob is a few dozen bytes — well under the 1 MB /
/// 1024-key ubiquitous KVS limit — so this needs no CloudKit container or
/// Drive-style file management, just the iCloud (Key-Value storage)
/// capability enabled for the app (see `iosVELA.entitlements`).
enum CloudRecoveryBackup {
    private static let legacyStorageKey = "vela.recovery.share1.v1"
    private static let storageKeyPrefix = "vela.recovery.share1.v2."

    struct Backup: Equatable {
        let userID: String
        let shareBase64: String
        let keyEpoch: Int
    }

    private struct Envelope: Codable {
        let version: Int
        let userID: String
        let shareB64: String
        let keyEpoch: Int?

        enum CodingKeys: String, CodingKey {
            case version
            case userID = "user_id"
            case shareB64 = "share_b64"
            case keyEpoch = "key_epoch"
        }

        var backup: Backup? {
            let epoch = keyEpoch ?? (version == 1 ? 1 : 0)
            guard epoch >= 1 else { return nil }
            return Backup(userID: userID, shareBase64: shareB64, keyEpoch: epoch)
        }
    }

    /// Backs up Share 1 under an epoch-specific key. A delayed epoch-N device
    /// therefore cannot overwrite the epoch-N+1 envelope in the shared iCloud
    /// store; readers select the highest valid epoch for the account.
    static func upload(userID: String, shareBase64: String, keyEpoch: Int) throws {
        guard keyEpoch >= 1 else { throw BackupError.invalidEpoch }
        let envelope = Envelope(
            version: 2, userID: userID, shareB64: shareBase64,
            keyEpoch: keyEpoch)
        let data = try JSONEncoder().encode(envelope)
        let store = NSUbiquitousKeyValueStore.default
        store.set(data, forKey: storageKey(userID: userID, keyEpoch: keyEpoch))
        store.synchronize()
    }

    enum BackupError: LocalizedError {
        case invalidEpoch
        var errorDescription: String? { "recovery backup epoch must be positive" }
    }

    /// Downloads the newest epoch-bound Share 1 for `userID`. A legacy v1
    /// envelope is accepted only as epoch 1.
    static func download(userID: String) -> Backup? {
        allBackups().filter { $0.userID == userID }.max { $0.keyEpoch < $1.keyEpoch }
    }

    /// The account id of whatever backup is currently stored, if any — lets
    /// the recovery screen pre-fill the account id without the user typing
    /// their UUID, mirroring desktop's cloud envelope.
    static func storedUserID() -> String? {
        allBackups().max { $0.keyEpoch < $1.keyEpoch }?.userID
    }

    private static func storageKey(userID: String, keyEpoch: Int) -> String {
        "\(storageKeyPrefix)\(userID).\(keyEpoch)"
    }

    private static func allBackups() -> [Backup] {
        let store = NSUbiquitousKeyValueStore.default
        store.synchronize()
        return store.dictionaryRepresentation.compactMap { key, value in
            guard key == legacyStorageKey || key.hasPrefix(storageKeyPrefix),
                  let data = value as? Data,
                  let envelope = try? JSONDecoder().decode(Envelope.self, from: data) else {
                return nil
            }
            return envelope.backup
        }
    }
}
