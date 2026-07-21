import Foundation

/// Stores/retrieves Share 1 of the recovery split (SPEC.md §4.3) via iCloud
/// Key-Value Storage. The blob is a few dozen bytes — well under the 1 MB /
/// 1024-key ubiquitous KVS limit — so this needs no CloudKit container or
/// Drive-style file management, just the iCloud (Key-Value storage)
/// capability enabled for the app (see `iosVELA.entitlements`).
enum CloudRecoveryBackup {
    private static let storageKey = "vela.recovery.share1.v1"

    private struct Envelope: Codable {
        let version: Int
        let userID: String
        let shareB64: String

        enum CodingKeys: String, CodingKey {
            case version
            case userID = "user_id"
            case shareB64 = "share_b64"
        }
    }

    /// Backs up Share 1, keyed by account — if this device's iCloud account
    /// is later used to set up a *different* VELA account, `upload` simply
    /// overwrites the previous backup (there is only ever one recovery in
    /// flight per iCloud account by design).
    static func upload(userID: String, shareBase64: String) {
        let envelope = Envelope(version: 1, userID: userID, shareB64: shareBase64)
        guard let data = try? JSONEncoder().encode(envelope) else { return }
        let store = NSUbiquitousKeyValueStore.default
        store.set(data, forKey: storageKey)
        store.synchronize()
    }

    /// Downloads Share 1 for `userID`, or nil if this iCloud account has no
    /// backup, or its backup belongs to a different account.
    static func download(userID: String) -> String? {
        guard let envelope = currentEnvelope(), envelope.userID == userID else { return nil }
        return envelope.shareB64
    }

    /// The account id of whatever backup is currently stored, if any — lets
    /// the recovery screen pre-fill the account id without the user typing
    /// their UUID, mirroring desktop's cloud envelope.
    static func storedUserID() -> String? {
        currentEnvelope()?.userID
    }

    private static func currentEnvelope() -> Envelope? {
        let store = NSUbiquitousKeyValueStore.default
        store.synchronize()
        guard let data = store.data(forKey: storageKey) else { return nil }
        return try? JSONDecoder().decode(Envelope.self, from: data)
    }
}
