import Foundation

/// The device's server account: identity keypair, server-assigned ids, and the
/// current PASETO token. Persisted file-protected in the shared App Group so the
/// app (and later the extension) can reach the server as the same device.
///
/// NOTE: `hybridSK` is a signing secret; it's file-protected here for Phase 4 and
/// is a candidate to move into the Keychain alongside the RMS.
struct AccountState: Codable, Equatable {
    var serverURL: String
    var userID: String
    var deviceID: String
    var hybridEK: String
    var hybridVK: String
    var hybridSK: String
    var token: String?
}

struct AccountStore {
    let url: URL

    init(directory: URL? = nil) {
        let dir = directory ?? AppGroup.vaultDirectory()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.url = dir.appendingPathComponent("account.json")
    }

    func load() -> AccountState? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(AccountState.self, from: data)
    }

    func save(_ state: AccountState) throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: url, options: [.completeFileProtection, .atomic])
    }

    func clear() {
        try? FileManager.default.removeItem(at: url)
    }
}
