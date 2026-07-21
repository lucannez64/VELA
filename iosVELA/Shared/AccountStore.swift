import Foundation
import Security

/// The device's server account: identity keypair, server-assigned ids, and the
/// current PASETO token.
///
/// `hybridSK` (signing secret, used in `createAuthSignature` to authenticate to
/// the server) and `shareDK` (share KEM secret, used to open incoming shares)
/// are secret key material and live in the Keychain via `KeychainAccountKeyStore`.
/// The rest of this struct is non-secret and is persisted file-protected in the
/// shared App Group so the app (and later the extension) can reach the server
/// as the same device.
struct AccountState: Codable, Equatable {
    var serverURL: String
    var userID: String
    var deviceID: String
    var hybridEK: String
    var hybridVK: String
    var hybridSK: String
    var token: String?
    /// ML-KEM-1024 + X25519 share public key (1600 B, base64). Published to server at registration.
    var shareEK: String = ""
    /// ML-KEM-1024 + X25519 share secret key (3200 B, base64). Used to open shares addressed to us.
    var shareDK: String = ""
}

/// The non-secret subset of `AccountState` that's safe to keep in the
/// file-backed store once `hybridSK`/`shareDK` have moved to the Keychain.
private struct AccountFileState: Codable {
    var serverURL: String
    var userID: String
    var deviceID: String
    var hybridEK: String
    var hybridVK: String
    var token: String?
    var shareEK: String = ""

    init(_ state: AccountState) {
        serverURL = state.serverURL
        userID = state.userID
        deviceID = state.deviceID
        hybridEK = state.hybridEK
        hybridVK = state.hybridVK
        token = state.token
        shareEK = state.shareEK
    }

    func merged(hybridSK: String, shareDK: String) -> AccountState {
        AccountState(serverURL: serverURL, userID: userID, deviceID: deviceID,
                     hybridEK: hybridEK, hybridVK: hybridVK, hybridSK: hybridSK,
                     token: token, shareEK: shareEK, shareDK: shareDK)
    }
}

protocol AccountKeyStore {
    func store(hybridSK: String, shareDK: String) throws
    func load() -> (hybridSK: String, shareDK: String)?
    func clear()
}

/// Keeps `hybridSK`/`shareDK` in the iOS Keychain, pinned to this device only
/// (never synced to iCloud Keychain or included in backups). Unlike the RMS
/// (`KeychainRMSStore`), these keys must be usable without a biometric prompt
/// for background sync operations, so they use
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` rather than `.biometryCurrentSet` —
/// still off-limits while the device is locked, but no Face ID/Touch ID gate.
struct KeychainAccountKeyStore: AccountKeyStore {
    let service: String

    init(service: String = "com.vela.account") {
        self.service = service
    }

    func store(hybridSK: String, shareDK: String) throws {
        try set(hybridSK, account: "hybridSK")
        try set(shareDK, account: "shareDK")
    }

    func load() -> (hybridSK: String, shareDK: String)? {
        guard let hybridSK = get(account: "hybridSK") else { return nil }
        return (hybridSK, get(account: "shareDK") ?? "")
    }

    func clear() {
        SecItemDelete(query(account: "hybridSK") as CFDictionary)
        SecItemDelete(query(account: "shareDK") as CFDictionary)
    }

    private func set(_ value: String, account: String) throws {
        guard let data = value.data(using: .utf8) else { throw VaultError.keychain }
        SecItemDelete(query(account: account) as CFDictionary) // replace any prior value
        var add = query(account: account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else {
            throw VaultError.keychain
        }
    }

    private func get(account: String) -> String? {
        var q = query(account: account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func query(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

/// Deterministic, headless key store for the Simulator/unit tests, where the
/// Keychain isn't reliably usable (mirrors `FileRMSStore`'s role for the RMS).
/// File-protected at rest; NOT used on real devices.
struct FileAccountKeyStore: AccountKeyStore {
    private struct Keys: Codable { var hybridSK: String; var shareDK: String }
    let url: URL

    init(directory: URL) {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.url = directory.appendingPathComponent("account_keys.json")
    }

    func store(hybridSK: String, shareDK: String) throws {
        let data = try JSONEncoder().encode(Keys(hybridSK: hybridSK, shareDK: shareDK))
        try data.write(to: url, options: [.completeFileProtection, .atomic])
    }

    func load() -> (hybridSK: String, shareDK: String)? {
        guard let data = try? Data(contentsOf: url),
              let keys = try? JSONDecoder().decode(Keys.self, from: data) else { return nil }
        return (keys.hybridSK, keys.shareDK)
    }

    func clear() {
        try? FileManager.default.removeItem(at: url)
    }
}

struct AccountStore {
    let url: URL
    private let keyStore: AccountKeyStore

    init(directory: URL? = nil) {
        if let directory = directory {
            // Test injection: deterministic, headless key store (mirrors VaultRepository).
            self.keyStore = FileAccountKeyStore(directory: directory)
        } else {
            self.keyStore = KeychainAccountKeyStore()
        }
        let dir = directory ?? AppGroup.vaultDirectory()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.url = dir.appendingPathComponent("account.json")
    }

    func load() -> AccountState? {
        guard let data = try? Data(contentsOf: url) else { return nil }

        // Pre-fix account.json embedded hybridSK/shareDK inline. If the file
        // still decodes as a full AccountState, migrate the keys into the
        // Keychain once and rewrite the file without them.
        if let legacy = try? JSONDecoder().decode(AccountState.self, from: data), !legacy.hybridSK.isEmpty {
            try? save(legacy)
            return legacy
        }

        guard let fileState = try? JSONDecoder().decode(AccountFileState.self, from: data),
              let keys = keyStore.load() else { return nil }
        return fileState.merged(hybridSK: keys.hybridSK, shareDK: keys.shareDK)
    }

    func save(_ state: AccountState) throws {
        try keyStore.store(hybridSK: state.hybridSK, shareDK: state.shareDK)
        let data = try JSONEncoder().encode(AccountFileState(state))
        try data.write(to: url, options: [.completeFileProtection, .atomic])
    }

    func clear() {
        try? FileManager.default.removeItem(at: url)
        keyStore.clear()
    }
}
