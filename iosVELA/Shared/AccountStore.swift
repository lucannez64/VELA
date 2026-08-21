import Foundation
import Security

/// The device's server account: identity keypair, server-assigned ids, and the
/// current PASETO token.
///
/// The device signing key and the share decapsulation key are **not** here.
/// They live behind a native handle (`VelaCoreFFI.IdentityHandle`); this struct
/// carries only `sealedIdentity`, an opaque AEAD blob the native side can
/// reopen, and the 32-byte seal key lives in the Keychain via
/// `KeychainAccountKeyStore`. Holding the keys here as base64 `String`s meant
/// un-wipeable copies on the heap for the life of the process, readable from any
/// crash report (audit C-1).
///
/// The rest of this struct is non-secret and is persisted file-protected in the
/// shared App Group so the app (and later the extension) can reach the server
/// as the same device.
struct AccountState: Codable, Equatable {
    var serverURL: String
    var userID: String
    var deviceID: String
    var hybridEK: String
    var hybridVK: String
    var token: String?
    /// ML-KEM-1024 + X25519 share public key (1600 B, base64). Published to server at registration.
    var shareEK: String = ""
    /// Sealed private halves — opaque to Swift, reopened natively with the seal key.
    var sealedIdentity: String = ""
}

/// The file-backed subset. The sealed blob rides along: it is useless without
/// the seal key, which is the thing that stays in the Keychain.
private struct AccountFileState: Codable {
    var serverURL: String
    var userID: String
    var deviceID: String
    var hybridEK: String
    var hybridVK: String
    var token: String?
    var shareEK: String = ""
    var sealedIdentity: String = ""

    init(_ state: AccountState) {
        serverURL = state.serverURL
        userID = state.userID
        deviceID = state.deviceID
        hybridEK = state.hybridEK
        hybridVK = state.hybridVK
        token = state.token
        shareEK = state.shareEK
        sealedIdentity = state.sealedIdentity
    }

    func merged() -> AccountState {
        AccountState(serverURL: serverURL, userID: userID, deviceID: deviceID,
                     hybridEK: hybridEK, hybridVK: hybridVK,
                     token: token, shareEK: shareEK, sealedIdentity: sealedIdentity)
    }
}

/// Stores the 32-byte key the native side seals the identity under, plus (for
/// migration only) any legacy plaintext keys written before the handle existed.
protocol AccountKeyStore {
    func storeSealKey(_ key: Data) throws
    func loadSealKey() -> Data?
    /// Legacy plaintext keys, if this device still has them.
    func loadLegacyKeys() -> (hybridSK: String, shareDK: String)?
    func clearLegacyKeys()
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

    func storeSealKey(_ key: Data) throws {
        try set(key.base64EncodedString(), account: "identitySealKey")
    }

    func loadSealKey() -> Data? {
        get(account: "identitySealKey").flatMap { Data(base64Encoded: $0) }
    }

    func loadLegacyKeys() -> (hybridSK: String, shareDK: String)? {
        guard let hybridSK = get(account: "hybridSK") else { return nil }
        return (hybridSK, get(account: "shareDK") ?? "")
    }

    func clearLegacyKeys() {
        SecItemDelete(query(account: "hybridSK") as CFDictionary)
        SecItemDelete(query(account: "shareDK") as CFDictionary)
    }

    func clear() {
        clearLegacyKeys()
        SecItemDelete(query(account: "identitySealKey") as CFDictionary)
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
    private struct Keys: Codable {
        var sealKey: String = ""
        var hybridSK: String = ""
        var shareDK: String = ""
    }
    let url: URL

    init(directory: URL) {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.url = directory.appendingPathComponent("account_keys.json")
    }

    private func read() -> Keys? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(Keys.self, from: data)
    }

    private func write(_ keys: Keys) throws {
        let data = try JSONEncoder().encode(keys)
        try data.write(to: url, options: [.completeFileProtection, .atomic])
        BackupExclusion.exclude(url)
    }

    func storeSealKey(_ key: Data) throws {
        var keys = read() ?? Keys()
        keys.sealKey = key.base64EncodedString()
        try write(keys)
    }

    func loadSealKey() -> Data? {
        read().flatMap { Data(base64Encoded: $0.sealKey) }
    }

    func loadLegacyKeys() -> (hybridSK: String, shareDK: String)? {
        guard let keys = read(), !keys.hybridSK.isEmpty else { return nil }
        return (keys.hybridSK, keys.shareDK)
    }

    func clearLegacyKeys() {
        guard var keys = read() else { return }
        keys.hybridSK = ""
        keys.shareDK = ""
        try? write(keys)
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
        guard let data = try? Data(contentsOf: url),
              let fileState = try? JSONDecoder().decode(AccountFileState.self, from: data) else {
            return nil
        }
        var state = fileState.merged()
        if state.sealedIdentity.isEmpty, let migrated = migrateLegacyKeys(into: state) {
            state = migrated
        }
        return state
    }

    func save(_ state: AccountState) throws {
        let data = try JSONEncoder().encode(AccountFileState(state))
        try data.write(to: url, options: [.completeFileProtection, .atomic])
        BackupExclusion.exclude(url)
    }

    func clear() {
        try? FileManager.default.removeItem(at: url)
        keyStore.clear()
        VelaCoreFFI.identityForgetAll()
    }

    /// The seal key for this device, minted on first use.
    func sealKey() -> Data {
        if let existing = keyStore.loadSealKey() { return existing }
        var key = Data(count: 32)
        _ = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try? keyStore.storeSealKey(key)
        return key
    }

    /// Open the stored identity, returning a live handle.
    func identityHandle(for state: AccountState) -> VelaCoreFFI.IdentityHandle? {
        guard !state.sealedIdentity.isEmpty else { return nil }
        return VelaCoreFFI.identityOpen(sealKey: sealKey(), sealedBase64: state.sealedIdentity)
    }

    /// Move a device that still holds plaintext keys onto the sealed format.
    ///
    /// The legacy keys are read exactly once — migration cannot avoid touching
    /// them — handed to the native side, and then deleted.
    private func migrateLegacyKeys(into state: AccountState) -> AccountState? {
        guard let legacy = keyStore.loadLegacyKeys(), !legacy.hybridSK.isEmpty else { return nil }
        guard let imported = VelaCoreFFI.identityImport(
            sealKey: sealKey(),
            hybridSKBase64: legacy.hybridSK,
            shareDKBase64: legacy.shareDK,
            hybridEKBase64: state.hybridEK
        ) else { return nil }

        var migrated = state
        migrated.sealedIdentity = imported.sealed
        if migrated.shareEK.isEmpty { migrated.shareEK = imported.shareEK }
        try? save(migrated)
        keyStore.clearLegacyKeys()
        return migrated
    }
}
