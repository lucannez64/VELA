import Foundation
import Security
import LocalAuthentication

/// Where the Root Master Seed (RMS) lives on the device.
///
/// The RMS is the 32-byte secret the Rust core derives the vault key from; it
/// must never leave the device and must be guarded behind user presence.
protocol RMSStore {
    func exists() -> Bool
    func generate() throws -> Data
    /// Persist a specific RMS (e.g. one recovered during device enrollment).
    func store(_ rms: Data) throws
    /// Load the RMS. Biometric-backed stores authenticate the user first; an
    /// already-authenticated `LAContext` may be supplied to avoid a second prompt.
    func load(context: LAContext?) throws -> Data
    func delete()
}

private let rmsByteCount = 32

private func randomRMS() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: rmsByteCount)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
        throw VaultError.rng
    }
    return Data(bytes)
}

/// Phase 2 production store: keeps the RMS in the iOS Keychain, gated by Face ID
/// / Touch ID (or the device passcode as fallback) and pinned to *this device
/// only* so it never syncs to iCloud Keychain or appears in a backup.
struct KeychainRMSStore: RMSStore {
    let service: String
    let account: String

    init(service: String = "com.vela.vault", account: String = "rms") {
        self.service = service
        self.account = account
    }

    func exists() -> Bool {
        var query = baseQuery()
        // Check presence without triggering a biometric prompt: if the item is
        // there but auth-protected the Keychain returns interactionNotAllowed.
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        query[kSecReturnData as String] = false
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    func generate() throws -> Data {
        let data = try randomRMS()
        try store(data)
        return data
    }

    func store(_ rms: Data) throws {
        var error: Unmanaged<CFError>?
        // .userPresence → biometry if available, else device passcode.
        // WhenPasscodeSetThisDeviceOnly → requires a passcode, never synced/backed up.
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .userPresence,
            &error
        ) else {
            throw VaultError.keychain
        }

        SecItemDelete(baseQuery() as CFDictionary) // replace any prior seed

        var add = baseQuery()
        add[kSecValueData as String] = rms
        add[kSecAttrAccessControl as String] = access
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else {
            throw VaultError.keychain
        }
    }

    func load(context: LAContext?) throws -> Data {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultError.keychain
        }
        return data
    }

    func delete() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

/// Phase 1b placeholder, retained for the Simulator and unit tests where the
/// biometric Keychain isn't usable headlessly (no enrolled biometrics/passcode).
/// File-protected at rest; NOT used on real devices.
struct FileRMSStore: RMSStore {
    let url: URL

    init(directory: URL) {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.url = directory.appendingPathComponent("rms.bin")
    }

    func exists() -> Bool {
        FileManager.default.fileExists(atPath: url.path)
    }

    func generate() throws -> Data {
        let data = try randomRMS()
        try store(data)
        return data
    }

    func store(_ rms: Data) throws {
        try rms.write(to: url, options: [.completeFileProtection, .atomic])
    }

    func load(context: LAContext?) throws -> Data {
        try Data(contentsOf: url)
    }

    func delete() {
        try? FileManager.default.removeItem(at: url)
    }
}

/// Thin wrapper over LocalAuthentication. Returns an authenticated `LAContext`
/// the Keychain read can reuse so the user sees a single prompt; `nil` on failure.
enum BiometricGate {
    static func authenticate(reason: String) async -> LAContext? {
        let context = LAContext()
        #if targetEnvironment(simulator)
        // The Simulator/CI has no reliable biometric or passcode, so don't block
        // the headless walkthrough. On a real device the #else branch gates entry.
        return context
        #else
        var err: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            return nil
        }
        do {
            let ok = try await context.evaluatePolicy(
                .deviceOwnerAuthentication, localizedReason: reason
            )
            return ok ? context : nil
        } catch {
            return nil
        }
        #endif
    }
}
