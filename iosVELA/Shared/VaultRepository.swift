import Foundation
import Security
import LocalAuthentication

enum VaultError: Error {
    case rng
    case crypto
    case keychain
}

/// On-device persistence for the vault: an encrypted blob plus the root seed.
///
/// Phase 2: the RMS now lives in a biometric-gated Keychain item (`KeychainRMSStore`)
/// on real devices, replacing the Phase 1b file placeholder. The Simulator and unit
/// tests fall back to `FileRMSStore`, since the biometric Keychain isn't usable
/// headlessly. The vault itself is always encrypted by the Rust core under the RMS.
struct VaultRepository {
    let directory: URL
    private let rmsStore: RMSStore
    private let passwordStore: PasswordRMSStore

    init(directory: URL? = nil) {
        if let directory = directory {
            // Test injection: deterministic, headless file store.
            self.directory = directory
            self.rmsStore = FileRMSStore(directory: directory)
        } else {
            // Shared App Group container so the AutoFill extension reads the same
            // vault the app writes (falls back to app-local when not provisioned).
            let base = AppGroup.vaultDirectory()
            self.directory = base
            #if targetEnvironment(simulator)
            self.rmsStore = FileRMSStore(directory: base)
            #else
            // The RMS lives in the shared keychain access group (see entitlements),
            // reachable from both the app and the extension; no group set in code so
            // the entitlement's single group is used by default.
            self.rmsStore = KeychainRMSStore()
            #endif
        }
        self.passwordStore = PasswordRMSStore(directory: self.directory)
    }

    private var vaultURL: URL { directory.appendingPathComponent("vault.enc") }
    private var vaultExists: Bool { FileManager.default.fileExists(atPath: vaultURL.path) }

    func hasVault() -> Bool { (rmsStore.exists() || passwordStore.exists()) && vaultExists }

    /// How the existing vault is unlocked (password takes precedence if present).
    var usesPasswordUnlock: Bool { passwordStore.exists() }

    func generateAndStoreRMS() throws -> Data {
        try rmsStore.generate()
    }

    /// Load the RMS, prompting Face ID / Touch ID on device. Pass an
    /// already-authenticated `LAContext` to reuse a single biometric prompt.
    func loadRMS(context: LAContext? = nil) throws -> Data {
        try rmsStore.load(context: context)
    }

    // MARK: - Password unlock (Phase 7)

    /// Create a fresh RMS protected by a password (PBKDF2 + AES-GCM).
    func generatePasswordRMS(password: String) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultError.rng
        }
        let rms = Data(bytes)
        try passwordStore.wrap(rms: rms, password: password)
        return rms
    }

    /// Unwrap the RMS with the password; throws on a wrong password.
    func loadRMSWithPassword(_ password: String) throws -> Data {
        try passwordStore.unwrap(password: password)
    }

    // MARK: - Enrollment (adopt a recovered RMS)

    /// Store an RMS recovered during enrollment under biometric protection.
    func adoptRMSBiometric(_ rms: Data) throws {
        try rmsStore.store(rms)
    }

    /// Store an RMS recovered during enrollment under a password.
    func adoptRMSWithPassword(_ rms: Data, password: String) throws {
        try passwordStore.wrap(rms: rms, password: password)
    }

    func save(_ store: VaultStore, rms: Data) throws {
        let vaultJSON = String(decoding: try JSONEncoder().encode(store), as: UTF8.self)
        guard let ciphertext = VelaCoreFFI.encryptVault(rmsBase64: rms.base64EncodedString(), vaultJSON: vaultJSON) else {
            throw VaultError.crypto
        }
        try Data(ciphertext.utf8).write(to: vaultURL, options: [.completeFileProtection, .atomic])
    }

    func load(rms: Data) throws -> VaultStore {
        let ciphertext = try String(contentsOf: vaultURL, encoding: .utf8)
        guard let vaultJSON = VelaCoreFFI.decryptVault(rmsBase64: rms.base64EncodedString(), ciphertextBase64: ciphertext) else {
            throw VaultError.crypto
        }
        return try JSONDecoder().decode(VaultStore.self, from: Data(vaultJSON.utf8))
    }

    /// Wipe the on-device vault (used by UI tests via the VELA_RESET launch env).
    func reset() {
        rmsStore.delete()
        passwordStore.delete()
        try? FileManager.default.removeItem(at: vaultURL)
    }
}
