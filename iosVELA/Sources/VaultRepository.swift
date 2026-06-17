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

    init(directory: URL? = nil) {
        if let directory = directory {
            // Test injection: deterministic, headless file store.
            self.directory = directory
            self.rmsStore = FileRMSStore(directory: directory)
        } else {
            let base = FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("vela", isDirectory: true)
            self.directory = base
            try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
            #if targetEnvironment(simulator)
            self.rmsStore = FileRMSStore(directory: base)
            #else
            self.rmsStore = KeychainRMSStore()
            #endif
        }
    }

    private var vaultURL: URL { directory.appendingPathComponent("vault.enc") }

    func hasVault() -> Bool {
        rmsStore.exists() && FileManager.default.fileExists(atPath: vaultURL.path)
    }

    func generateAndStoreRMS() throws -> Data {
        try rmsStore.generate()
    }

    /// Load the RMS, prompting Face ID / Touch ID on device. Pass an
    /// already-authenticated `LAContext` to reuse a single biometric prompt.
    func loadRMS(context: LAContext? = nil) throws -> Data {
        try rmsStore.load(context: context)
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
        try? FileManager.default.removeItem(at: vaultURL)
    }
}
