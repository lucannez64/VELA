import Foundation
import Security

enum VaultError: Error {
    case rng
    case crypto
}

/// On-device persistence for the vault: an encrypted blob plus the root seed.
///
/// NOTE (Phase 1b): the RMS is stored in a file-protected sandbox file as a
/// placeholder. Phase 2 moves it into the Keychain / Secure Enclave. The vault
/// itself is always encrypted by the Rust core under the RMS.
struct VaultRepository {
    let directory: URL

    init(directory: URL? = nil) {
        if let directory = directory {
            self.directory = directory
        } else {
            let base = FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            self.directory = base.appendingPathComponent("vela", isDirectory: true)
        }
        try? FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true)
    }

    private var rmsURL: URL { directory.appendingPathComponent("rms.bin") }
    private var vaultURL: URL { directory.appendingPathComponent("vault.enc") }

    func hasVault() -> Bool {
        let fm = FileManager.default
        return fm.fileExists(atPath: rmsURL.path) && fm.fileExists(atPath: vaultURL.path)
    }

    func generateAndStoreRMS() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultError.rng
        }
        let data = Data(bytes)
        try data.write(to: rmsURL, options: [.completeFileProtection, .atomic])
        return data
    }

    func loadRMS() throws -> Data {
        try Data(contentsOf: rmsURL)
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
}
