import Foundation
import CryptoKit
import CommonCrypto

/// Wraps the RMS under a password-derived key (PBKDF2-HMAC-SHA256 + AES-GCM),
/// an alternative to the biometric Keychain store. The blob is on-device only
/// (never synced), so the format is ours; params match the Android
/// `PasswordRmsProtector` (210k iterations, 256-bit key, 16-byte salt).
struct PasswordRMSStore {
    static let iterations = 210_000
    static let saltLength = 16

    let url: URL

    init(directory: URL) {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.url = directory.appendingPathComponent("rms_password.blob")
    }

    private struct Blob: Codable {
        let version: Int
        let iterations: Int
        let salt: String      // base64
        let combined: String  // base64 AES-GCM nonce‖ciphertext‖tag
    }

    func exists() -> Bool {
        FileManager.default.fileExists(atPath: url.path)
    }

    func wrap(rms: Data, password: String) throws {
        var salt = Data(count: Self.saltLength)
        let status = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, Self.saltLength, $0.baseAddress!) }
        guard status == errSecSuccess else { throw VaultError.rng }

        let key = try Self.deriveKey(password: password, salt: salt, iterations: Self.iterations)
        let sealed = try AES.GCM.seal(rms, using: key)
        guard let combined = sealed.combined else { throw VaultError.crypto }

        let blob = Blob(version: 1, iterations: Self.iterations,
                        salt: salt.base64EncodedString(), combined: combined.base64EncodedString())
        try JSONEncoder().encode(blob).write(to: url, options: [.completeFileProtection, .atomic])
    }

    /// Unwrap the RMS; throws on a wrong password (AES-GCM tag mismatch).
    func unwrap(password: String) throws -> Data {
        let blob = try JSONDecoder().decode(Blob.self, from: Data(contentsOf: url))
        guard let salt = Data(base64Encoded: blob.salt),
              let combined = Data(base64Encoded: blob.combined) else {
            throw VaultError.crypto
        }
        let key = try Self.deriveKey(password: password, salt: salt, iterations: blob.iterations)
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    func delete() {
        try? FileManager.default.removeItem(at: url)
    }

    /// PBKDF2-HMAC-SHA256 → 32-byte SymmetricKey.
    static func deriveKey(password: String, salt: Data, iterations: Int) throws -> SymmetricKey {
        let passwordBytes = Array(password.utf8)
        var derived = [UInt8](repeating: 0, count: 32)
        let status = salt.withUnsafeBytes { saltPtr in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, passwordBytes.count,
                saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                UInt32(iterations),
                &derived, derived.count
            )
        }
        guard status == kCCSuccess else { throw VaultError.crypto }
        return SymmetricKey(data: Data(derived))
    }
}
