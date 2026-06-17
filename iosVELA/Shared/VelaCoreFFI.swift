import Foundation
import VelaCore

/// Thin Swift wrapper over the VELA Rust core's C ABI (the `VelaCore` module
/// vended by VelaCore.xcframework). All payloads are UTF-8 JSON; every returned
/// pointer is freed here.
enum VelaCoreFFI {
    private static func consume(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
        guard let ptr = ptr else { return "" }
        defer { vela_ffi_free_string(ptr) }
        return String(cString: ptr)
    }

    private static func json(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: object),
              let string = String(data: data, encoding: .utf8) else { return "{}" }
        return string
    }

    /// Pull a string field out of a JSON object response, or nil (e.g. on `{"error":...}`).
    private static func field(_ response: String, _ key: String) -> String? {
        guard let data = response.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = obj[key] as? String else { return nil }
        return value
    }

    /// Pull a `[String]` field out of a JSON object response, or nil on error.
    private static func stringArray(_ response: String, _ key: String) -> [String]? {
        guard let data = response.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = obj[key] as? [String] else { return nil }
        return value
    }

    /// e.g. "vela-apple-bridge/0.1.0"
    static func version() -> String {
        consume(vela_ffi_version())
    }

    // MARK: - Identity & auth

    /// A freshly generated device identity (all base64).
    struct Identity {
        let hybridEK: String
        let hybridVK: String
        let hybridSK: String
    }

    /// Generate a fresh device identity, or nil on error.
    static func generateIdentity() -> Identity? {
        let response = generateIdentityJSON()
        guard let ek = field(response, "hybrid_ek_b64"),
              let vk = field(response, "hybrid_vk_b64"),
              let sk = field(response, "hybrid_sk_b64") else { return nil }
        return Identity(hybridEK: ek, hybridVK: vk, hybridSK: sk)
    }

    /// Sign a server auth challenge with the device signing key. Returns base64 signature.
    static func createAuthSignature(hybridSKBase64: String, challengeBase64: String, deviceID: String) -> String? {
        let request = json(["hybrid_sk_b64": hybridSKBase64, "challenge_b64": challengeBase64, "device_id": deviceID])
        let response = request.withCString { consume(vela_ffi_create_auth_signature_json($0)) }
        return field(response, "signature_b64")
    }

    // MARK: - Sync (per-chunk)

    static func encryptVaultChunk(rmsBase64: String, chunkID: String, vaultJSON: String) -> String? {
        let request = json(["rms_b64": rmsBase64, "chunk_id": chunkID, "vault_json": vaultJSON])
        let response = request.withCString { consume(vela_ffi_encrypt_vault_chunk_json($0)) }
        return field(response, "ciphertext_b64")
    }

    static func decryptVaultChunk(rmsBase64: String, chunkID: String, ciphertextBase64: String) -> String? {
        let request = json(["rms_b64": rmsBase64, "chunk_id": chunkID, "ciphertext_b64": ciphertextBase64])
        let response = request.withCString { consume(vela_ffi_decrypt_vault_chunk_json($0)) }
        return field(response, "vault_json")
    }

    // MARK: - Enrollment

    /// Decrypt an RMS capsule (AEAD under a 32-byte transfer key). Returns base64 RMS.
    static func decryptRMSCapsule(transferKeyBase64: String, capsuleBase64: String) -> String? {
        let request = json(["transfer_key_b64": transferKeyBase64, "capsule_b64": capsuleBase64])
        let response = request.withCString { consume(vela_ffi_decrypt_rms_capsule_json($0)) }
        return field(response, "rms_b64")
    }

    /// Decrypt an enrollment package (AEAD under a 32-byte key). Returns the plaintext JSON.
    static func decryptEnrollmentPackage(keyBase64: String, ciphertextBase64: String) -> String? {
        let request = json(["key_b64": keyBase64, "ciphertext_b64": ciphertextBase64])
        let response = request.withCString { consume(vela_ffi_decrypt_enrollment_package_json($0)) }
        return field(response, "plaintext")
    }

    // MARK: - Recovery (Shamir)

    /// Split the RMS into `n` base64 shares, `threshold` of which reconstruct it.
    static func splitRecovery(rmsBase64: String, threshold: Int, n: Int) -> [String]? {
        let request = json(["rms_b64": rmsBase64, "threshold": threshold, "n": n])
        let response = request.withCString { consume(vela_ffi_split_recovery_json($0)) }
        return stringArray(response, "shares_b64")
    }

    /// Reconstruct the RMS (base64) from `threshold`+ recovery shares.
    static func combineRecovery(sharesBase64: [String]) -> String? {
        let request = json(["shares_b64": sharesBase64])
        let response = request.withCString { consume(vela_ffi_combine_recovery_json($0)) }
        return field(response, "rms_b64")
    }

    static func passwordStrengthJSON(_ password: String) -> String {
        json(["password": password]).withCString { consume(vela_ffi_password_strength_json($0)) }
    }

    static func generateIdentityJSON() -> String {
        consume(vela_ffi_generate_identity_json())
    }

    /// Encrypt a vault (JSON string) under the RMS. Returns base64 ciphertext, or nil on error.
    static func encryptVault(rmsBase64: String, vaultJSON: String) -> String? {
        let request = json(["rms_b64": rmsBase64, "vault_json": vaultJSON])
        let response = request.withCString { consume(vela_ffi_encrypt_vault_json($0)) }
        return field(response, "ciphertext_b64")
    }

    /// Decrypt a vault. Returns the vault JSON string, or nil on error / wrong RMS.
    static func decryptVault(rmsBase64: String, ciphertextBase64: String) -> String? {
        let request = json(["rms_b64": rmsBase64, "ciphertext_b64": ciphertextBase64])
        let response = request.withCString { consume(vela_ffi_decrypt_vault_json($0)) }
        return field(response, "vault_json")
    }
}
