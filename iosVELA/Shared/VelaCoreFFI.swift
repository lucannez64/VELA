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

    /// e.g. "vela-apple-bridge/0.1.0"
    static func version() -> String {
        consume(vela_ffi_version())
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
