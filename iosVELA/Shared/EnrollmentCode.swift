import Foundation

/// The payload carried by a VELA enrollment code (the new device's identity +
/// the transfer key that unwraps the RMS capsule). Field names match the JSON
/// the desktop primary device emits.
struct EnrollmentPayload: Decodable {
    let device_id: String
    let hybrid_ek: String
    let hybrid_vk: String
    let hybrid_sk: String
    let transfer_key: String
    let server_url: String?
}

/// Parses VELA enrollment codes, mirroring the Android `EnrollmentCodePayload`:
/// - **V1**: standard base64 of the payload JSON.
/// - **V2**: `VELA-ENROLL:v2:` + base64url(locator `{v,u,t,k}`); the payload is
///   fetched from `/device/enrollment-package/:t` and decrypted with key `k`.
enum EnrollmentCode {
    static let v2Prefix = "VELA-ENROLL:v2:"
    static let v3Prefix = "VELA-ENROLL:v3:"

    enum Parsed {
        case direct(EnrollmentPayload)
        case v2(serverURL: String?, token: String, packageKeyB64URL: String)
        /// Enrollment v3 (audit P-1): a one-time grant and a server URL, and
        /// nothing else. Compare with the cases above, which carry the joining
        /// device's private signing key and the key the RMS capsule is
        /// encrypted under — so reading one of those codes was holding the
        /// vault, permanently.
        case v3(serverURL: String?, grantID: String)
    }

    /// Whether a code is a v3 one, for callers that must decide which flow to
    /// run before parsing. Both versions stay live until old installs age out.
    static func looksLikeV3(_ code: String) -> Bool {
        code.filter { !$0.isWhitespace }.hasPrefix(v3Prefix)
    }

    enum CodeError: LocalizedError {
        case malformed
        var errorDescription: String? { "Enrollment code is not valid." }
    }

    static func parse(_ code: String) throws -> Parsed {
        let normalized = code.filter { !$0.isWhitespace }
        if normalized.hasPrefix(v3Prefix) {
            let locatorB64 = String(normalized.dropFirst(v3Prefix.count))
            guard let data = dataFromBase64URL(locatorB64),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (obj["v"] as? Int) == 3,
                  let grantID = obj["g"] as? String else {
                throw CodeError.malformed
            }
            return .v3(serverURL: obj["u"] as? String, grantID: grantID)
        }
        if normalized.hasPrefix(v2Prefix) {
            let locatorB64 = String(normalized.dropFirst(v2Prefix.count))
            guard let data = dataFromBase64URL(locatorB64),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (obj["v"] as? Int) == 2,
                  let token = obj["t"] as? String,
                  let key = obj["k"] as? String else {
                throw CodeError.malformed
            }
            return .v2(serverURL: obj["u"] as? String, token: token, packageKeyB64URL: key)
        }
        guard let data = Data(base64Encoded: normalized),
              let payload = try? JSONDecoder().decode(EnrollmentPayload.self, from: data) else {
            throw CodeError.malformed
        }
        return .direct(payload)
    }

    /// Decode the payload from a V2 enrollment package (ciphertext fetched from
    /// the server, base64url; key is base64url) via the core.
    static func decodeV2Package(ciphertextB64URL: String, packageKeyB64URL: String) throws -> EnrollmentPayload {
        guard let keyData = dataFromBase64URL(packageKeyB64URL),
              let cipherData = dataFromBase64URL(ciphertextB64URL) else {
            throw CodeError.malformed
        }
        guard let json = VelaCoreFFI.decryptEnrollmentPackage(
            keyBase64: keyData.base64EncodedString(),
            ciphertextBase64: cipherData.base64EncodedString()),
            let payload = try? JSONDecoder().decode(EnrollmentPayload.self, from: Data(json.utf8)) else {
            throw CodeError.malformed
        }
        return payload
    }

    /// Decode standard or URL-safe base64 (with or without padding).
    static func dataFromBase64URL(_ string: String) -> Data? {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 { s += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: s)
    }
}
