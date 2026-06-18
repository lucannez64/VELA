import Foundation
import CryptoKit

/// RFC 6238 TOTP. Accepts either a raw Base32 secret or an `otpauth://` URL
/// (parsing `secret`, `digits`, `period`, `algorithm`). Mirrors the Android
/// ItemDetail TOTP field.
struct TOTP {
    enum Algorithm: String {
        case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512"
    }

    let secret: Data
    let digits: Int
    let period: Int
    let algorithm: Algorithm

    /// Parse a stored TOTP string (raw Base32 secret or otpauth:// URL).
    init?(string raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        var secretText = trimmed
        var digits = 6
        var period = 30
        var algorithm = Algorithm.sha1

        if trimmed.lowercased().hasPrefix("otpauth://"),
           let comps = URLComponents(string: trimmed) {
            let query = comps.queryItems ?? []
            secretText = query.first { $0.name.lowercased() == "secret" }?.value ?? ""
            if let d = query.first(where: { $0.name.lowercased() == "digits" })?.value, let v = Int(d) { digits = v }
            if let p = query.first(where: { $0.name.lowercased() == "period" })?.value, let v = Int(p) { period = v }
            if let a = query.first(where: { $0.name.lowercased() == "algorithm" })?.value,
               let alg = Algorithm(rawValue: a.uppercased()) { algorithm = alg }
        }

        guard let secret = TOTP.base32Decode(secretText) else { return nil }
        self.secret = secret
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
    }

    /// The current code at `date`.
    func code(at date: Date = Date()) -> String {
        let counter = UInt64(date.timeIntervalSince1970) / UInt64(period)
        var bigEndian = counter.bigEndian
        let counterData = withUnsafeBytes(of: &bigEndian) { Data($0) }

        let key = SymmetricKey(data: secret)
        let digest: Data
        switch algorithm {
        case .sha1: digest = Data(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
        case .sha256: digest = Data(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
        case .sha512: digest = Data(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
        }

        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let value = binary % UInt32(pow(10, Double(digits)))
        return String(format: "%0\(digits)d", value)
    }

    /// Seconds until the current code rolls over.
    func secondsRemaining(at date: Date = Date()) -> Int {
        period - Int(date.timeIntervalSince1970) % period
    }

    /// Decode RFC 4648 Base32 (uppercased, padding/spaces ignored).
    static func base32Decode(_ input: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let cleaned = input.uppercased().replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "=", with: "")
        guard !cleaned.isEmpty else { return nil }

        var bits = 0
        var value = 0
        var out = Data()
        for char in cleaned {
            guard let idx = alphabet.firstIndex(of: char) else { return nil }
            value = (value << 5) | alphabet.distance(from: alphabet.startIndex, to: idx)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((value >> bits) & 0xff))
            }
        }
        return out.isEmpty ? nil : out
    }
}
