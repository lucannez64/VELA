import Foundation

/// Random password generator (mirrors the Android Add screen options).
/// Lowercase + digits are always on; uppercase and symbols are toggleable.
enum PasswordGenerator {
    static let symbols = "!@#$%^&*()-_=+[]{};:,.?"

    static func generate(length: Int, uppercase: Bool = true, symbols includeSymbols: Bool = true) -> String {
        let lower = "abcdefghijkmnpqrstuvwxyz"
        let upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        let digits = "23456789"
        var alphabet = Array(lower + digits)
        if uppercase { alphabet += Array(upper) }
        if includeSymbols { alphabet += Array(symbols) }

        let count = max(1, length)
        var out = String()
        out.reserveCapacity(count)
        for _ in 0..<count {
            out.append(alphabet[Int.random(in: 0..<alphabet.count)])
        }
        return out
    }
}
