import Foundation
import CryptoKit

struct PasswordBreachResult {
    let breached: Bool
    let count: Int
}

struct BreachEntry: Identifiable {
    let id = UUID()
    let name: String
    let title: String
    let domain: String
    let breachDate: String
    let dataClasses: [String]
}

/// Have I Been Pwned checks, mirroring the Android `BreachCheckService`.
///
/// Passwords use the **k-anonymity** range API: only the first 5 chars of the
/// SHA-1 hash ever leave the device — never the password or its full hash.
/// Email checks hit the breachedaccount API, which requires an HIBP API key
/// (so without one this surfaces the same "requires API key" error as Android).
enum BreachService {
    struct ServiceError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func checkPassword(_ password: String, session: URLSession = .shared) async throws -> PasswordBreachResult {
        let digest = Insecure.SHA1.hash(data: Data(password.utf8))
        let hash = digest.map { String(format: "%02X", $0) }.joined()
        let prefix = String(hash.prefix(5))
        let suffix = String(hash.dropFirst(5))

        var req = URLRequest(url: URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")!)
        req.setValue("VELA-iOS-App", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw ServiceError(message: "Pwned Passwords API error")
        }
        for line in String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            if parts.count == 2, String(parts[0]) == suffix {
                return PasswordBreachResult(breached: true, count: Int(parts[1]) ?? 0)
            }
        }
        return PasswordBreachResult(breached: false, count: 0)
    }

    static func checkEmail(_ email: String, session: URLSession = .shared) async throws -> [BreachEntry] {
        let encoded = email.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? email
        var req = URLRequest(url: URL(string: "https://haveibeenpwned.com/api/v3/breachedaccount/\(encoded)?truncateResponse=false")!)
        req.setValue("VELA-iOS-App", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw ServiceError(message: "No response")
        }
        switch http.statusCode {
        case 404: return []
        case 401, 403: throw ServiceError(message: "Email checks require an HIBP API key")
        case 200..<300: break
        default: throw ServiceError(message: "HIBP API error: HTTP \(http.statusCode)")
        }

        let array = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] ?? []
        return array.map { json in
            BreachEntry(
                name: json["Name"] as? String ?? "",
                title: json["Title"] as? String ?? "",
                domain: json["Domain"] as? String ?? "",
                breachDate: json["BreachDate"] as? String ?? "",
                dataClasses: json["DataClasses"] as? [String] ?? []
            )
        }
    }
}
