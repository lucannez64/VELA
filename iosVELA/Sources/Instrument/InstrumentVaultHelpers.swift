import Foundation

/// Passwords shorter than this are flagged for review (same as Android).
let minHealthyPasswordLength = 12

extension VaultItem {
    var glyph: InstrumentIconName {
        switch kind {
        case .login: return item_type == "passkey" ? .fingerprint : .key
        case .creditCard: return .card
        case .secureNote: return .note
        case .fileBlob: return .note
        case .breachMonitor: return .shield
        }
    }

    var kindLabel: String {
        if item_type == "passkey" { return "Passkey" }
        if item_type == "identity" { return "Identity" }
        return kind.displayName
    }

    /// Secondary line in vault rows, like the prototype.
    var rowSubtitle: String {
        switch kind {
        case .login:
            if let username, !username.isEmpty { return username }
            return (url ?? "").displayHost
        case .creditCard:
            let digits = (number ?? "").filter(\.isNumber)
            let last4 = "•••• " + String(digits.suffix(4))
            if let exp, !exp.isEmpty { return "\(last4) · \(exp)" }
            return last4
        case .secureNote:
            return "Private note"
        default:
            return subtitle
        }
    }

    var updatedDate: Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: updatedAt) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: updatedAt)
    }
}

extension String {
    /// `https://www.github.com/login` → `github.com`.
    var displayHost: String {
        let trimmed = trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return "" }
        let withScheme = trimmed.contains("://") ? trimmed : "https://" + trimmed
        guard let host = URL(string: withScheme)?.host else { return trimmed }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }
}

extension Array where Element == VaultItem {
    /// Logins with a missing, short or reused password.
    var accountsNeedingAttention: Set<String> {
        let logins = filter { $0.kind == .login && $0.item_type == "login" }
        var counts: [String: Int] = [:]
        for login in logins {
            if let password = login.password, !password.isEmpty { counts[password, default: 0] += 1 }
        }
        var ids = Set<String>()
        for login in logins {
            let password = login.password ?? ""
            if password.isEmpty || password.count < minHealthyPasswordLength || (counts[password] ?? 0) > 1 {
                ids.insert(login.id)
            }
        }
        return ids
    }
}

enum Greeting {
    static func now(_ date: Date = Date()) -> String {
        switch Calendar.current.component(.hour, from: date) {
        case 5...11: return "Good morning."
        case 12...17: return "Good afternoon."
        default: return "Good evening."
        }
    }
}
