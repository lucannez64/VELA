import Foundation

/// Domain matching for AutoFill, mirroring the Android `findAutofillLogins` /
/// `domainsMatch` logic: a stored login matches a requested service when the
/// stored host is a suffix of the requested host on dot boundaries
/// (e.g. requested `mail.google.com` matches stored `google.com`).
enum AutofillMatch {
    /// Logins whose URL matches any of the requested service identifiers
    /// (URLs or bare domains). If no usable identifier is given, returns all logins.
    static func logins(_ items: [VaultItem], matching identifiers: [String]) -> [VaultItem] {
        let logins = items.filter { $0.item_type == "login" }
        let queries = identifiers.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard !queries.isEmpty else { return logins }
        return logins.filter { login in
            queries.contains { domainsMatch(query: $0, stored: login.url) }
        }
    }

    static func domainsMatch(query: String, stored: String) -> Bool {
        let queryHost = host(of: query) ?? query.lowercased()
        let storedHost = host(of: stored) ?? stored.lowercased()
        if queryHost == storedHost { return true }
        if isIPAddress(queryHost) { return false }

        let queryParts = queryHost.split(separator: ".").map(String.init)
        let storedParts = storedHost.split(separator: ".").map(String.init)
        // Need a real registrable-ish domain (≥2 labels) that isn't longer than the query.
        guard storedParts.count >= 2, storedParts.count <= queryParts.count else { return false }
        return Array(queryParts.suffix(storedParts.count)) == storedParts
    }

    /// Lowercased host without a leading `www.`. Accepts bare domains too.
    static func host(of value: String) -> String? {
        let normalized = (value.hasPrefix("http://") || value.hasPrefix("https://"))
            ? value : "https://\(value)"
        guard let host = URLComponents(string: normalized)?.host?.lowercased() else { return nil }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    private static func isIPAddress(_ host: String) -> Bool {
        let parts = host.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { part in
            Int(part).map { (0...255).contains($0) } ?? false
        }
    }
}
