import Foundation

/// Mirrors the Rust `VaultStore` JSON. Tombstones default on the Rust side, so
/// Phase 1b only carries `items`.
struct VaultStore: Codable {
    var items: [VaultItem]
}

/// A login item, matching the Rust `VaultItem::Login` flattened JSON shape
/// (tag `item_type`, camelCase meta keys, `password`). Phase 1b supports logins
/// only; other item types come later. Property names intentionally match the
/// JSON keys so the default Codable round-trips through the Rust core unchanged.
struct VaultItem: Codable, Identifiable, Equatable {
    var item_type: String = "login"
    var id: String
    var name: String
    var notes: String?
    var createdAt: String
    var updatedAt: String
    var lastModifiedDevice: String?
    var favorite: Bool = false
    var shared: Bool = false
    var shareRecipient: String?
    var url: String
    var username: String
    var password: String
    var totp: String?

    static func newLogin(name: String, url: String, username: String, password: String, totp: String?) -> VaultItem {
        let now = VaultClock.nowISO8601()
        let cleanTotp = (totp?.isEmpty == false) ? totp : nil
        return VaultItem(
            id: UUID().uuidString,
            name: name,
            createdAt: now,
            updatedAt: now,
            url: url,
            username: username,
            password: password,
            totp: cleanTotp
        )
    }
}

enum VaultClock {
    /// RFC3339 / ISO-8601 (e.g. "2026-06-17T15:23:45Z"), which the Rust core's
    /// chrono `DateTime<Utc>` parses.
    static func nowISO8601() -> String {
        ISO8601DateFormatter().string(from: Date())
    }
}
