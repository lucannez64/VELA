import Foundation

/// Mirrors the Rust `VaultStore` JSON. Tombstones are now carried explicitly so
/// deletions survive sync: without them, the next pull resurrected every item
/// another device had deleted, and a push from this device silently wiped the
/// tombstone set for everyone else.
struct VaultStore: Codable, Equatable {
    var items: [VaultItem]
    var tombstones: [Tombstone] = []

    init(items: [VaultItem], tombstones: [Tombstone] = []) {
        self.items = items
        self.tombstones = tombstones
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        items = try container.decode([VaultItem].self, forKey: .items)
        // Older chunks (and older iOS builds) predate the field; the Rust core
        // defaults it the same way (`#[serde(default)]`).
        tombstones = try container.decodeIfPresent([Tombstone].self, forKey: .tombstones) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case items, tombstones
    }
}

/// Mirrors the Rust `Tombstone`: proof that an item was deleted on some device,
/// compared against `updatedAt` during merge so "delete" wins over a stale copy.
struct Tombstone: Codable, Equatable {
    var id: String
    var deletedAt: String
    var deletedBy: String?

    init(id: String, deletedAt: String, deletedBy: String? = nil) {
        self.id = id
        self.deletedAt = deletedAt
        self.deletedBy = deletedBy
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        deletedAt = try container.decodeIfPresent(String.self, forKey: .deletedAt) ?? ""
        deletedBy = try container.decodeIfPresent(String.self, forKey: .deletedBy)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(deletedAt, forKey: .deletedAt)
        try container.encodeIfPresent(deletedBy, forKey: .deletedBy)
    }

    enum CodingKeys: String, CodingKey {
        case id
        case deletedAt = "deleted_at"
        case deletedBy = "deleted_by"
    }
}

/// The item kinds VELA supports. iOS creates Login / Card / Note (matching the
/// Android Add screen); the other variants are modelled so they round-trip
/// through sync without data loss.
enum ItemKind: String, CaseIterable, Identifiable {
    case login
    case creditCard
    case secureNote
    case fileBlob
    case breachMonitor

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .login: return "Login"
        case .creditCard: return "Card"
        case .secureNote: return "Note"
        case .fileBlob: return "File"
        case .breachMonitor: return "Breach Monitor"
        }
    }

    var systemImage: String {
        switch self {
        case .login: return "key.fill"
        case .creditCard: return "creditcard.fill"
        case .secureNote: return "note.text"
        case .fileBlob: return "doc.fill"
        case .breachMonitor: return "shield.lefthalf.filled"
        }
    }

    /// The kinds the user can create/edit on iOS.
    static var creatable: [ItemKind] { [.login, .creditCard, .secureNote] }
}

/// A single breach record inside a BreachMonitor item. Snake_case wire keys
/// match the Rust `BreachEntry`.
struct BreachEntry: Codable, Equatable {
    var name: String = ""
    var title: String = ""
    var domain: String = ""
    var breachDate: String = ""
    var description: String = ""
    var dataClasses: [String] = []
    var isVerified: Bool = false

    enum CodingKeys: String, CodingKey {
        case name, title, domain, description
        case breachDate = "breach_date"
        case dataClasses = "data_classes"
        case isVerified = "is_verified"
    }
}

/// A vault item. A single flat struct (rather than a Swift enum) keeps SwiftUI
/// and Codable simple while matching the Rust core's internally-tagged
/// (`item_type`) JSON with a flattened `meta`. Type-specific fields are optional
/// so a card/note decodes without login fields and vice-versa. Property names
/// equal the JSON keys (camelCase, matching the Android client) so the default
/// Codable round-trips through the core unchanged.
struct VaultItem: Codable, Identifiable, Equatable {
    var item_type: String = "login"

    // meta (flattened, camelCase)
    var id: String
    var name: String
    var notes: String?
    var createdAt: String
    var updatedAt: String
    var lastModifiedDevice: String?
    var favorite: Bool = false
    var shared: Bool = false
    var shareRecipient: String?

    // login
    var url: String?
    var username: String?
    var password: String?
    var totp: String?
    /// Apps the user linked to this login, as `androidapp://<package>`.
    ///
    /// iOS never sets this — it is Android's app association (audit A-2) — but
    /// it is decoded and re-encoded so editing an item on an iPhone does not
    /// delete the links its owner made on their phone. Optional, so it is simply
    /// absent on items that have none.
    var app_ids: [String]?

    // credit card
    var number: String?
    var exp: String?
    var cvv: String?
    var pin: String?
    var cardholderName: String?

    // secure note
    var title: String?
    var content: String?

    // file blob
    var filename: String?
    var mime: String?
    var chunks: [String]?
    var sizeBytes: Int?

    // breach monitor
    var email: String?
    var checkedAt: String?
    var breachCount: Int?
    var breaches: [BreachEntry]?

    var kind: ItemKind { ItemKind(rawValue: item_type) ?? .login }

    /// Secondary text for list rows / autofill, by type.
    var subtitle: String {
        switch kind {
        case .login: return username ?? url ?? ""
        case .creditCard: return cardholderName ?? maskedCardNumber
        case .secureNote: return "Secure note"
        case .fileBlob: return filename ?? "File"
        case .breachMonitor: return email ?? "Breach monitor"
        }
    }

    var maskedCardNumber: String {
        guard let number = number, number.count >= 4 else { return "Card" }
        return "•••• " + String(number.suffix(4))
    }

    private static func now() -> String { VaultClock.nowISO8601() }

    static func newLogin(name: String, url: String, username: String, password: String, totp: String?) -> VaultItem {
        let now = VaultItem.now()
        let cleanTotp = (totp?.isEmpty == false) ? totp : nil
        return VaultItem(item_type: "login", id: UUID().uuidString, name: name,
                         createdAt: now, updatedAt: now,
                         url: url, username: username, password: password, totp: cleanTotp)
    }

    static func newCard(name: String, number: String, exp: String, cvv: String, pin: String?, cardholderName: String?, notes: String?) -> VaultItem {
        let now = VaultItem.now()
        return VaultItem(item_type: "creditCard", id: UUID().uuidString, name: name, notes: notes,
                         createdAt: now, updatedAt: now,
                         number: number, exp: exp, cvv: cvv,
                         pin: pin?.isEmpty == false ? pin : nil,
                         cardholderName: cardholderName?.isEmpty == false ? cardholderName : nil)
    }

    static func newNote(name: String, content: String) -> VaultItem {
        let now = VaultItem.now()
        return VaultItem(item_type: "secureNote", id: UUID().uuidString, name: name,
                         createdAt: now, updatedAt: now,
                         title: name, content: content)
    }

    /// Stamp `updatedAt` (call after edits before persisting/syncing).
    func touched() -> VaultItem {
        var copy = self
        copy.updatedAt = VaultItem.now()
        return copy
    }
}

enum VaultClock {
    /// RFC3339 / ISO-8601 (e.g. "2026-06-17T15:23:45Z"), which the Rust core's
    /// chrono `DateTime<Utc>` parses.
    static func nowISO8601() -> String {
        ISO8601DateFormatter().string(from: Date())
    }
}
