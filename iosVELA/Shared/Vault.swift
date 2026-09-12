import Foundation

/// Mirrors the Rust `VaultStore` JSON. Tombstones are now carried explicitly so
/// deletions survive sync: without them, the next pull resurrected every item
/// another device had deleted, and a push from this device silently wiped the
/// tombstone set for everyone else.
struct VaultStore: Codable, Equatable {
    var items: [VaultItem]
    var tombstones: [Tombstone] = []
    /// The trash (§1.2): deleted items, restorable until purged. Optional so
    /// chunks written by clients that predate it decode unchanged.
    var deletedItems: [DeletedItem] = []

    init(items: [VaultItem], tombstones: [Tombstone] = [], deletedItems: [DeletedItem] = []) {
        self.items = items
        self.tombstones = tombstones
        self.deletedItems = deletedItems
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        items = try container.decode([VaultItem].self, forKey: .items)
        // Older chunks (and older iOS builds) predate the field; the Rust core
        // defaults it the same way (`#[serde(default)]`).
        tombstones = try container.decodeIfPresent([Tombstone].self, forKey: .tombstones) ?? []
        deletedItems = try container.decodeIfPresent([DeletedItem].self, forKey: .deletedItems) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case items, tombstones
        case deletedItems = "deleted_items"
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
    // §1.3 item model depth. Decodable and round-trippable here; the editor
    // still offers only `creatable` on iOS.
    case address
    case bankAccount
    case apiKey
    case sshKey

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .login: return "Login"
        case .creditCard: return "Card"
        case .secureNote: return "Note"
        case .fileBlob: return "File"
        case .breachMonitor: return "Breach Monitor"
        case .address: return "Address"
        case .bankAccount: return "Bank Account"
        case .apiKey: return "API Key"
        case .sshKey: return "SSH Key"
        }
    }

    var systemImage: String {
        switch self {
        case .login: return "key.fill"
        case .creditCard: return "creditcard.fill"
        case .secureNote: return "note.text"
        case .fileBlob: return "doc.fill"
        case .breachMonitor: return "shield.lefthalf.filled"
        case .address: return "mappin.and.ellipse"
        case .bankAccount: return "banknote.fill"
        case .apiKey: return "curlybraces.square.fill"
        case .sshKey: return "terminal.fill"
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
    /// §1.1 organization: canonical tags and one optional folder name.
    /// Canonical form (trimmed, deduplicated case-insensitively, sorted) is
    /// applied by `normalizedTags` on write; the merge below unions tags and
    /// keeps the winning copy's folder, mirroring `vela-sync-policy`'s
    /// `merge_org_fields` on the desktop. Optional/ defaulted so items from
    /// clients that predate the fields decode unchanged.
    var tags: [String]? = nil
    /// Removal records for tags: without one, the union merge resurrects a
    /// removed tag from every stale copy that still carries it. `tag` is the
    /// canonical (lowercased) key; the merge suppresses a union'd tag whose
    /// removal is newer than the carrying copy's last edit, and an edit that
    /// (re-)adds the tag clears its record.
    var tagTombstones: [TagTombstone]? = nil
    var folder: String? = nil
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

    // §1.3: user-defined extra fields (meta level, wire `customFields`) and
    // previous password values (logins). Optional so items from clients
    // that predate the fields decode unchanged — the A-2 rule.
    var customFields: [CustomField]?
    var password_history: [PasswordHistoryEntry]?

    // §1.3 new item types — direct wire spellings.
    // address
    var full_name: String?
    var street: String?
    var street_line2: String?
    var city: String?
    var state: String?
    var postal_code: String?
    var country: String?
    var phone: String?
    // bankAccount
    var bank_name: String?
    var account_kind: String?
    var holder: String?
    var account_number: String?
    var routing_number: String?
    var iban: String?
    var swift: String?
    // apiKey
    var api_key: String?
    var expires: String?
    // sshKey
    var kind: String?
    var public_key: String?
    var private_key: String?
    var passphrase: String?
    var comment: String?

    var kind: ItemKind { ItemKind(rawValue: item_type) ?? .login }

    /// The item's tags (never nil for UI use).
    var tagList: [String] { tags ?? [] }

    /// Secondary text for list rows / autofill, by type.
    var subtitle: String {
        switch kind {
        case .login: return username ?? url ?? ""
        case .creditCard: return cardholderName ?? maskedCardNumber
        case .secureNote: return "Secure note"
        case .fileBlob: return filename ?? "File"
        case .breachMonitor: return email ?? "Breach monitor"
        // §1.3: non-secret identifiers for the new types.
        case .address: return city ?? full_name ?? "Address"
        case .bankAccount: return holder ?? bank_name ?? "Bank account"
        case .apiKey: return url ?? username ?? "API key"
        case .sshKey: return kind ?? comment ?? "SSH key"
        }
    }

    /// §1.3: user-defined extra fields (never nil for UI use).
    var customFieldList: [CustomField] { customFields ?? [] }

    /// §1.3: previous password values (never nil for UI use).
    var passwordHistoryList: [PasswordHistoryEntry] { password_history ?? [] }

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

    /// Records the tag removals this edit makes relative to `existing`, and
    /// clears the records of tags this edit (re-)adds — the iOS twin of the
    /// desktop's `with_tag_removals_recorded`.
    func withTagRemovalsRecorded(_ existing: VaultItem, now: Date = Date()) -> VaultItem {
        var copy = self
        copy.tagTombstones = VaultMerge.recordedRemovals(
            old: existing.tagList,
            new: tagList,
            previous: existing.tagTombstones ?? [],
            now: now)
        return copy
    }

    /// How many previous passwords are kept per login (§1.3) — the desktop's cap.
    static let maxPasswordHistory = 12

    /// Records the previous password into the history when this edit changes
    /// a login's password; the diff is against `existing` (the stored copy)
    /// and the record is capped, newest first — the iOS twin of the desktop's
    /// `with_password_history_recorded`.
    func withPasswordHistoryRecorded(_ existing: VaultItem, now: Date = Date()) -> VaultItem {
        guard kind == .login, existing.kind == .login,
              let previous = existing.password, !previous.isEmpty,
              password != previous
        else { return self }
        var copy = self
        var history = existing.passwordHistoryList
        history.insert(
            PasswordHistoryEntry(password: previous, changedAt: VaultClock.iso8601(from: now)),
            at: 0)
        if history.count > VaultItem.maxPasswordHistory {
            history = Array(history.prefix(VaultItem.maxPasswordHistory))
        }
        copy.password_history = history
        return copy
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
    static func nowISO8601() -> String {        ISO8601DateFormatter().string(from: Date())
    }

    /// RFC3339 for an arbitrary instant (used by tag removal records).
    static func iso8601(from date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    /// Parses an RFC3339 timestamp back to a `Date`, tolerating the
    /// fractional seconds the Rust core writes.
    static func date(fromISO8601 value: String) -> Date? {
        let plain = ISO8601DateFormatter()
        if let date = plain.date(from: value) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value)
    }
}

/// A recorded tag removal (see `VaultItem.tagTombstones`). Serialized as
/// `{"tag": "work", "deleted_at": "<rfc3339>"}` to match the desktop's
/// `TagTombstone`.
struct TagTombstone: Codable, Equatable {
    var tag: String
    var deletedAt: String

    enum CodingKeys: String, CodingKey {
        case tag
        case deletedAt = "deleted_at"
    }

    var date: Date? { VaultClock.date(fromISO8601: deletedAt) }
}

/// §1.3: a user-defined extra field (see `VaultItem.customFields`). Serialized
/// to match the desktop's `CustomField` (`field_type` is snake_case there).
struct CustomField: Codable, Equatable {
    var label: String
    var value: String
    var fieldType: String

    enum CodingKeys: String, CodingKey {
        case label
        case value
        case fieldType = "field_type"
    }

    var isHidden: Bool { fieldType == "hidden" }
}

/// §1.3: a previous password value with the time it was replaced. Old
/// passwords are still secrets. Matches the desktop's `PasswordHistoryEntry`.
struct PasswordHistoryEntry: Codable, Equatable {
    var password: String
    var changedAt: String

    enum CodingKeys: String, CodingKey {
        case password
        case changedAt = "changed_at"
    }
}

/// An item sitting in the trash (§1.2): the tombstone propagates the
/// deletion, the copy makes an undo possible. Serialized as
/// `{"item": …, "deleted_at": …, "deleted_by": …}` to match the desktop.
struct DeletedItem: Codable, Equatable {
    var item: VaultItem
    var deletedAt: String
    var deletedBy: String?

    enum CodingKeys: String, CodingKey {
        case item
        case deletedAt = "deleted_at"
        case deletedBy = "deleted_by"
    }

    init(item: VaultItem, deletedAt: String, deletedBy: String? = nil) {
        self.item = item
        self.deletedAt = deletedAt
        self.deletedBy = deletedBy
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        item = try container.decode(VaultItem.self, forKey: .item)
        deletedAt = try container.decodeIfPresent(String.self, forKey: .deletedAt) ?? ""
        deletedBy = try container.decodeIfPresent(String.self, forKey: .deletedBy)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(item, forKey: .item)
        try container.encode(deletedAt, forKey: .deletedAt)
        try container.encodeIfPresent(deletedBy, forKey: .deletedBy)
    }

    var date: Date? { VaultClock.date(fromISO8601: deletedAt) }
}
