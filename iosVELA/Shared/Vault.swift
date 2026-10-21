import Foundation

/// Mirrors the Rust `VaultStore` JSON. Tombstones are now carried explicitly so
/// deletions survive sync: without them, the next pull resurrected every item
/// another device had deleted, and a push from this device silently wiped the
/// tombstone set for everyone else.
indirect enum PreservedJSON: Codable, Equatable {
    case object([String: PreservedJSON]), array([PreservedJSON]), string(String), integer(Int64), unsigned(UInt64), number(Double), boolean(Bool), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .boolean(v) }
        else if let v = try? c.decode(Int64.self) { self = .integer(v) }
        else if let v = try? c.decode(UInt64.self) { self = .unsigned(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([PreservedJSON].self) { self = .array(v) }
        else { self = .object(try c.decode([String: PreservedJSON].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .integer(let v): try c.encode(v)
        case .unsigned(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .boolean(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }
}

extension PreservedJSON {
    /// Bridge from `JSONSerialization` output (used for the core's FFI).
    init?(any: Any) {
        switch any {
        case is NSNull:
            self = .null
        case let string as String:
            self = .string(string)
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                self = .boolean(number.boolValue)
            } else if CFNumberIsFloatType(number) {
                self = .number(number.doubleValue)
            } else if number.compare(NSNumber(value: Int64.max)) == .orderedDescending {
                self = .unsigned(number.uint64Value)
            } else {
                self = .integer(number.int64Value)
            }
        case let array as [Any]:
            self = .array(array.compactMap { PreservedJSON(any: $0) })
        case let object as [String: Any]:
            var out: [String: PreservedJSON] = [:]
            for (key, value) in object {
                if let converted = PreservedJSON(any: value) { out[key] = converted }
            }
            self = .object(out)
        default:
            return nil
        }
    }

    /// Bridge to `JSONSerialization` input.
    var anyValue: Any {
        switch self {
        case .object(let value): return value.mapValues { $0.anyValue }
        case .array(let value): return value.map { $0.anyValue }
        case .string(let value): return value
        case .integer(let value): return NSNumber(value: value)
        case .unsigned(let value): return NSNumber(value: value)
        case .number(let value): return NSNumber(value: value)
        case .boolean(let value): return value
        case .null: return NSNull()
        }
    }

    var objectValue: [String: PreservedJSON]? {
        if case .object(let value) = self { return value }
        return nil
    }

    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var boolValue: Bool? {
        if case .boolean(let value) = self { return value }
        return nil
    }
}

struct VaultStore: Codable, Equatable {
    var schemaVersion: Int = 1
    var folders: [PreservedJSON] = []
    var tags: [PreservedJSON] = []
    var organizationTombstones: [PreservedJSON] = []
    var items: [VaultItem]
    var tombstones: [Tombstone] = []
    /// Per item id: JSON keys written by newer clients that `VaultItem` does
    /// not model. Re-attached on encode so editing here never drops them.
    var unknownItemKeys: [String: [String: PreservedJSON]] = [:]

    init(items: [VaultItem], tombstones: [Tombstone] = [], schemaVersion: Int = 1, folders: [PreservedJSON] = [], tags: [PreservedJSON] = [], organizationTombstones: [PreservedJSON] = [], unknownItemKeys: [String: [String: PreservedJSON]] = [:]) {
        self.schemaVersion = schemaVersion; self.folders = folders; self.tags = tags; self.organizationTombstones = organizationTombstones
        self.items = items
        self.tombstones = tombstones
        self.unknownItemKeys = unknownItemKeys
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        guard schemaVersion <= 2 else { throw DecodingError.dataCorruptedError(forKey: .schemaVersion, in: container, debugDescription: "Upgrade VELA to read this vault") }
        folders = try container.decodeIfPresent([PreservedJSON].self, forKey: .folders) ?? []
        tags = try container.decodeIfPresent([PreservedJSON].self, forKey: .tags) ?? []
        organizationTombstones = try container.decodeIfPresent([PreservedJSON].self, forKey: .organizationTombstones) ?? []
        items = try container.decode([VaultItem].self, forKey: .items)
        let rawItems = (try? container.decode([PreservedJSON].self, forKey: .items)) ?? []
        for raw in rawItems {
            guard let object = raw.objectValue, let id = object["id"]?.stringValue else { continue }
            let unknown = object.filter { !VaultItem.knownKeys.contains($0.key) }
            if !unknown.isEmpty { unknownItemKeys[id] = unknown }
        }
        // Older chunks (and older iOS builds) predate the field; the Rust core
        // defaults it the same way (`#[serde(default)]`).
        tombstones = try container.decodeIfPresent([Tombstone].self, forKey: .tombstones) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(folders, forKey: .folders)
        try container.encode(tags, forKey: .tags)
        try container.encode(organizationTombstones, forKey: .organizationTombstones)
        if unknownItemKeys.isEmpty {
            try container.encode(items, forKey: .items)
        } else {
            let itemEncoder = JSONEncoder()
            let itemDecoder = JSONDecoder()
            let merged: [PreservedJSON] = try items.map { item in
                let encoded = try itemDecoder.decode(PreservedJSON.self, from: itemEncoder.encode(item))
                guard var object = encoded.objectValue, let unknown = unknownItemKeys[item.id] else { return encoded }
                for (key, value) in unknown where object[key] == nil { object[key] = value }
                return .object(object)
            }
            try container.encode(merged, forKey: .items)
        }
        try container.encode(tombstones, forKey: .tombstones)
    }

    enum CodingKeys: String, CodingKey {
        case items, tombstones, schemaVersion, folders, tags, organizationTombstones
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
    case identity
    case passkey
    case unsupported

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .login: return "Login"
        case .creditCard: return "Card"
        case .secureNote: return "Note"
        case .fileBlob: return "File"
        case .breachMonitor: return "Breach Monitor"
        case .identity: return "Identity"
        case .passkey: return "Passkey"
        case .unsupported: return "Item"
        }
    }

    var systemImage: String {
        switch self {
        case .login: return "key.fill"
        case .creditCard: return "creditcard.fill"
        case .secureNote: return "note.text"
        case .fileBlob: return "doc.fill"
        case .breachMonitor: return "shield.lefthalf.filled"
        case .identity: return "person.fill"
        case .passkey: return "key.fill"
        case .unsupported: return "doc.fill"
        }
    }

    /// The kinds the user can create/edit on iOS.
    static var creatable: [ItemKind] { [.login, .creditCard, .secureNote, .identity] }
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
    var folderId: String?
    var tagIds: [String]?
    var customFields: [PreservedJSON]?
    var additionalUrls: [PreservedJSON]?
    var identityDetails: PreservedJSON?
    var firstName: String?
    var lastName: String?
    var ssn: String?
    var rp_id: String?
    var rp_name: String?
    var credential_id: String?
    var user_handle: String?
    var user_name: String?
    var user_display_name: String?
    var private_key: String?
    var sign_count: UInt64?
    var credential_change_needs_reauth: Bool?
    var allow_second_factor_downgrade: Bool?
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

    var kind: ItemKind { ItemKind(rawValue: item_type) ?? .unsupported }

    /// Every JSON key this struct models (property names are the wire keys).
    static let knownKeys: Set<String> = {
        let sample = VaultItem(id: "", name: "", createdAt: "", updatedAt: "")
        return Set(Mirror(reflecting: sample).children.compactMap { $0.label }).union(["first_name", "last_name", "cardholder_name"])
    }()

    /// Secondary text for list rows / autofill, by type.
    var subtitle: String {
        switch kind {
        case .login: return username ?? url ?? ""
        case .creditCard: return cardholderName ?? maskedCardNumber
        case .secureNote: return "Secure note"
        case .fileBlob: return filename ?? "File"
        case .breachMonitor: return email ?? "Breach monitor"
        case .identity: return [firstName, lastName].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
        case .passkey: return user_name ?? rp_id ?? "Passkey"
        case .unsupported: return "Update VELA to view this item"
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

// Decode wire defaults explicitly; Swift stored-property defaults are not
// applied by synthesized Decodable when an older client omits a key.
extension VaultItem {
    private enum LegacyIdentityKeys: String, CodingKey { case firstName, lastName, cardholderName }
    enum CodingKeys: String, CodingKey {
        case folderId
        case tagIds
        case customFields
        case additionalUrls
        case identityDetails
        case firstName = "first_name"
        case lastName = "last_name"
        case ssn
        case rp_id
        case rp_name
        case credential_id
        case user_handle
        case user_name
        case user_display_name
        case private_key
        case sign_count
        case credential_change_needs_reauth
        case allow_second_factor_downgrade
        case item_type
        case id
        case name
        case notes
        case createdAt
        case updatedAt
        case lastModifiedDevice
        case favorite
        case shared
        case shareRecipient
        case url
        case username
        case password
        case totp
        case app_ids
        case number
        case exp
        case cvv
        case pin
        case cardholderName = "cardholder_name"
        case title
        case content
        case filename
        case mime
        case chunks
        case sizeBytes
        case email
        case checkedAt
        case breachCount
        case breaches
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        folderId = try c.decodeIfPresent(String.self, forKey: .folderId)
        tagIds = try c.decodeIfPresent([String].self, forKey: .tagIds)
        customFields = try c.decodeIfPresent([PreservedJSON].self, forKey: .customFields)
        additionalUrls = try c.decodeIfPresent([PreservedJSON].self, forKey: .additionalUrls)
        identityDetails = try c.decodeIfPresent(PreservedJSON.self, forKey: .identityDetails)
        let legacy = try decoder.container(keyedBy: LegacyIdentityKeys.self)
        firstName = try c.decodeIfPresent(String.self, forKey: .firstName) ?? legacy.decodeIfPresent(String.self, forKey: .firstName)
        lastName = try c.decodeIfPresent(String.self, forKey: .lastName) ?? legacy.decodeIfPresent(String.self, forKey: .lastName)
        ssn = try c.decodeIfPresent(String.self, forKey: .ssn)
        rp_id = try c.decodeIfPresent(String.self, forKey: .rp_id)
        rp_name = try c.decodeIfPresent(String.self, forKey: .rp_name)
        credential_id = try c.decodeIfPresent(String.self, forKey: .credential_id)
        user_handle = try c.decodeIfPresent(String.self, forKey: .user_handle)
        user_name = try c.decodeIfPresent(String.self, forKey: .user_name)
        user_display_name = try c.decodeIfPresent(String.self, forKey: .user_display_name)
        private_key = try c.decodeIfPresent(String.self, forKey: .private_key)
        sign_count = try c.decodeIfPresent(UInt64.self, forKey: .sign_count)
        credential_change_needs_reauth = try c.decodeIfPresent(Bool.self, forKey: .credential_change_needs_reauth)
        allow_second_factor_downgrade = try c.decodeIfPresent(Bool.self, forKey: .allow_second_factor_downgrade)
        item_type = try c.decodeIfPresent(String.self, forKey: .item_type) ?? "login"
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        notes = try c.decodeIfPresent(String.self, forKey: .notes)
        createdAt = try c.decode(String.self, forKey: .createdAt)
        updatedAt = try c.decode(String.self, forKey: .updatedAt)
        lastModifiedDevice = try c.decodeIfPresent(String.self, forKey: .lastModifiedDevice)
        favorite = try c.decodeIfPresent(Bool.self, forKey: .favorite) ?? false
        shared = try c.decodeIfPresent(Bool.self, forKey: .shared) ?? false
        shareRecipient = try c.decodeIfPresent(String.self, forKey: .shareRecipient)
        url = try c.decodeIfPresent(String.self, forKey: .url)
        username = try c.decodeIfPresent(String.self, forKey: .username)
        password = try c.decodeIfPresent(String.self, forKey: .password)
        totp = try c.decodeIfPresent(String.self, forKey: .totp)
        app_ids = try c.decodeIfPresent([String].self, forKey: .app_ids)
        number = try c.decodeIfPresent(String.self, forKey: .number)
        exp = try c.decodeIfPresent(String.self, forKey: .exp)
        cvv = try c.decodeIfPresent(String.self, forKey: .cvv)
        pin = try c.decodeIfPresent(String.self, forKey: .pin)
        cardholderName = try c.decodeIfPresent(String.self, forKey: .cardholderName) ?? legacy.decodeIfPresent(String.self, forKey: .cardholderName)
        title = try c.decodeIfPresent(String.self, forKey: .title)
        content = try c.decodeIfPresent(String.self, forKey: .content)
        filename = try c.decodeIfPresent(String.self, forKey: .filename)
        mime = try c.decodeIfPresent(String.self, forKey: .mime)
        chunks = try c.decodeIfPresent([String].self, forKey: .chunks)
        sizeBytes = try c.decodeIfPresent(Int.self, forKey: .sizeBytes)
        email = try c.decodeIfPresent(String.self, forKey: .email)
        checkedAt = try c.decodeIfPresent(String.self, forKey: .checkedAt)
        breachCount = try c.decodeIfPresent(Int.self, forKey: .breachCount)
        breaches = try c.decodeIfPresent([BreachEntry].self, forKey: .breaches)
    }
}
