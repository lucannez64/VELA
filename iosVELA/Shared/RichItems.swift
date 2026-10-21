import Foundation

// Typed views over the schema-2 records (folders, tags, custom fields,
// additional websites). Every record keeps the JSON it came from, so keys
// added by newer clients survive an edit made here. Validation and folder/tag
// mutation always go through the Rust core (`vela_ffi_rich_items_json`), the
// same engine Android, desktop and the extension use.

struct RichFolder: Identifiable, Equatable {
    let id: String
    let name: String
    let parentID: String?
}

struct RichTag: Identifiable, Equatable {
    let id: String
    let name: String
}

/// The vault's folders and tags, plus whether schema 2 is turned on.
struct VaultOrganization: Equatable {
    var enabled = false
    var folders: [RichFolder] = []
    var tags: [RichTag] = []

    init() {}

    init(store: VaultStore) {
        enabled = store.schemaVersion >= 2
        let deleted = Set(store.organizationTombstones.compactMap { $0.objectValue?["id"]?.stringValue })
        folders = store.folders.compactMap { record in
            guard let object = record.objectValue, let id = object["id"]?.stringValue, !deleted.contains(id) else { return nil }
            return RichFolder(id: id, name: object["name"]?.stringValue ?? "", parentID: object["parentId"]?.stringValue)
        }
        tags = store.tags.compactMap { record in
            guard let object = record.objectValue, let id = object["id"]?.stringValue, !deleted.contains(id) else { return nil }
            return RichTag(id: id, name: object["name"]?.stringValue ?? "")
        }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// "Work / Clients" style path, cycle-safe.
    func path(of id: String?) -> String {
        guard let id, !id.isEmpty else { return "" }
        let byID = Dictionary(folders.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var parts: [String] = []
        var seen = Set<String>()
        var cursor: String? = id
        while let current = cursor, seen.insert(current).inserted, parts.count < 16, let folder = byID[current] {
            parts.insert(folder.name, at: 0)
            cursor = folder.parentID
        }
        return parts.joined(separator: " / ")
    }

    /// Folders ordered by their full path, for pickers and lists.
    var sortedFolders: [RichFolder] {
        folders.sorted { path(of: $0.id).localizedCaseInsensitiveCompare(path(of: $1.id)) == .orderedAscending }
    }

    func tagName(_ id: String) -> String? {
        tags.first { $0.id == id }?.name
    }

    func contains(folder id: String?) -> Bool {
        guard let id, !id.isEmpty else { return false }
        return folders.contains { $0.id == id }
    }
}

enum CustomFieldKind: String, CaseIterable {
    case text, concealed, boolean

    var title: String {
        switch self {
        case .text: return "Text"
        case .concealed: return "Hidden"
        case .boolean: return "Switch"
        }
    }
}

/// Editable custom field. Unknown types from newer clients are read-only.
struct CustomFieldDraft: Identifiable, Equatable {
    var id: String
    var label: String
    var type: String
    var text: String
    var flag: Bool
    var extra: [String: PreservedJSON]

    var kind: CustomFieldKind? { CustomFieldKind(rawValue: type) }
    var isEditable: Bool { kind != nil }

    init(kind: CustomFieldKind) {
        id = UUID().uuidString.lowercased()
        label = ""
        type = kind.rawValue
        text = ""
        flag = false
        extra = [:]
    }

    init?(record: PreservedJSON) {
        guard let object = record.objectValue, let id = object["id"]?.stringValue else { return nil }
        self.id = id
        label = object["label"]?.stringValue ?? ""
        type = object["type"]?.stringValue ?? "text"
        text = object["value"]?.stringValue ?? ""
        flag = object["value"]?.boolValue ?? false
        extra = object
    }

    var record: PreservedJSON {
        var object = extra
        object["id"] = .string(id)
        object["label"] = .string(label.trimmingCharacters(in: .whitespaces))
        object["type"] = .string(type)
        switch kind {
        case .boolean: object["value"] = .boolean(flag)
        case .text, .concealed: object["value"] = .string(text)
        case .none: break // unknown type: value untouched
        }
        return .object(object)
    }

    /// Displayed value (detail screen).
    var displayValue: String {
        switch kind {
        case .boolean: return flag ? "On" : "Off"
        case .text, .concealed: return text
        case .none: return "Unsupported field, kept as is"
        }
    }
}

enum URLMatchMode: String, CaseIterable {
    case origin, exact

    var title: String { self == .origin ? "Whole site" : "Exact address" }
}

struct AdditionalURLDraft: Identifiable, Equatable {
    var id: String
    var url: String
    var match: String
    var extra: [String: PreservedJSON]

    var mode: URLMatchMode? { URLMatchMode(rawValue: match) }

    init() {
        id = UUID().uuidString.lowercased()
        url = ""
        match = URLMatchMode.origin.rawValue
        extra = [:]
    }

    init?(record: PreservedJSON) {
        guard let object = record.objectValue, let id = object["id"]?.stringValue else { return nil }
        self.id = id
        url = object["url"]?.stringValue ?? ""
        match = object["match"]?.stringValue ?? URLMatchMode.origin.rawValue
        extra = object
    }

    var record: PreservedJSON {
        var object = extra
        object["id"] = .string(id)
        object["url"] = .string(url.trimmingCharacters(in: .whitespacesAndNewlines))
        object["match"] = .string(match)
        return .object(object)
    }
}

extension VaultItem {
    var customFieldDrafts: [CustomFieldDraft] { (customFields ?? []).compactMap { CustomFieldDraft(record: $0) } }
    var additionalURLDrafts: [AdditionalURLDraft] { (additionalUrls ?? []).compactMap { AdditionalURLDraft(record: $0) } }

    var hasRichData: Bool {
        !(folderId ?? "").isEmpty || !(tagIds ?? []).isEmpty || !(customFields ?? []).isEmpty
            || !(additionalUrls ?? []).isEmpty || identityDetails != nil
    }

    /// The `RichItemData` JSON the core validates.
    var richObject: [String: Any] {
        var object: [String: Any] = [:]
        if let folderId { object["folderId"] = folderId }
        if let tagIds { object["tagIds"] = tagIds }
        if let customFields { object["customFields"] = customFields.map { $0.anyValue } }
        if let additionalUrls { object["additionalUrls"] = additionalUrls.map { $0.anyValue } }
        if let identityDetails { object["identityDetails"] = identityDetails.anyValue }
        return object
    }
}

extension VaultStore {
    var organizationObject: [String: Any] {
        ["folders": folders.map { $0.anyValue },
         "tags": tags.map { $0.anyValue },
         "organizationTombstones": organizationTombstones.map { $0.anyValue }]
    }
}
