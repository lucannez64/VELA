import Foundation

/// Pure search + type filtering for the vault list (kept testable).
enum ItemFilter {
    static func apply(_ items: [VaultItem], query: String, kind: ItemKind?) -> [VaultItem] {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        return items.filter { item in
            (kind == nil || item.kind == kind)
                && (trimmed.isEmpty
                    || item.name.localizedCaseInsensitiveContains(trimmed)
                    || item.subtitle.localizedCaseInsensitiveContains(trimmed)
                    // §1.1: a folder or tag name finds its items.
                    || (item.folder?.localizedCaseInsensitiveContains(trimmed) == true)
                    || item.tagList.contains { $0.localizedCaseInsensitiveContains(trimmed) })
        }
    }

    /// The distinct folders/tags with item counts, folders first — the
    /// filter-chip source. Keyed case-insensitively so "Work" and "work"
    /// collapse to one chip.
    static func organizationChips(_ items: [VaultItem]) -> [OrgChip] {
        func collect(kind: String, valuesFor: (VaultItem) -> [String]) -> [OrgChip] {
            var byKey: [String: (label: String, count: Int)] = [:]
            for item in items {
                for value in valuesFor(item) where !value.isEmpty {
                    let key = value.lowercased()
                    byKey[key] = (value, (byKey[key]?.count ?? 0) + 1)
                }
            }
            return byKey.sorted { $0.key < $1.key }
                .map { OrgChip(kind: kind, key: $0.key, label: $0.value.label, count: $0.value.count) }
        }
        let folders = collect(kind: "folder") { item in
            item.folder.map { [$0] } ?? []
        }
        let tags = collect(kind: "tag") { $0.tagList }
        return folders + tags
    }
}

/// One folder/tag filter chip (see `ItemFilter.organizationChips`).
struct OrgChip: Identifiable, Equatable {
    let kind: String
    let key: String
    let label: String
    let count: Int
    /// Kind + key: a folder and a tag may share a name.
    var id: String { "\(kind):\(key)" }
}
