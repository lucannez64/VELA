import Foundation

/// Pure search + type filtering for the vault list (kept testable).
enum ItemFilter {
    static func apply(_ items: [VaultItem], query: String, kind: ItemKind?) -> [VaultItem] {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        return items.filter { item in
            (kind == nil || item.kind == kind)
                && (trimmed.isEmpty
                    || item.name.localizedCaseInsensitiveContains(trimmed)
                    || item.subtitle.localizedCaseInsensitiveContains(trimmed))
        }
    }
}
