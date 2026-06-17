import Foundation

/// Last-writer-wins merge of two item sets by `id`, using `updatedAt`. Pure and
/// unit-tested. (Deletion propagation via tombstones is a later refinement; this
/// unions items, preferring the most recently updated copy.)
enum VaultMerge {
    static func merge(local: [VaultItem], remote: [VaultItem]) -> [VaultItem] {
        var byID: [String: VaultItem] = [:]
        for item in local { byID[item.id] = item }
        for item in remote {
            if let existing = byID[item.id] {
                if isNewer(item.updatedAt, than: existing.updatedAt) { byID[item.id] = item }
            } else {
                byID[item.id] = item
            }
        }
        return byID.values.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    static func isNewer(_ a: String, than b: String) -> Bool {
        let formatter = ISO8601DateFormatter()
        if let da = formatter.date(from: a), let db = formatter.date(from: b) { return da > db }
        return a > b // ISO-8601 Z strings sort chronologically
    }
}
