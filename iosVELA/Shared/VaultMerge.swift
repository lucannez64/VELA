import Foundation

/// Merge of two vault stores by item `id`.
///
/// Items: last-writer-wins by `updatedAt`. Tombstones: a deletion recorded on
/// any device beats a copy of the item whose `updatedAt` predates it — without
/// this, the next sync resurrected every deleted credential (and an attacker-
/// rolled-back chunk could re-import them). Pure and unit-tested. Semantics
/// mirror Android's `mergeVaultStores` / the Rust core.
enum VaultMerge {
    /// Tombstones older than this are dropped once merged (parity with Android's
    /// 30-day prune; long enough for any realistic offline device to catch up).
    static let tombstoneRetentionDays = 30

    static func mergeStores(local: VaultStore, remote: VaultStore) -> VaultStore {
        var tombstoneByID: [String: Tombstone] = [:]
        for tombstone in local.tombstones + remote.tombstones {
            if let existing = tombstoneByID[tombstone.id] {
                if isNewerOrEqual(tombstone.deletedAt, than: existing.deletedAt) {
                    tombstoneByID[tombstone.id] = tombstone
                }
            } else {
                tombstoneByID[tombstone.id] = tombstone
            }
        }

        var mergedItems: [String: VaultItem] = [:]
        // Insertion order matters only for stable output; items are sorted below.
        func apply(_ item: VaultItem) {
            if let tombstone = tombstoneByID[item.id],
               isNewerOrEqual(tombstone.deletedAt, than: item.updatedAt) {
                mergedItems.removeValue(forKey: item.id)
                return
            }
            if let existing = mergedItems[item.id] {
                if isNewerOrEqual(item.updatedAt, than: existing.updatedAt) {
                    mergedItems[item.id] = item
                }
            } else {
                mergedItems[item.id] = item
            }
        }
        local.items.forEach(apply)
        remote.items.forEach(apply)

        return VaultStore(
            items: mergedItems.values.sorted {
                $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            },
            tombstones: pruneTombstones(Array(tombstoneByID.values))
        )
    }

    /// Item-only convenience (used by tests and callers that carry no
    /// tombstones locally).
    static func merge(local: [VaultItem], remote: [VaultItem]) -> [VaultItem] {
        mergeStores(local: VaultStore(items: local), remote: VaultStore(items: remote)).items
    }

    static func isNewer(_ a: String, than b: String) -> Bool {
        if let da = Self.parse(a), let db = Self.parse(b) { return da > db }
        return a > b // ISO-8601 Z strings sort chronologically
    }

    static func isNewerOrEqual(_ a: String, than b: String) -> Bool {
        a == b || isNewer(a, than: b)
    }

    /// RFC3339 timestamps arrive in two shapes here: iOS writes second
    /// precision ("…:45Z"), the Rust core's chrono may write fractional
    /// seconds ("…:45.123Z"). The plain formatter rejects the latter, so try
    /// both before falling back to string comparison.
    private static func parse(_ value: String) -> Date? {
        let plain = ISO8601DateFormatter()
        if let date = plain.date(from: value) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value)
    }

    private static func pruneTombstones(_ tombstones: [Tombstone]) -> [Tombstone] {
        let cutoff = Date().addingTimeInterval(-Double(tombstoneRetentionDays) * 86_400)
        return tombstones.filter { entry in
            guard let deleted = parse(entry.deletedAt) else { return true }
            return deleted >= cutoff
        }
    }
}
