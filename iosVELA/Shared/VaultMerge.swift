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
                    // The newer copy wins the item — including the
                    // single-valued folder — but not the tags: those union
                    // across both copies (with removal records suppressing
                    // stale carriers), so a tag added on one device survives
                    // the other device's edit of any field, and a tag
                    // removed on one device is not resurrected by this
                    // stale copy.
                    var winner = item
                    let mergedTags = mergedTagList(winner: item, loser: existing)
                    winner.tags = normalizedTags(mergedTags.tags)
                    winner.tagTombstones = mergedTags.removals
                    mergedItems[item.id] = winner
                }
            } else {
                mergedItems[item.id] = item
            }
        }
        local.items.forEach(apply)
        remote.items.forEach(apply)

        // ── Trash (§1.2): union by id, newest deletion wins. An entry yields
        // to a live copy that is newer than the deletion — a restore on
        // either side — and expires with the same retention tombstones get.
        var trashByID: [String: DeletedItem] = [:]
        for entry in local.deletedItems + remote.deletedItems {
            if let existing = trashByID[entry.item.id] {
                if isNewer(entry.deletedAt, than: existing.deletedAt) {
                    trashByID[entry.item.id] = entry
                }
            } else {
                trashByID[entry.item.id] = entry
            }
        }
        let retentionCutoff = Date().addingTimeInterval(-Double(tombstoneRetentionDays) * 86_400)
        let mergedTrash = trashByID.values.filter { entry in
            guard let deletedOn = entry.date, deletedOn >= retentionCutoff else { return false }
            if let live = mergedItems[entry.item.id] {
                return !isNewer(live.updatedAt, than: entry.deletedAt)
            }
            return true
        }

        return VaultStore(
            items: mergedItems.values.sorted {
                $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            },
            tombstones: pruneTombstones(Array(tombstoneByID.values)),
            deletedItems: mergedTrash
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

    /// The canonical tag list: trimmed, empties dropped, deduplicated
    /// case-insensitively (first spelling wins), sorted — the same rule the
    /// desktop's `vela-sync-policy::normalize_tags` applies, so every client
    /// stores the same bytes for the same tags.
    static func normalizedTags(_ values: [String]) -> [String] {
        var byKey: [String: String] = [:]
        for raw in values {
            let tag = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !tag.isEmpty else { continue }
            let key = tag.lowercased()
            if byKey[key] == nil { byKey[key] = tag }
        }
        return byKey.sorted { $0.key < $1.key }.map(\.value)
    }

    /// Collapses removal records: newest per tag, expired dropped, sorted —
    /// mirroring `vela-sync-policy::normalize_tag_removals`.
    static func normalizedRemovals(_ removals: [TagTombstone], now: Date) -> [TagTombstone] {
        let cutoff = now.timeIntervalSince1970 * 1000 - tagRemovalRetentionMs
        var byTag: [String: TagTombstone] = [:]
        for removal in removals
        where removal.date.map({ $0.timeIntervalSince1970 * 1000 > cutoff }) ?? false {
            if let existing = byTag[removal.tag] {
                if (removal.date ?? .distantPast) > (existing.date ?? .distantPast) {
                    byTag[removal.tag] = removal
                }
            } else {
                byTag[removal.tag] = removal
            }
        }
        return byTag.sorted { $0.key < $1.key }.map(\.value)
    }

    /// Removal-record retention: the same 30-day window item tombstones get.
    static let tagRemovalRetentionMs: Double = 30 * 24 * 60 * 60 * 1000

    private static func unixMillis(_ value: String) -> Double {
        (parse(value)?.timeIntervalSince1970 ?? 0) * 1000
    }

    /// The merged tag list and removal records for a merge where `winner`'s
    /// copy already won the item. Mirrors `vela-sync-policy::merge_org_fields`.
    static func mergedTagList(winner: VaultItem, loser: VaultItem) -> (
        tags: [String], removals: [TagTombstone]
    ) {
        let now = Date()
        let removals = normalizedRemovals(
            (winner.tagTombstones ?? []) + (loser.tagTombstones ?? []), now: now)
        let winnerKeys = Set(normalizedTags(winner.tagList).map(\.lowercased()))
        let loserKeys = Set(normalizedTags(loser.tagList).map(\.lowercased()))
        let winnerMs = unixMillis(winner.updatedAt)
        let loserMs = unixMillis(loser.updatedAt)

        let kept = normalizedTags(winner.tagList + loser.tagList).filter { tag in
            let key = tag.lowercased()
            guard let removal = removals.first(where: { $0.tag == key }) else { return true }
            var carriers: [Double] = []
            if winnerKeys.contains(key) { carriers.append(winnerMs) }
            if loserKeys.contains(key) { carriers.append(loserMs) }
            guard let oldestCarrier = carriers.min() else { return false }
            return (removal.date?.timeIntervalSince1970 ?? 0) * 1000 < oldestCarrier
        }
        return (kept, removals)
    }

    /// Records the tag removals an edit makes relative to the stored copy,
    /// and clears the records of tags the edit (re-)adds — the iOS twin of
    /// the desktop's `with_tag_removals_recorded`.
    static func recordedRemovals(
        old: [String], new: [String], previous: [TagTombstone], now: Date
    ) -> [TagTombstone] {
        let newKeys = Set(normalizedTags(new).map(\.lowercased()))
        let oldKeys = Set(normalizedTags(old).map(\.lowercased()))
        var kept = previous.filter { !newKeys.contains($0.tag.lowercased()) }
        for key in oldKeys.subtracting(newKeys) {
            kept.append(TagTombstone(tag: key, deletedAt: VaultClock.iso8601(from: now)))
        }
        return normalizedRemovals(kept, now: now)
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
