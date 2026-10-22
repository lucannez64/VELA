import Foundation

/// A single outbound share entry: maps a sent `share_id` back to the vault item and
/// the recipient's share public key so the sender can re-seal on update.
struct ShareRecord: Codable, Equatable {
    let shareID: String
    let vaultItemID: String
    let recipientUserID: String
    /// The recipient's share public key (base64, 1600 B), fetched at send time.
    let recipientShareEK: String
    /// Share envelope v2: signed into every envelope of this share. Empty for
    /// shares sent before v2; recipients no longer accept updates for those.
    var lineageID: String = ""
    /// Last revision sealed (1 at first send).
    var revision: UInt64 = 0

    init(shareID: String, vaultItemID: String, recipientUserID: String,
         recipientShareEK: String, lineageID: String = "", revision: UInt64 = 0) {
        self.shareID = shareID
        self.vaultItemID = vaultItemID
        self.recipientUserID = recipientUserID
        self.recipientShareEK = recipientShareEK
        self.lineageID = lineageID
        self.revision = revision
    }

    // Manifests written before envelope v2 have no lineage or revision.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        shareID = try c.decode(String.self, forKey: .shareID)
        vaultItemID = try c.decode(String.self, forKey: .vaultItemID)
        recipientUserID = try c.decode(String.self, forKey: .recipientUserID)
        recipientShareEK = try c.decode(String.self, forKey: .recipientShareEK)
        lineageID = try c.decodeIfPresent(String.self, forKey: .lineageID) ?? ""
        revision = try c.decodeIfPresent(UInt64.self, forKey: .revision) ?? 0
    }
}

/// Persists the outbound share manifest to the shared App Group container.
///
/// This is the only place where VELA iOS stores the mapping from a local vault item
/// to the server `share_id`s needed to push updates. It does NOT contain any key material
/// or vault content — it only holds metadata the sender already knows.
final class ShareManifest {
    private var entries: [ShareRecord] = []
    private let url: URL

    init(directory: URL? = nil) {
        let dir = directory ?? AppGroup.vaultDirectory()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        url = dir.appendingPathComponent("shares_manifest.json")
        entries = (try? JSONDecoder().decode([ShareRecord].self, from: Data(contentsOf: url))) ?? []
    }

    func records(for vaultItemID: String) -> [ShareRecord] {
        entries.filter { $0.vaultItemID == vaultItemID }
    }

    func add(_ record: ShareRecord) {
        entries.removeAll { $0.shareID == record.shareID }
        entries.append(record)
        persist()
    }

    func remove(shareID: String) {
        entries.removeAll { $0.shareID == shareID }
        persist()
    }

    private func persist() {
        try? JSONEncoder().encode(entries).write(to: url, options: [.completeFileProtection, .atomic])
        BackupExclusion.exclude(url)
    }
}
