import Foundation

/// A single outbound share entry: maps a sent `share_id` back to the vault item and
/// the recipient's share public key so the sender can re-seal on update.
struct ShareRecord: Codable, Equatable {
    let shareID: String
    let vaultItemID: String
    let recipientUserID: String
    /// The recipient's share public key (base64, 1600 B), fetched at send time.
    let recipientShareEK: String
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
        try? JSONEncoder().encode(entries).write(to: url, options: .atomic)
    }
}
