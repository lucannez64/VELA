import Foundation

struct AuditEntry: Codable, Identifiable {
    var id = UUID().uuidString
    var timestamp: String        // ISO-8601
    var action: String
    var detail: String?
}

/// A local, on-device activity log (never synced), mirroring the Android
/// `AuditLogRepository`. Append-only, capped at the most recent 1000 events.
struct AuditLog {
    static let shared = AuditLog()

    let url: URL
    private let cap = 1000

    init(directory: URL? = nil) {
        let dir = directory ?? AppGroup.vaultDirectory()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.url = dir.appendingPathComponent("audit.json")
    }

    func record(_ action: String, _ detail: String? = nil) {
        var all = entries()
        all.insert(AuditEntry(timestamp: VaultClock.nowISO8601(), action: action, detail: detail), at: 0)
        if all.count > cap { all = Array(all.prefix(cap)) }
        if let data = try? JSONEncoder().encode(all) {
            try? data.write(to: url, options: [.completeFileProtection, .atomic])
        }
    }

    /// Newest first.
    func entries() -> [AuditEntry] {
        guard let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode([AuditEntry].self, from: data) else {
            return []
        }
        return decoded
    }

    func clear() {
        try? FileManager.default.removeItem(at: url)
    }
}
