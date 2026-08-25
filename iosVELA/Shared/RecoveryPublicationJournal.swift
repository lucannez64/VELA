import Foundation
import Security

/// One account/epoch/split publication, persisted before any external write.
/// Production storage is Keychain-encrypted and device-only; tests may inject
/// a complete-file-protected directory.
struct RecoveryPublicationJournal: Codable, Equatable {
    var version = 1
    var accountID: String
    var keyEpoch: Int
    var splitID: String
    var cloudShareBase64: String
    var serverShareBase64: String
    var trustedContactShareBase64: String
    /// Blind RMS commitment staged with the server share (M18).
    var possessionHashBase64 = ""
    var serverStaged = false
    var cloudCandidateDurable = false
    var serverFinalized = false
    var cloudActive = false

    func validate() throws {
        guard version == 1, !accountID.isEmpty, keyEpoch >= 1,
              UUID(uuidString: splitID) != nil,
              !cloudShareBase64.isEmpty, !serverShareBase64.isEmpty else {
            throw RecoveryPublicationJournalError.invalid
        }
        guard !serverFinalized || (serverStaged && cloudCandidateDurable),
              !cloudActive || serverFinalized else {
            throw RecoveryPublicationJournalError.invalid
        }
    }
}

enum RecoveryPublicationJournalError: Error {
    case invalid
    case keychain(OSStatus)
}

struct RecoveryPublicationJournalStore {
    private let service = "com.vela.recovery-publication"
    private let account = "journal-v1"
    private let fileURL: URL?

    init(directory: URL? = nil) {
        if let directory {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            fileURL = directory.appendingPathComponent("recovery_publication.json")
        } else {
            fileURL = nil
        }
    }

    func load() throws -> RecoveryPublicationJournal? {
        let data: Data
        if let fileURL {
            guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
            data = try Data(contentsOf: fileURL)
        } else {
            var query = baseQuery()
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess, let found = result as? Data else {
                throw RecoveryPublicationJournalError.keychain(status)
            }
            data = found
        }
        let journal = try JSONDecoder().decode(RecoveryPublicationJournal.self, from: data)
        try journal.validate()
        return journal
    }

    func save(_ journal: RecoveryPublicationJournal) throws {
        try journal.validate()
        let data = try JSONEncoder().encode(journal)
        if let fileURL {
            try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
            BackupExclusion.exclude(fileURL)
            return
        }
        SecItemDelete(baseQuery() as CFDictionary)
        var add = baseQuery()
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw RecoveryPublicationJournalError.keychain(status)
        }
    }

    func clear() {
        if let fileURL {
            try? FileManager.default.removeItem(at: fileURL)
        } else {
            SecItemDelete(baseQuery() as CFDictionary)
        }
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}
