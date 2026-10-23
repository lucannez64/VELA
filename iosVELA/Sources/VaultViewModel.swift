import Foundation
import SwiftUI

@MainActor
final class VaultViewModel: ObservableObject {
    enum LockState: Equatable {
        case noVault   // nothing on device yet → Welcome / create
        case locked    // vault exists, awaiting Face ID / Touch ID
        case unlocked  // RMS in memory, vault open
    }

    enum UnlockMode { case biometric, password }

    @Published var items: [VaultItem] = []
    /// Deletions awaiting propagation (and honoring remote ones). Kept beside
    /// `items` so a local delete survives sync instead of being resurrected by
    /// another device's copy on the next pull.
    @Published var tombstones: [Tombstone] = []
    @Published var lockState: LockState = .noVault
    @Published var unlockMode: UnlockMode = .biometric
    @Published var errorMessage: String?

    private let repo: VaultRepository
    /// Folders, tags and whether schema 2 is on (derived from the envelope).
    @Published private(set) var organization = VaultOrganization()
    private var envelope = VaultStore(items: []) {
        didSet { organization = VaultOrganization(store: envelope) }
    }
    private static var organizationDeviceID: String {
        let key = "vela.organizationDeviceID"
        if let existing = UserDefaults.standard.string(forKey: key) { return existing }
        let id = UUID().uuidString.lowercased()
        UserDefaults.standard.set(id, forKey: key)
        return id
    }
    private var rms: Data?
    private var backgroundedAt: Date?
    /// Grace period the cached RMS survives in the background before the next
    /// foreground requires re-authentication instead of a silent reload. Bounds
    /// how long the master key sits in process memory while unattended, without
    /// forcing Face ID on every brief app switch.
    private static let backgroundLockTimeout: TimeInterval = 5 * 60

    /// Called after every successful `update(_:)` so the account layer can push
    /// updated share capsules to recipients. Wired in ContentView to avoid a
    /// circular dependency between VaultViewModel and AccountViewModel.
    var onItemUpdated: ((VaultItem) async -> Void)?

    /// Called after a *local* edit is persisted (add/update/delete), so the
    /// account layer can push it to the server immediately instead of waiting
    /// for the next timer tick. Not called after `applyMergedStore`, which is
    /// the sync itself writing back.
    var onLocalChange: (() -> Void)?

    init(repo: VaultRepository = VaultRepository()) {
        self.repo = repo
        bootstrap()
    }

    private func bootstrap() {
        // Launch-env switches are a convenience for development and UI tests
        // (which run Debug builds). Compiled out of release so they can never
        // serve as a wipe/seed primitive.
        #if DEBUG
        if ProcessInfo.processInfo.environment["VELA_RESET"] == "1" {
            envelope = VaultStore(items: [])
        repo.reset()
        }
        #endif
        if repo.hasVault() {
            // Don't read the RMS yet — that would fire Face ID before any UI.
            // The UnlockView drives unlock() on demand.
            unlockMode = repo.usesPasswordUnlock ? .password : .biometric
            lockState = .locked
        }

        // CI/screenshot seed: create a demo vault so the populated UI is captured.
        #if DEBUG
        if lockState != .unlocked, ProcessInfo.processInfo.environment["VELA_DEMO"] == "1" {
            try? createVault()
            // Mirrors the sample vault in docs/mobile-redesign-instrument.html.
            for item in DemoVault.items() { add(item) }
            if ProcessInfo.processInfo.environment["VELA_DEMO_RICH"] == "1" { DemoVault.decorate(self) }
        }
        #endif
    }

    /// Authenticate with Face ID / Touch ID, then decrypt and open the vault.
    func unlock() {
        errorMessage = nil
        Task { @MainActor in
            guard let context = await BiometricGate.authenticate(reason: "Unlock your VELA vault") else {
                errorMessage = "Authentication failed."
                return
            }
            do {
                let r = try repo.loadRMS(context: context)
                let loaded = try repo.load(rms: r)
                envelope = loaded; items = loaded.items; tombstones = loaded.tombstones
                rms = r
                backgroundedAt = nil
                lockState = .unlocked
                AuditLog.shared.record("vault_unlocked", "biometric")
            } catch {
                errorMessage = "Couldn't open the vault."
            }
        }
    }

    func createVault() throws {
        let r = try repo.generateAndStoreRMS()
        rms = r
        envelope = VaultStore(items: [])
        items = []
        tombstones = []
        backgroundedAt = nil
        try repo.save(currentStore, rms: r)
        unlockMode = .biometric
        lockState = .unlocked
        AuditLog.shared.record("vault_created", "biometric")
    }

    /// Create a vault protected by a password instead of biometrics.
    func createVault(password: String) throws {
        let r = try repo.generatePasswordRMS(password: password)
        rms = r
        envelope = VaultStore(items: [])
        items = []
        tombstones = []
        backgroundedAt = nil
        try repo.save(currentStore, rms: r)
        unlockMode = .password
        lockState = .unlocked
        AuditLog.shared.record("vault_created", "password")
    }

    /// Unlock a password-protected vault.
    ///
    /// KNOWN LIMITATION: `loadRMSWithPassword` runs a ~210k-iteration PBKDF2,
    /// and this whole function executes on the MainActor (this class is
    /// `@MainActor`), so unlock briefly blocks the UI thread. Moving it off
    /// to a background Task would need `VaultRepository`/`RMSStore` to be
    /// verified `Sendable` and re-verified against this project's actual
    /// Swift concurrency-checking mode — there's no existing
    /// `Task.detached`/background-actor precedent elsewhere in this codebase
    /// to confirm the pattern compiles cleanly here, and no Swift toolchain
    /// available to test it. Left as-is rather than risk an unverifiable
    /// build break; a real fix should be written and tested where the
    /// project can actually be built.
    func unlock(password: String) {
        errorMessage = nil
        do {
            let r = try repo.loadRMSWithPassword(password)
            let store = try repo.load(rms: r)
            envelope = store
            items = store.items
            tombstones = store.tombstones
            rms = r
            backgroundedAt = nil
            lockState = .unlocked
            AuditLog.shared.record("vault_unlocked", "password")
        } catch {
            errorMessage = "Wrong password."
        }
    }

    func addLogin(name: String, url: String, username: String, password: String, totp: String?) {
        add(VaultItem.newLogin(name: name, url: url, username: username, password: password, totp: totp))
    }

    @discardableResult
    func add(_ item: VaultItem) -> Bool {
        guard checkWritable(item, old: nil), !items.contains(where: { $0.id == item.id }) else { return false }
        var next = currentStore
        next.items.append(item)
        do { try commit(next) } catch { errorMessage = "Couldn't save the vault."; return false }
        AuditLog.shared.record("item_added", item.kind.displayName)
        return true
    }

    @discardableResult
    func update(_ item: VaultItem) -> Bool {
        guard let index = items.firstIndex(where: { $0.id == item.id }) else { return false }
        guard checkWritable(item, old: items[index]) else { return false }
        let updated = item.touched()
        var next = currentStore
        next.items[index] = updated
        do { try commit(next) } catch { errorMessage = "Couldn't save the vault."; return false }
        AuditLog.shared.record("item_updated", item.name)
        if let onItemUpdated = onItemUpdated { Task { await onItemUpdated(updated) } }
        return true
    }

    func delete(_ item: VaultItem) {
        var next = currentStore
        next.items.removeAll { $0.id == item.id }
        next.unknownItemKeys.removeValue(forKey: item.id)
        next.tombstones.removeAll { $0.id == item.id }
        next.tombstones.append(Tombstone(id: item.id, deletedAt: VaultClock.nowISO8601()))
        do { try commit(next) } catch { errorMessage = "Couldn't save the vault."; return }
        AuditLog.shared.record("item_deleted")
    }

    // MARK: - Folders, tags and richer fields (vault schema 2)

    /// Validates richer fields in the core before any write. Schema-2 data
    /// needs collections turned on first, exactly like Android and desktop.
    private func checkWritable(_ item: VaultItem, old: VaultItem?) -> Bool {
        errorMessage = nil
        guard envelope.schemaVersion <= 2 else {
            errorMessage = "Update VELA to edit this vault."
            return false
        }
        guard item.hasRichData || envelope.schemaVersion >= 2 else { return true }
        guard envelope.schemaVersion >= 2 else {
            errorMessage = "Turn on folders and custom fields first."
            return false
        }
        do {
            _ = try VelaCoreFFI.richItems([
                "operation": "validate",
                "organization": envelope.organizationObject,
                "rich": item.richObject,
                "old": old?.richObject ?? [:],
            ])
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    /// Upgrade this vault to schema 2 (folders, tags, custom fields). Other
    /// devices must run a VELA version that understands it before they can
    /// sync changes; the server enforces that on the next push.
    func enableCollections() throws {
        guard envelope.schemaVersion < 2 else { return }
        _ = try VelaCoreFFI.richItems(["operation": "capabilities"])
        guard let r = rms, lockState == .unlocked else {
            throw NSError(domain: "VELA", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unlock the vault first."])
        }
        // Keep an encrypted snapshot before the first schema-2 write.
        try repo.save(currentStore, rms: r)
        let backup = repo.directory.appendingPathComponent("vault.before-rich-items.enc")
        if !FileManager.default.fileExists(atPath: backup.path) {
            try FileManager.default.copyItem(at: repo.directory.appendingPathComponent("vault.enc"), to: backup)
        }
        BackupExclusion.exclude(backup) // Also repair exclusion on an existing safety copy.
        var next = currentStore
        next.schemaVersion = 2
        try commit(next)
        AuditLog.shared.record("collections_enabled")
    }

    enum OrganizationAction {
        case createFolder(name: String, parentID: String?)
        case updateFolder(id: String, name: String, parentID: String?)
        case deleteFolder(id: String)
        case createTag(name: String)
        case renameTag(id: String, name: String)
        case deleteTag(id: String)

        var json: [String: Any] {
            switch self {
            case let .createFolder(name, parent):
                var object: [String: Any] = ["operation": "createFolder", "name": name]
                if let parent { object["parentId"] = parent }
                return object
            case let .updateFolder(id, name, parent):
                var object: [String: Any] = ["operation": "updateFolder", "id": id, "name": name]
                if let parent { object["parentId"] = parent }
                return object
            case let .deleteFolder(id): return ["operation": "deleteFolder", "id": id]
            case let .createTag(name): return ["operation": "createTag", "name": name]
            case let .renameTag(id, name): return ["operation": "renameTag", "id": id, "name": name]
            case let .deleteTag(id): return ["operation": "deleteTag", "id": id]
            }
        }
    }

    /// Change folders/tags through the core, then repair items that pointed
    /// at a deleted folder or tag.
    func mutateOrganization(_ action: OrganizationAction) throws {
        guard envelope.schemaVersion == 2 else {
            throw NSError(domain: "VELA", code: 2, userInfo: [NSLocalizedDescriptionKey: "Turn on folders and custom fields first."])
        }
        let result = try VelaCoreFFI.richItems([
            "operation": "mutate",
            "deviceId": Self.organizationDeviceID,
            "organization": envelope.organizationObject,
            "action": action.json,
        ])
        func list(_ key: String) -> [PreservedJSON] {
            ((result[key] as? [Any]) ?? []).compactMap { PreservedJSON(any: $0) }
        }
        var next = currentStore
        next.folders = list("folders")
        next.tags = list("tags")
        next.organizationTombstones = list("organizationTombstones")
        let now = VaultClock.nowISO8601()
        for index in next.items.indices where next.items[index].folderId != nil || next.items[index].tagIds != nil {
            let repaired = try VelaCoreFFI.richItems([
                "operation": "repair",
                "organization": next.organizationObject,
                "rich": next.items[index].richObject,
            ])
            let folder = repaired["folderId"] as? String
            let tags = repaired["tagIds"] as? [String]
            if folder != next.items[index].folderId || tags != next.items[index].tagIds {
                next.items[index].folderId = folder
                next.items[index].tagIds = tags
                next.items[index].updatedAt = now
            }
        }
        try commit(next)
    }

    /// Lock the vault: drop the in-memory RMS and items, return to the unlock screen.
    func lock() {
        guard repo.hasVault() else { return }
        rms = nil
        items = []
        tombstones = []
        // The envelope holds the same decrypted items; drop it too.
        envelope = VaultStore(items: [])
        lockState = .locked
        AuditLog.shared.record("vault_locked")
    }

    /// Adopt an RMS recovered during enrollment, securing it with the chosen mode,
    /// then open an (empty) vault ready for the first sync to populate.
    func adoptVault(rms newRMS: Data, keyEpoch: Int,
                    mode: UnlockMode, password: String?) throws {
        guard keyEpoch >= 1 else { throw VaultError.crypto }
        switch mode {
        case .biometric:
            try repo.adoptRMSBiometric(newRMS)
        case .password:
            guard let password = password, !password.isEmpty else { throw VaultError.crypto }
            try repo.adoptRMSWithPassword(newRMS, password: password)
        }
        rms = newRMS
        envelope = VaultStore(items: [])
        items = []
        tombstones = []
        backgroundedAt = nil
        try repo.save(currentStore, rms: newRMS)
        try repo.saveKeyEpoch(keyEpoch, rms: newRMS)
        unlockMode = mode
        lockState = .unlocked
    }

    func loadAuthenticatedKeyEpoch() throws -> Int? {
        guard let rms else { throw VaultError.crypto }
        return try repo.loadKeyEpoch(rms: rms)
    }

    func saveAuthenticatedKeyEpoch(_ keyEpoch: Int) throws {
        guard let rms else { throw VaultError.crypto }
        try repo.saveKeyEpoch(keyEpoch, rms: rms)
    }

    /// Security model (matches Android on background): drop decrypted plaintext
    /// from memory but keep the RMS session, so a brief foreground reloads
    /// without re-auth. The session itself is time-bounded — see reloadFromSession.
    func clearMemory() {
        guard lockState == .unlocked else { return }
        items = []
        tombstones = []
        envelope = VaultStore(items: [])
        backgroundedAt = Date()
    }

    /// Reload decrypted items from the kept session (used on foreground). If the
    /// app was backgrounded longer than `backgroundLockTimeout`, the cached RMS
    /// is dropped and the user must re-authenticate instead of silently reloading.
    func reloadFromSession() {
        guard lockState == .unlocked, let rms = rms else { return }
        if let backgroundedAt = backgroundedAt, Date().timeIntervalSince(backgroundedAt) > Self.backgroundLockTimeout {
            lock()
            return
        }
        do {
            let store = try repo.load(rms: rms)
            envelope = store
            items = store.items
            tombstones = store.tombstones
            backgroundedAt = nil
        } catch {
            // Never mark a failed reload as a loaded empty vault.
            lock()
            errorMessage = "Couldn't reload the vault."
        }
    }

    /// Wipe the on-device vault entirely (reset local security).
    func wipe() {
        envelope = VaultStore(items: [])
        repo.reset()
        rms = nil
        items = []
        tombstones = []
        backgroundedAt = nil
        lockState = .noVault
    }

    // MARK: - Phase 4 (server sync) accessors

    /// The in-memory RMS, available while unlocked (needed to seal sync/share blobs).
    var currentRMS: Data? { rms }

    /// True only while the decrypted vault is in memory (unlocked and in the
    /// foreground). A sync must not start from a cleared store: merging an
    /// empty item list would drop local items that were never uploaded.
    var hasLoadedVault: Bool { lockState == .unlocked && rms != nil && backgroundedAt == nil }

    /// The full local store, available while unlocked (needed for sync).
    var currentStore: VaultStore { var value = envelope; value.items = items; value.tombstones = tombstones; return value }

    /// Replace the vault contents after a sync merge and persist locally.
    func applyMergedStore(_ merged: VaultStore) {
        // Finished in the background: SyncEngine already saved the merge to
        // disk. Keep plaintext out of memory; the foreground reload reads it.
        if backgroundedAt != nil || lockState != .unlocked { return }
        envelope = merged
        items = merged.items
        tombstones = merged.tombstones
        persist(notifyLocalChange: false)
    }

    /// Publish only after encryption and atomic disk persistence succeed.
    private func commit(_ candidate: VaultStore, notifyLocalChange: Bool = true) throws {
        guard let r = rms, lockState == .unlocked else {
            throw NSError(domain: "VELA", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unlock the vault first."])
        }
        try repo.save(candidate, rms: r)
        envelope = candidate
        items = candidate.items
        tombstones = candidate.tombstones
        if notifyLocalChange { onLocalChange?() }
    }

    private func persist(notifyLocalChange: Bool = true) {
        guard let r = rms else { return }
        do {
            try repo.save(currentStore, rms: r)
            if notifyLocalChange { onLocalChange?() }
        } catch {
            errorMessage = "Couldn't save the vault."
        }
    }
}

/// Result of one import run, mirroring the desktop/Android report.
struct VaultImportSummary {
    var source = ""
    var added = 0
    var duplicates = 0
    var skipped = 0
    var preserved = 0
    var converted = 0
    var unsupported: [String] = []
    var failure: String?

    var summary: String {
        if let failure { return "Import failed: \(failure)" }
        var text = source.isEmpty ? "" : "\(source): "
        text += "imported \(added)"
        if duplicates > 0 { text += ", \(duplicates) already in vault" }
        if preserved > 0 { text += ", \(preserved) with folders/tags/fields" }
        if converted > 0 { text += ", \(converted) converted to notes" }
        if skipped > 0 { text += ", \(skipped) item types skipped" }
        if !unsupported.isEmpty { text += " · unsupported: \(unsupported.joined(separator: ", "))" }
        return text
    }
}

extension VaultViewModel {
    /// Import a password-manager export (JSON, CSV, .1pif, .1pux). Parsing runs
    /// in the shared Rust crate; this maps the neutral entries onto the vault
    /// and writes them in one transaction.
    @discardableResult
    func importVault(data: Data) -> VaultImportSummary {
        var summary = VaultImportSummary()
        let response: [String: Any]
        do {
            response = try VelaCoreFFI.parseImport(["dataBase64": data.base64EncodedString()])
        } catch {
            summary.failure = error.localizedDescription
            return summary
        }
        summary.source = response["source"] as? String ?? ""
        summary.skipped = (response["skippedUnsupported"] as? NSNumber)?.intValue ?? 0
        if let unsupported = response["unsupported"] as? [String: Any] {
            summary.unsupported = unsupported.compactMap { key, value in
                (value as? NSNumber).map { "\(key) ×\($0.intValue)" }
            }.sorted()
        }
        guard let entries = response["entries"] as? [[String: Any]] else { return summary }

        let collections = envelope.schemaVersion >= 2
        var next = currentStore
        var orgObject = next.organizationObject
        let device = Self.organizationDeviceID
        var folderCache: [String: String] = [:]
        var tagCache: [String: String] = [:]

        func firstFolder(named name: String, parent: String?) -> String? {
            guard let folders = orgObject["folders"] as? [[String: Any]] else { return nil }
            return folders.first {
                (($0["name"] as? String)?.caseInsensitiveCompare(name) == .orderedSame)
                    && (($0["parentId"] as? String) ?? "") == (parent ?? "")
            }?["id"] as? String
        }

        func ensureFolder(_ path: String) -> String? {
            var parent: String?
            var accumulated = ""
            for raw in path.split(separator: "/") {
                let segment = raw.trimmingCharacters(in: .whitespaces)
                if segment.isEmpty { continue }
                accumulated = accumulated.isEmpty ? segment : accumulated + "/" + segment
                if let cached = folderCache[accumulated] { parent = cached; continue }
                var id = firstFolder(named: segment, parent: parent)
                if id == nil {
                    var action: [String: Any] = ["operation": "createFolder", "name": segment]
                    if let parent { action["parentId"] = parent }
                    guard let result = try? VelaCoreFFI.richItems([
                        "operation": "mutate", "deviceId": device,
                        "organization": orgObject, "action": action,
                    ]) else { return nil }
                    orgObject = result
                    id = firstFolder(named: segment, parent: parent)
                }
                guard let id else { return nil }
                folderCache[accumulated] = id
                parent = id
            }
            return parent
        }

        func ensureTag(_ name: String) -> String? {
            let trimmed = name.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { return nil }
            let key = trimmed.lowercased()
            if let cached = tagCache[key] { return cached }
            if let tags = orgObject["tags"] as? [[String: Any]],
               let existing = tags.first(where: { ($0["name"] as? String)?.caseInsensitiveCompare(trimmed) == .orderedSame })?["id"] as? String {
                tagCache[key] = existing
                return existing
            }
            guard let result = try? VelaCoreFFI.richItems([
                "operation": "mutate", "deviceId": device,
                "organization": orgObject, "action": ["operation": "createTag", "name": trimmed],
            ]) else { return nil }
            orgObject = result
            guard let id = (result["tags"] as? [[String: Any]])?
                .first(where: { ($0["name"] as? String)?.caseInsensitiveCompare(trimmed) == .orderedSame })?["id"] as? String
            else { return nil }
            tagCache[key] = id
            return id
        }

        var seenLogins = Set(items.filter { $0.kind == .login }.map { importLoginKey($0.url ?? "", $0.name, $0.username ?? "") })
        var seenCards = Set(items.filter { $0.kind == .creditCard }.map { importCardKey($0.number ?? "", $0.name) })
        var seenIdentities = Set(items.filter { $0.kind == .identity }.map { importIdentityKey($0.name, $0.notes ?? "") })

        for entry in entries {
            let kind = entry["kind"] as? String ?? "login"
            let name = importNonEmpty(entry["name"] as? String)
                ?? importNonEmpty(entry["url"] as? String)
                ?? importNonEmpty(entry["username"] as? String)
                ?? "Imported item"
            let itemType: String
            switch kind {
            case "note": itemType = "secureNote"
            case "card": itemType = "creditCard"
            case "identity": itemType = "identity"
            default: itemType = "login"
            }
            let stamp = VaultClock.nowISO8601()
            var item = VaultItem(item_type: itemType, id: UUID().uuidString.lowercased(), name: name, createdAt: stamp, updatedAt: stamp)
            item.favorite = entry["favorite"] as? Bool ?? false
            var notes = entry["notes"] as? String ?? ""
            var entryPreserved = false

            if collections {
                if let folder = importNonEmpty(entry["folder"] as? String) {
                    if let id = ensureFolder(folder) { item.folderId = id; entryPreserved = true } else { summary.converted += 1 }
                }
                if let tags = entry["tags"] as? [String], !tags.isEmpty {
                    let ids = tags.compactMap { ensureTag($0) }
                    summary.converted += tags.count - ids.count
                    if !ids.isEmpty { item.tagIds = ids; entryPreserved = true }
                }
                if let fields = entry["fields"] as? [[String: Any]], !fields.isEmpty {
                    var records: [PreservedJSON] = []
                    var dropped = 0
                    for field in fields {
                        let label = (field["label"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
                        if label.isEmpty { dropped += 1; continue }
                        let fieldKind = field["kind"] as? String ?? "text"
                        var object: [String: Any] = ["id": UUID().uuidString.lowercased(), "label": label, "type": fieldKind]
                        if fieldKind == "boolean" {
                            object["value"] = (field["value"] as? Bool) ?? ((field["value"] as? String)?.lowercased() == "true")
                        } else {
                            object["value"] = field["value"] as? String ?? ""
                        }
                        if let record = PreservedJSON(any: object) { records.append(record) }
                    }
                    summary.converted += dropped
                    if !records.isEmpty { item.customFields = records; entryPreserved = true }
                }
                if let urls = entry["extraUrls"] as? [String], !urls.isEmpty {
                    let records = urls.compactMap { raw -> PreservedJSON? in
                        let url = raw.trimmingCharacters(in: .whitespaces)
                        guard !url.isEmpty else { return nil }
                        return PreservedJSON(any: ["id": UUID().uuidString.lowercased(), "url": url, "match": "exact"])
                    }
                    if !records.isEmpty { item.additionalUrls = records; entryPreserved = true }
                }
                if let details = importIdentityDetails(entry) {
                    item.identityDetails = details
                    entryPreserved = true
                }
                if entryPreserved {
                    let valid = (try? VelaCoreFFI.richItems([
                        "operation": "validate", "organization": orgObject,
                        "rich": item.richObject, "old": [:],
                    ])) != nil
                    if !valid {
                        item.folderId = nil
                        item.tagIds = nil
                        item.customFields = nil
                        item.additionalUrls = nil
                        item.identityDetails = nil
                        entryPreserved = false
                        summary.converted += 1
                    }
                }
            }

            if !collections || !entryPreserved {
                let folded = importFoldIntoNotes(entry)
                if !folded.isEmpty {
                    notes = notes.isEmpty ? folded : notes + "\n" + folded
                    summary.converted += 1
                }
            }
            item.notes = importNonEmpty(notes)

            switch kind {
            case "login":
                item.url = importNonEmpty(entry["url"] as? String)
                item.username = importNonEmpty(entry["username"] as? String)
                item.password = entry["password"] as? String ?? ""
                item.totp = importNonEmpty(entry["totp"] as? String)
                let key = importLoginKey(item.url ?? "", item.name, item.username ?? "")
                if seenLogins.contains(key) { summary.duplicates += 1; continue }
                seenLogins.insert(key)
            case "note":
                item.title = item.name
                item.content = notes
            case "card":
                let card = entry["card"] as? [String: Any] ?? [:]
                item.number = importNonEmpty(card["number"] as? String)
                item.exp = importNonEmpty(card["expiry"] as? String)
                item.cvv = importNonEmpty(card["cvv"] as? String)
                item.pin = importNonEmpty(card["pin"] as? String)
                item.cardholderName = importNonEmpty(card["cardholder"] as? String)
                let key = importCardKey(item.number ?? "", item.name)
                if seenCards.contains(key) { summary.duplicates += 1; continue }
                seenCards.insert(key)
            case "identity":
                let identity = entry["identity"] as? [String: Any] ?? [:]
                item.firstName = importNonEmpty(identity["first"] as? String)
                item.lastName = importNonEmpty(identity["last"] as? String)
                item.ssn = importNonEmpty(identity["ssn"] as? String)
                let key = importIdentityKey(item.name, notes)
                if seenIdentities.contains(key) { summary.duplicates += 1; continue }
                seenIdentities.insert(key)
            default:
                continue
            }

            next.items.append(item)
            summary.added += 1
            if entryPreserved { summary.preserved += 1 }

            if let attachments = entry["attachments"] as? [[String: Any]] {
                for attachment in attachments {
                    let file = attachment["fileName"] as? String ?? "attachment"
                    let noteStamp = VaultClock.nowISO8601()
                    var note = VaultItem(item_type: "secureNote", id: UUID().uuidString.lowercased(),
                                         name: "\(name) — \(file)", createdAt: noteStamp, updatedAt: noteStamp)
                    note.title = file
                    note.content = attachment["note"] as? String ?? ""
                    next.items.append(note)
                    summary.added += 1
                    summary.preserved += 1
                }
            }
        }

        next.folders = (orgObject["folders"] as? [Any])?.compactMap { PreservedJSON(any: $0) } ?? next.folders
        next.tags = (orgObject["tags"] as? [Any])?.compactMap { PreservedJSON(any: $0) } ?? next.tags
        do {
            try commit(next)
            AuditLog.shared.record("vault_imported", summary.source)
        } catch {
            summary.failure = error.localizedDescription
        }
        return summary
    }
}

private func importNonEmpty(_ value: String?) -> String? {
    guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
    return value
}

private func importLoginKey(_ url: String, _ name: String, _ username: String) -> String {
    "\(url.lowercased())|\(name.lowercased())|\(username.lowercased())"
}

private func importCardKey(_ number: String, _ name: String) -> String {
    "\(number.filter(\.isNumber).suffix(4))|\(name.lowercased())"
}

private func importIdentityKey(_ name: String, _ notes: String) -> String {
    "\(name.lowercased())|\(notes.lowercased())"
}

private func importIdentityDetails(_ entry: [String: Any]) -> PreservedJSON? {
    guard let identity = entry["identity"] as? [String: Any] else { return nil }
    var details: [String: Any] = [:]
    if let middle = importNonEmpty(identity["middle"] as? String) { details["middleName"] = middle }
    if let email = importNonEmpty(identity["email"] as? String) { details["email"] = email }
    if let phone = importNonEmpty(identity["phone"] as? String) { details["phone"] = phone }
    if let company = importNonEmpty(identity["company"] as? String) { details["company"] = company }
    if let jobTitle = importNonEmpty(identity["jobTitle"] as? String) { details["jobTitle"] = jobTitle }
    if let addresses = identity["addresses"] as? [[String: Any]] {
        let records: [[String: Any]] = addresses.compactMap { address in
            let joined = ["line1", "city", "postal"].contains { importNonEmpty(address[$0] as? String) != nil }
            guard joined else { return nil }
            return [
                "id": UUID().uuidString.lowercased(),
                "label": address["label"] as? String ?? "",
                "line1": address["line1"] as? String ?? "",
                "line2": address["line2"] as? String ?? "",
                "city": address["city"] as? String ?? "",
                "region": address["region"] as? String ?? "",
                "postalCode": address["postal"] as? String ?? "",
                "countryCode": address["country"] as? String ?? "",
            ]
        }
        if !records.isEmpty { details["addresses"] = records }
    }
    guard !details.isEmpty else { return nil }
    return PreservedJSON(any: details)
}

private func importFoldIntoNotes(_ entry: [String: Any]) -> String {
    var lines: [String] = []
    if let folder = importNonEmpty(entry["folder"] as? String) { lines.append("Folder: \(folder)") }
    if let tags = entry["tags"] as? [String], !tags.isEmpty { lines.append("Tags: \(tags.joined(separator: ", "))") }
    if let fields = entry["fields"] as? [[String: Any]], !fields.isEmpty {
        lines.append("Custom fields:")
        for field in fields {
            lines.append("  \(field["label"] as? String ?? ""): \(field["value"] ?? "")")
        }
    }
    if let urls = entry["extraUrls"] as? [String], !urls.isEmpty {
        lines.append("Additional websites:")
        lines.append(contentsOf: urls.map { "  \($0)" })
    }
    if (entry["kind"] as? String) == "identity", let identity = entry["identity"] as? [String: Any] {
        var details: [String] = []
        for (key, label) in [("email", "Email"), ("phone", "Phone"), ("company", "Company"), ("jobTitle", "Job title")] {
            if let value = importNonEmpty(identity[key] as? String) { details.append("  \(label): \(value)") }
        }
        if let addresses = identity["addresses"] as? [[String: Any]] {
            for address in addresses {
                let joined = ["line1", "line2", "city", "region", "postal", "country"]
                    .compactMap { importNonEmpty(address[$0] as? String) }
                    .joined(separator: ", ")
                if !joined.isEmpty { details.append("  Address: \(joined)") }
            }
        }
        if !details.isEmpty {
            lines.append("Identity:")
            lines.append(contentsOf: details)
        }
    }
    return lines.joined(separator: "\n")
}
