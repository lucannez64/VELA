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
