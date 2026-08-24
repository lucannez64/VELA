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
            addLogin(name: "GitHub", url: "https://github.com", username: "alice", password: "h7$Kp2!q", totp: nil)
            addLogin(name: "Proton Mail", url: "https://proton.me", username: "alice@proton.me", password: "Zq9!vT3m", totp: nil)
            addLogin(name: "Cloudflare", url: "https://dash.cloudflare.com", username: "alice", password: "Wp4#nL8x", totp: nil)
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
                items = try repo.load(rms: r).items
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
        items = []
        tombstones = []
        backgroundedAt = nil
        try repo.save(VaultStore(items: items), rms: r)
        unlockMode = .biometric
        lockState = .unlocked
        AuditLog.shared.record("vault_created", "biometric")
    }

    /// Create a vault protected by a password instead of biometrics.
    func createVault(password: String) throws {
        let r = try repo.generatePasswordRMS(password: password)
        rms = r
        items = []
        tombstones = []
        backgroundedAt = nil
        try repo.save(VaultStore(items: items), rms: r)
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
        items.append(VaultItem.newLogin(name: name, url: url, username: username, password: password, totp: totp))
        persist()
    }

    /// Add any item kind (login / card / note).
    func add(_ item: VaultItem) {
        items.append(item)
        persist()
        AuditLog.shared.record("item_added", item.kind.displayName)
    }

    /// Replace an existing item by id, stamping `updatedAt`.
    func update(_ item: VaultItem) {
        guard let index = items.firstIndex(where: { $0.id == item.id }) else { return }
        let updated = item.touched()
        items[index] = updated
        persist()
        AuditLog.shared.record("item_updated", item.name)
        if let onItemUpdated = onItemUpdated {
            Task { await onItemUpdated(updated) }
        }
    }

    func delete(_ item: VaultItem) {
        items.removeAll { $0.id == item.id }
        // Record the deletion so sync propagates it instead of resurrecting
        // the item from another device's (or the server's) copy.
        tombstones.removeAll { $0.id == item.id }
        tombstones.append(Tombstone(id: item.id, deletedAt: VaultClock.nowISO8601()))
        persist()
        AuditLog.shared.record("item_deleted")
    }

    /// Lock the vault: drop the in-memory RMS and items, return to the unlock screen.
    func lock() {
        guard repo.hasVault() else { return }
        rms = nil
        items = []
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
        items = []
        tombstones = []
        backgroundedAt = nil
        try repo.save(VaultStore(items: items), rms: newRMS)
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
        backgroundedAt = nil
        if let store = try? repo.load(rms: rms) {
            items = store.items
            tombstones = store.tombstones
        }
    }

    /// Wipe the on-device vault entirely (reset local security).
    func wipe() {
        repo.reset()
        rms = nil
        items = []
        lockState = .noVault
    }

    // MARK: - Phase 4 (server sync) accessors

    /// The in-memory RMS, available while unlocked (needed to seal sync/share blobs).
    var currentRMS: Data? { rms }

    /// The full local store, available while unlocked (needed for sync).
    var currentStore: VaultStore { VaultStore(items: items, tombstones: tombstones) }

    /// Replace the vault contents after a sync merge and persist locally.
    func applyMergedStore(_ merged: VaultStore) {
        items = merged.items
        tombstones = merged.tombstones
        persist()
    }

    private func persist() {
        guard let r = rms else { return }
        do {
            try repo.save(VaultStore(items: items, tombstones: tombstones), rms: r)
        } catch {
            errorMessage = "Couldn't save the vault."
        }
    }
}
