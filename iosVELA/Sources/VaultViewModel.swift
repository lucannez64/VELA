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
    @Published var lockState: LockState = .noVault
    @Published var unlockMode: UnlockMode = .biometric
    @Published var errorMessage: String?

    private let repo: VaultRepository
    private var rms: Data?

    /// Called after every successful `update(_:)` so the account layer can push
    /// updated share capsules to recipients. Wired in ContentView to avoid a
    /// circular dependency between VaultViewModel and AccountViewModel.
    var onItemUpdated: ((VaultItem) async -> Void)?

    init(repo: VaultRepository = VaultRepository()) {
        self.repo = repo
        bootstrap()
    }

    private func bootstrap() {
        if ProcessInfo.processInfo.environment["VELA_RESET"] == "1" {
            repo.reset()
        }
        if repo.hasVault() {
            // Don't read the RMS yet — that would fire Face ID before any UI.
            // The UnlockView drives unlock() on demand.
            unlockMode = repo.usesPasswordUnlock ? .password : .biometric
            lockState = .locked
        }

        // CI/screenshot seed: create a demo vault so the populated UI is captured.
        if lockState != .unlocked, ProcessInfo.processInfo.environment["VELA_DEMO"] == "1" {
            try? createVault()
            addLogin(name: "GitHub", url: "https://github.com", username: "alice", password: "h7$Kp2!q", totp: nil)
            addLogin(name: "Proton Mail", url: "https://proton.me", username: "alice@proton.me", password: "Zq9!vT3m", totp: nil)
            addLogin(name: "Cloudflare", url: "https://dash.cloudflare.com", username: "alice", password: "Wp4#nL8x", totp: nil)
        }
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
        try repo.save(VaultStore(items: items), rms: r)
        unlockMode = .password
        lockState = .unlocked
        AuditLog.shared.record("vault_created", "password")
    }

    /// Unlock a password-protected vault.
    func unlock(password: String) {
        errorMessage = nil
        do {
            let r = try repo.loadRMSWithPassword(password)
            items = try repo.load(rms: r).items
            rms = r
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
    func adoptVault(rms newRMS: Data, mode: UnlockMode, password: String?) throws {
        switch mode {
        case .biometric:
            try repo.adoptRMSBiometric(newRMS)
        case .password:
            guard let password = password, !password.isEmpty else { throw VaultError.crypto }
            try repo.adoptRMSWithPassword(newRMS, password: password)
        }
        rms = newRMS
        items = []
        try repo.save(VaultStore(items: items), rms: newRMS)
        unlockMode = mode
        lockState = .unlocked
    }

    /// Security model (matches Android on background): drop decrypted plaintext
    /// from memory but keep the RMS session, so foregrounding reloads without re-auth.
    func clearMemory() {
        guard lockState == .unlocked else { return }
        items = []
    }

    /// Reload decrypted items from the kept session (used on foreground).
    func reloadFromSession() {
        guard lockState == .unlocked, let rms = rms else { return }
        if let store = try? repo.load(rms: rms) { items = store.items }
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

    /// Replace the item set after a sync merge and persist locally.
    func applyMergedItems(_ merged: [VaultItem]) {
        items = merged
        persist()
    }

    private func persist() {
        guard let r = rms else { return }
        do {
            try repo.save(VaultStore(items: items), rms: r)
        } catch {
            errorMessage = "Couldn't save the vault."
        }
    }
}
