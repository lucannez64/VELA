import Foundation
import SwiftUI

@MainActor
final class VaultViewModel: ObservableObject {
    enum LockState {
        case noVault   // nothing on device yet → Welcome / create
        case locked    // vault exists, awaiting Face ID / Touch ID
        case unlocked  // RMS in memory, vault open
    }

    @Published var items: [VaultItem] = []
    @Published var lockState: LockState = .noVault
    @Published var errorMessage: String?

    private let repo: VaultRepository
    private var rms: Data?

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
        lockState = .unlocked
    }

    func addLogin(name: String, url: String, username: String, password: String, totp: String?) {
        items.append(VaultItem.newLogin(name: name, url: url, username: username, password: password, totp: totp))
        persist()
    }

    func delete(_ item: VaultItem) {
        items.removeAll { $0.id == item.id }
        persist()
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
