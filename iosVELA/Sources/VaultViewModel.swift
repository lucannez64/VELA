import Foundation
import SwiftUI

@MainActor
final class VaultViewModel: ObservableObject {
    @Published var items: [VaultItem] = []
    @Published var isUnlocked = false
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
            do {
                let r = try repo.loadRMS()
                items = try repo.load(rms: r).items
                rms = r
                isUnlocked = true
            } catch {
                errorMessage = "Couldn't open the vault."
            }
        }

        // CI/screenshot seed: create a demo vault so the populated UI is captured.
        if !isUnlocked, ProcessInfo.processInfo.environment["VELA_DEMO"] == "1" {
            try? createVault()
            addLogin(name: "GitHub", url: "https://github.com", username: "alice", password: "h7$Kp2!q", totp: nil)
            addLogin(name: "Proton Mail", url: "https://proton.me", username: "alice@proton.me", password: "Zq9!vT3m", totp: nil)
            addLogin(name: "Cloudflare", url: "https://dash.cloudflare.com", username: "alice", password: "Wp4#nL8x", totp: nil)
        }
    }

    func createVault() throws {
        let r = try repo.generateAndStoreRMS()
        rms = r
        items = []
        try repo.save(VaultStore(items: items), rms: r)
        isUnlocked = true
    }

    func addLogin(name: String, url: String, username: String, password: String, totp: String?) {
        items.append(VaultItem.newLogin(name: name, url: url, username: username, password: password, totp: totp))
        persist()
    }

    func delete(_ item: VaultItem) {
        items.removeAll { $0.id == item.id }
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
