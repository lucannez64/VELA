import Foundation
import SwiftUI

/// Drives the Phase 4 server flows: register/enroll this device, authenticate,
/// two-way vault sync, sharing, and recovery-share setup — all over `VelaClient`.
@MainActor
final class AccountViewModel: ObservableObject {
    @Published var account: AccountState?
    @Published var status: String = ""
    @Published var busy = false
    @Published var recoveryShares: [String] = []   // shares to hand to the user after setup

    private let store: AccountStore
    private unowned let vault: VaultViewModel
    private let defaultServer: String

    init(vault: VaultViewModel, store: AccountStore = AccountStore(), defaultServer: String = "https://vault.klyt.eu") {
        self.vault = vault
        self.store = store
        self.defaultServer = defaultServer
        self.account = store.load()
    }

    var isRegistered: Bool { account != nil }

    /// Snapshot of the unlocked vault's items (for the share picker).
    var vaultItems: [VaultItem] { vault.items }

    private func client() -> VelaClient {
        let urlString = account?.serverURL ?? defaultServer
        return VelaClient(baseURL: URL(string: urlString) ?? URL(string: defaultServer)!, token: account?.token)
    }

    private func run(_ label: String, _ work: @escaping () async throws -> String) {
        busy = true
        status = "\(label)…"
        Task { @MainActor in
            do { status = try await work() }
            catch { status = "\(label) failed: \(error.localizedDescription)" }
            busy = false
        }
    }

    /// Register a fresh device identity with the server.
    func register(serverURL: String, deviceName: String) {
        run("Registering") { [self] in
            guard let identity = VelaCoreFFI.generateIdentity() else { throw Failure("identity generation failed") }
            let base = URL(string: serverURL) ?? URL(string: defaultServer)!
            let client = VelaClient(baseURL: base)
            let resp = try await client.register(hybridEK: identity.hybridEK, hybridVK: identity.hybridVK, deviceName: deviceName)
            let token = await client.currentToken ?? resp.token
            let state = AccountState(
                serverURL: serverURL, userID: resp.user_id, deviceID: resp.device_id,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK, hybridSK: identity.hybridSK,
                token: token
            )
            try store.save(state)
            account = state
            return "Registered device \(resp.device_id.prefix(8))…"
        }
    }

    /// Re-authenticate with the challenge/verify handshake to refresh the session token.
    func login() {
        run("Authenticating") { [self] in
            guard var state = account else { throw Failure("not registered") }
            let client = client()
            let challenge = try await client.challenge()
            guard let signature = VelaCoreFFI.createAuthSignature(
                hybridSKBase64: state.hybridSK, challengeBase64: challenge, deviceID: state.deviceID) else {
                throw Failure("signing failed")
            }
            let resp = try await client.verify(deviceID: state.deviceID, challenge: challenge, signature: signature, deviceType: "ios")
            state.token = resp.token
            try store.save(state)
            account = state
            return "Authenticated"
        }
    }

    /// Two-way vault sync (pull → merge → push).
    func syncNow() {
        run("Syncing") { [self] in
            guard let rms = vault.currentRMS else { throw Failure("unlock the vault first") }
            guard account != nil else { throw Failure("register first") }
            let client = client()
            let engine = SyncEngine(client: client, repo: VaultRepository())
            let merged = try await engine.sync(rms: rms, localItems: vault.items)
            await persistRenewedToken(from: client)
            vault.applyMergedItems(merged)
            return "Synced \(merged.count) item(s)"
        }
    }

    /// Share a vault item with another user (capsule = item sealed under our vault key).
    func share(item: VaultItem, recipientUserID: String) {
        run("Sharing") { [self] in
            guard let rms = vault.currentRMS else { throw Failure("unlock the vault first") }
            guard account != nil else { throw Failure("register first") }
            let itemJSON = String(decoding: try JSONEncoder().encode(item), as: UTF8.self)
            guard let capsule = VelaCoreFFI.encryptVault(rmsBase64: rms.base64EncodedString(), vaultJSON: "{\"items\":[\(itemJSON)]}") else {
                throw Failure("sealing failed")
            }
            let client = client()
            let resp = try await client.sendShare(recipientUserID: recipientUserID, capsuleBase64: capsule)
            await persistRenewedToken(from: client)
            return "Shared (inbox \(resp.inbox_id.prefix(8))…)"
        }
    }

    /// Split the RMS into recovery shares and store one on the server.
    func setupRecovery(threshold: Int = 2, total: Int = 3) {
        run("Setting up recovery") { [self] in
            guard let rms = vault.currentRMS else { throw Failure("unlock the vault first") }
            guard account != nil else { throw Failure("register first") }
            guard let shares = VelaCoreFFI.splitRecovery(rmsBase64: rms.base64EncodedString(), threshold: threshold, n: total),
                  let serverShare = shares.first else {
                throw Failure("recovery split failed")
            }
            let client = client()
            try await client.putRecoveryShare(serverShare)
            await persistRenewedToken(from: client)
            // The remaining shares are shown to the user to distribute to guardians.
            recoveryShares = Array(shares.dropFirst())
            return "Recovery ready (\(threshold)-of-\(total)); \(recoveryShares.count) guardian share(s)"
        }
    }

    func signOut() {
        let loggingOut = account.map {
            VelaClient(baseURL: URL(string: $0.serverURL) ?? URL(string: defaultServer)!, token: $0.token)
        }
        account = nil
        recoveryShares = []
        status = "Signed out"
        store.clear()
        if let loggingOut = loggingOut {
            Task { try? await loggingOut.logout() }
        }
    }

    private func persistRenewedToken(from client: VelaClient) async {
        guard var state = account else { return }
        let token = await client.currentToken
        if token != state.token {
            state.token = token
            try? store.save(state)
            account = state
        }
    }

    private struct Failure: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }
}
