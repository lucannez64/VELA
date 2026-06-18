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
    var deviceID: String? { account?.deviceID }
    var userID: String? { account?.userID }

    /// Snapshot of the unlocked vault's items (for the share picker).
    var vaultItems: [VaultItem] { vault.items }

    /// A client bound to the current account/token, or nil if not registered.
    func makeClient() -> VelaClient? {
        guard let account = account else { return nil }
        return VelaClient(baseURL: URL(string: account.serverURL) ?? URL(string: defaultServer)!, token: account.token)
    }

    /// Persist a token rotated during another screen's request.
    func adoptToken(from client: VelaClient) async { await persistRenewedToken(from: client) }

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
            AuditLog.shared.record("device_registered", String(resp.device_id.prefix(8)))
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
            AuditLog.shared.record("vault_sync", "\(merged.count) item(s)")
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
            AuditLog.shared.record("share_sent", String(recipientUserID.prefix(8)))
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
            AuditLog.shared.record("recovery_setup", "\(threshold)-of-\(total)")
            return "Recovery ready (\(threshold)-of-\(total)); \(recoveryShares.count) guardian share(s)"
        }
    }

    /// Join an existing vault with an enrollment code (the joining side of
    /// device enrollment): authenticate as the pre-registered device, download +
    /// decrypt the RMS capsule, secure it locally, then pull the vault.
    func joinWithCode(serverURL: String, code: String, secure: VaultViewModel.UnlockMode, password: String?) {
        run("Joining") { [self] in
            var effectiveServer = serverURL.trimmingCharacters(in: .whitespaces)
            let payload = try await resolvePayload(code: code, serverOverride: &effectiveServer)
            if effectiveServer.isEmpty { effectiveServer = payload.server_url ?? defaultServer }
            guard let base = URL(string: effectiveServer) else { throw Failure("invalid server URL") }

            // Authenticate as the device the primary already registered.
            let client = VelaClient(baseURL: base)
            let challenge = try await client.challenge()
            guard let signature = VelaCoreFFI.createAuthSignature(
                hybridSKBase64: payload.hybrid_sk, challengeBase64: challenge, deviceID: payload.device_id) else {
                throw Failure("signing failed")
            }
            let verified = try await client.verify(deviceID: payload.device_id, challenge: challenge,
                                                   signature: signature, deviceType: "ios")

            // Download + decrypt the one-shot RMS capsule.
            let capsule = try await client.getCapsule()
            guard let rmsB64 = VelaCoreFFI.decryptRMSCapsule(transferKeyBase64: payload.transfer_key, capsuleBase64: capsule),
                  let rms = Data(base64Encoded: rmsB64) else {
                throw Failure("couldn't decrypt the enrollment capsule")
            }
            try vault.adoptVault(rms: rms, mode: secure, password: password)

            let state = AccountState(
                serverURL: effectiveServer, userID: verified.user_id, deviceID: payload.device_id,
                hybridEK: payload.hybrid_ek, hybridVK: payload.hybrid_vk, hybridSK: payload.hybrid_sk,
                token: await client.currentToken ?? verified.token)
            try store.save(state)
            account = state

            // First sync pulls the vault down.
            let merged = try await SyncEngine(client: client, repo: VaultRepository()).sync(rms: rms, localItems: vault.items)
            await persistRenewedToken(from: client)
            vault.applyMergedItems(merged)
            AuditLog.shared.record("device_enrolled", String(payload.device_id.prefix(8)))
            return "Enrolled device \(payload.device_id.prefix(8))…; \(merged.count) item(s)"
        }
    }

    private func resolvePayload(code: String, serverOverride: inout String) async throws -> EnrollmentPayload {
        switch try EnrollmentCode.parse(code) {
        case .direct(let payload):
            return payload
        case .v2(let url, let token, let key):
            let server = serverOverride.isEmpty ? (url ?? "") : serverOverride
            guard !server.isEmpty, let base = URL(string: server) else { throw Failure("server URL required") }
            let ciphertext = try await VelaClient(baseURL: base).getEnrollmentPackage(token: token)
            if serverOverride.isEmpty { serverOverride = server }
            return try EnrollmentCode.decodeV2Package(ciphertextB64URL: ciphertext, packageKeyB64URL: key)
        }
    }

    // MARK: - Background sync (foreground periodic timer, like Android)

    private var syncTask: Task<Void, Never>?

    func startPeriodicSync() {
        stopPeriodicSync()
        guard isRegistered else { return }
        let stored = UserDefaults.standard.integer(forKey: "vela.backgroundSyncMinutes")
        let minutes = stored <= 0 ? 5 : stored
        syncTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(minutes) * 60_000_000_000)
                guard let self = self, !Task.isCancelled else { break }
                if self.vault.currentRMS != nil { self.syncNow() }
            }
        }
    }

    func stopPeriodicSync() {
        syncTask?.cancel()
        syncTask = nil
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
