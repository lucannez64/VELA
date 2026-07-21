import CryptoKit
import Foundation
import SwiftUI

/// Older JSON form of the link code. The current code is a bare `session_id`.
struct WebSessionQR: Decodable {
    let session_id: String
}

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
        // Without this guard, a user-initiated action (e.g. tapping "Sync
        // Now") firing at the same moment the periodic sync timer does would
        // run both concurrently — two overlapping syncs racing on `vault`
        // and issuing duplicate/conflicting server writes.
        guard !busy else { return }
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
            let resp = try await client.register(hybridEK: identity.hybridEK, hybridVK: identity.hybridVK,
                                                  deviceName: deviceName, shareEK: identity.shareEK)
            let token = await client.currentToken ?? resp.token
            var state = AccountState(
                serverURL: serverURL, userID: resp.user_id, deviceID: resp.device_id,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK, hybridSK: identity.hybridSK,
                token: token
            )
            state.shareEK = identity.shareEK
            state.shareDK = identity.shareDK
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
            await ensureShareKey(client: client)
            let engine = SyncEngine(client: client, repo: VaultRepository())
            let merged = try await engine.sync(rms: rms, localItems: vault.items)
            await persistRenewedToken(from: client)
            vault.applyMergedItems(merged)
            AuditLog.shared.record("vault_sync", "\(merged.count) item(s)")
            return "Synced \(merged.count) item(s)"
        }
    }

    /// Backfill a share keypair for accounts created before sharing existed.
    /// Generates the keypair locally, registers the public half, persists both.
    /// Best-effort and a no-op once a share key is present.
    private func ensureShareKey(client: VelaClient) async {
        guard var state = account, state.shareEK.isEmpty else { return }
        guard let pair = VelaCoreFFI.generateShareKeypair() else { return }
        do {
            try await client.putMyShareEK(pair.shareEK)
            state.shareEK = pair.shareEK
            state.shareDK = pair.shareDK
            try store.save(state)
            account = state
        } catch {
            // Leave shareEK empty so the next sync retries the backfill.
        }
    }

    /// Share a vault item with another user using real KEM-sealed encryption.
    func share(item: VaultItem, recipientUserID: String) {
        run("Sharing") { [self] in
            guard account != nil else { throw Failure("register first") }
            let itemJSON = String(decoding: try JSONEncoder().encode(item), as: UTF8.self)
            let client = client()
            // Fetch recipient's share public key.
            let recipientShareEK = try await client.getRecipientShareEK(userID: recipientUserID)
            // Seal the item with the recipient's KEM key — server never sees plaintext.
            guard let capsuleB64 = VelaCoreFFI.sealShare(recipientShareEKBase64: recipientShareEK, itemJSON: itemJSON) else {
                throw Failure("KEM sealing failed")
            }
            let resp = try await client.sendShare(recipientUserID: recipientUserID, capsuleBase64: capsuleB64)
            await persistRenewedToken(from: client)
            // Persist share record so we can re-seal on update.
            shareManifest.add(ShareRecord(
                shareID: resp.share_id, vaultItemID: item.id,
                recipientUserID: recipientUserID, recipientShareEK: recipientShareEK
            ))
            AuditLog.shared.record("share_sent", String(recipientUserID.prefix(8)))
            return "Shared (inbox \(resp.inbox_id.prefix(8))…)"
        }
    }

    /// Approve a browser's temporary, revocable web access. Parses the pasted
    /// code, seals the capsule (RO vault snapshot / RW RMS) to the browser's
    /// ephemeral key, grants it, and records the audit event.
    /// See EPHEMERAL_WEB_ACCESS_DESIGN.md §14 for the wire formats.
    func grantWebAccess(codeJSON: String, mode: String, ttlSecs: Int) {
        run("Approving web access") { [self] in
            guard account != nil else { throw Failure("register first") }
            // The code is a bare session id (optionally with #fingerprint and
            // #link_nonce suffixes); fetch the browser's ephemeral key from the
            // server (keeps the QR small enough to scan).
            let (sessionID, expectedFP, linkNonce) = try parseWebSessionID(codeJSON)
            let client = client()
            let (ephemeralPK, webVK) = try await client.getWebSessionKeys(sessionID: sessionID)

            // Verify fingerprint if present to detect server-side key substitution.
            if let expected = expectedFP {
                guard let keyData = Data(base64Encoded: ephemeralPK) else {
                    throw Failure("Invalid ephemeral key from server")
                }
                let actual = ekFingerprint(keyData)
                guard actual == expected else {
                    throw Failure("Key fingerprint mismatch — possible server-side key substitution. Expected \(expected), got \(actual). Approval aborted.")
                }
            }

            let envelope: String
            if mode == "rw" {
                guard !webVK.isEmpty else {
                    throw Failure("This browser did not offer read-write access; choose read-only.")
                }
                guard let rms = vault.currentRMS else { throw Failure("unlock the vault first") }
                envelope = "{\"v\":1,\"mode\":\"rw\",\"rms_b64\":\"\(rms.base64EncodedString())\"}"
            } else {
                let itemsJSON = String(decoding: try JSONEncoder().encode(vault.items), as: UTF8.self)
                envelope = "{\"v\":1,\"mode\":\"ro\",\"vault\":{\"items\":\(itemsJSON),\"tombstones\":[]}}"
            }

            guard let capsuleB64 = VelaCoreFFI.sealShare(
                recipientShareEKBase64: ephemeralPK, itemJSON: envelope) else {
                throw Failure("KEM sealing failed")
            }
            let expiresAt = try await client.grantWebSession(
                sessionID: sessionID, mode: mode, capsuleBase64: capsuleB64,
                ttlSecs: ttlSecs, linkNonce: linkNonce)
            await persistRenewedToken(from: client)
            AuditLog.shared.record(
                "web_session_granted",
                "\(mode == "rw" ? "read-write" : "read-only") · \(ttlSecs / 60) min")
            return "Web access granted until \(expiresAt.prefix(16))"
        }
    }

    /// The scanned/pasted code is `{id}#{fingerprint}#{link_nonce}`, `{id}#{fingerprint}`,
    /// a bare id, or (older) a JSON object. Returns `(sessionID, fingerprint?, linkNonce?)`.
    private func parseWebSessionID(_ code: String) throws -> (String, String?, String?) {
        let t = code.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix("{") {
            guard let data = t.data(using: .utf8),
                  let qr = try? JSONDecoder().decode(WebSessionQR.self, from: data) else {
                throw Failure("Invalid web access code")
            }
            return (qr.session_id, nil, nil)
        }
        guard !t.isEmpty else { throw Failure("Empty web access code") }
        let parts = t.split(separator: "#", maxSplits: 2, omittingEmptySubsequences: false)
            .map(String.init)
        let fp = parts.count > 1 && !parts[1].isEmpty ? parts[1] : nil
        let nonce = parts.count > 2 && !parts[2].isEmpty ? parts[2] : nil
        return (parts[0], fp, nonce)
    }

    /// Compute the key fingerprint: base32(sha256(rawKeyBytes)[0:8]).
    private func ekFingerprint(_ data: Data) -> String {
        let hash = SHA256.hash(data: data)
        return base32Encode(Array(hash.prefix(8)))
    }

    private func base32Encode(_ bytes: [UInt8]) -> String {
        let alphabet: [Character] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = ""
        var bits = 0, value = 0
        for b in bytes {
            value = (value << 8) | Int(b)
            bits += 8
            while bits >= 5 { out.append(alphabet[(value >> (bits - 5)) & 31]); bits -= 5 }
        }
        if bits > 0 { out.append(alphabet[(value << (5 - bits)) & 31]) }
        return out
    }

    /// Re-seal and push updated capsules to all recipients who have linked shares for `item`.
    func pushShareUpdates(for item: VaultItem) async {
        guard account != nil else { return }
        let records = shareManifest.records(for: item.id)
        guard !records.isEmpty else { return }
        let itemJSON = (try? String(decoding: JSONEncoder().encode(item), as: UTF8.self)) ?? ""
        let client = client()
        for record in records {
            guard let newCapsule = VelaCoreFFI.sealShare(
                recipientShareEKBase64: record.recipientShareEK, itemJSON: itemJSON) else { continue }
            try? await client.updateLinkedShare(id: record.shareID, capsuleBase64: newCapsule)
        }
        await persistRenewedToken(from: client)
    }

    var shareManifest = ShareManifest()

    /// Split the RMS into recovery shares (SPEC.md §4.3), register a WebAuthn
    /// recovery passkey (a physical security key, independent of this
    /// device's own biometrics — see `WebAuthnCeremony`), deliver Share 2 to
    /// the server gated behind that passkey, and back Share 1 up to iCloud
    /// Key-Value Storage (see `CloudRecoveryBackup`). Share 3 (trusted
    /// contact) is handed to the caller to distribute — there's no
    /// automated channel for that one.
    func setupRecovery(threshold: Int = 2, total: Int = 3) {
        run("Setting up recovery") { [self] in
            guard let rms = vault.currentRMS else { throw Failure("unlock the vault first") }
            guard let account = account else { throw Failure("register first") }
            guard let shares = VelaCoreFFI.splitRecovery(rmsBase64: rms.base64EncodedString(), threshold: threshold, n: total),
                  shares.count == total else {
                throw Failure("recovery split failed")
            }
            let client = client()

            let startResp = try await client.startRecoveryWebAuthnRegistration()
            let creationOptions = WebAuthnCeremony.unwrapPublicKey(startResp)
            let credentialJSON = try await WebAuthnCeremony().register(optionsJSON: creationOptions)
            let registered = try await client.finishRecoveryWebAuthnRegistration(credentialJSON: credentialJSON)
            guard registered else { throw Failure("recovery passkey registration was not confirmed by the server") }

            // Share 2 is gated by the passkey we just registered.
            try await client.putRecoveryShare(shares[1])
            await persistRenewedToken(from: client)
            CloudRecoveryBackup.upload(userID: account.userID, shareBase64: shares[0])
            // Share 3 (trusted contact) is shown to the user to distribute —
            // there is no automated channel for a trusted-contact handoff.
            recoveryShares = [shares[2]]
            AuditLog.shared.record("recovery_setup", "\(threshold)-of-\(total)")
            return "Recovery ready (\(threshold)-of-\(total)); Share 1 backed up to iCloud"
        }
    }

    /// Reconstruct the RMS on a brand-new device from Share 1 (pasted from
    /// wherever the user stored it) + Share 2 (released by the server after
    /// the WebAuthn assertion below), then register this device against the
    /// existing account and pull the vault down — the download side of
    /// `setupRecovery`, mirroring `joinWithCode`'s bootstrap sequence.
    func restoreAccount(serverURL: String, userID: String, share1Base64: String,
                         secure: VaultViewModel.UnlockMode, password: String?, deviceName: String) {
        run("Recovering account") { [self] in
            let base = URL(string: serverURL) ?? URL(string: defaultServer)!
            let client = VelaClient(baseURL: base)

            let initiateResp = try await client.initiateRecovery(userID: userID)
            let requestOptions = WebAuthnCeremony.unwrapPublicKey(initiateResp.publicKeyJSON)
            let credentialJSON = try await WebAuthnCeremony().assert(optionsJSON: requestOptions)
            let recoverResp = try await client.recoverAccount(
                userID: userID, recoveryID: initiateResp.recoveryID, credentialJSON: credentialJSON)

            guard let rmsB64 = VelaCoreFFI.combineRecovery(sharesBase64: [share1Base64, recoverResp.shareBase64]),
                  let rms = Data(base64Encoded: rmsB64) else {
                throw Failure("couldn't reconstruct the vault key from the two shares")
            }

            guard let identity = VelaCoreFFI.generateIdentity() else { throw Failure("identity generation failed") }
            let deviceID = try await client.enrollDeviceViaRecovery(
                userID: userID, recoveryGrant: recoverResp.recoveryGrant,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK, deviceName: deviceName)

            let challenge = try await client.challenge()
            guard let signature = VelaCoreFFI.createAuthSignature(
                hybridSKBase64: identity.hybridSK, challengeBase64: challenge, deviceID: deviceID) else {
                throw Failure("signing failed")
            }
            let verified = try await client.verify(deviceID: deviceID, challenge: challenge,
                                                    signature: signature, deviceName: deviceName, deviceType: "ios")

            try vault.adoptVault(rms: rms, mode: secure, password: password)

            var state = AccountState(
                serverURL: serverURL, userID: verified.user_id, deviceID: deviceID,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK, hybridSK: identity.hybridSK,
                token: await client.currentToken ?? verified.token)
            state.shareEK = identity.shareEK
            state.shareDK = identity.shareDK
            try store.save(state)
            account = state

            let merged = try await SyncEngine(client: client, repo: VaultRepository()).sync(rms: rms, localItems: vault.items)
            await persistRenewedToken(from: client)
            vault.applyMergedItems(merged)
            AuditLog.shared.record("account_recovered", String(deviceID.prefix(8)))
            return "Account recovered on device \(deviceID.prefix(8))…; \(merged.count) item(s)"
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
