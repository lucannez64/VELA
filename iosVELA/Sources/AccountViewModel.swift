import CryptoKit
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

    /// Server URLs arrive from user input and from enrollment codes. A code
    /// must not be able to point the join flow — which sends this device's
    /// public keys and receives the RMS capsule — at an arbitrary or cleartext
    /// host (audit L-2). This is the single entry gate for a server URL.
    private static func validatedBase(_ urlString: String) throws -> URL {
        let trimmed = urlString.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: trimmed),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else {
            throw Failure("server URL must be an https:// address")
        }
        return url
    }

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

    /// A live handle for this device's identity, for the flows that need to open
    /// shares. The keys behind it never come back across the FFI (audit C-1).
    func identityHandle() -> UInt64? {
        guard let account = account else { return nil }
        return store.identityHandle(for: account)?.handle
    }

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
            // The private halves stay native; only the public keys and the
            // sealed blob come back here (audit C-1).
            guard let identity = VelaCoreFFI.identityCreate(sealKey: store.sealKey()) else {
                throw Failure("identity generation failed")
            }
            let base = try Self.validatedBase(serverURL)
            let client = VelaClient(baseURL: base)
            let resp = try await client.register(hybridEK: identity.hybridEK, hybridVK: identity.hybridVK,
                                                  deviceName: deviceName, shareEK: identity.shareEK)
            let token = await client.currentToken ?? resp.token
            var state = AccountState(
                serverURL: serverURL, userID: resp.user_id, deviceID: resp.device_id,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK,
                token: token
            )
            state.shareEK = identity.shareEK
            state.sealedIdentity = identity.sealed
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
            guard let identity = store.identityHandle(for: state),
                  let signature = VelaCoreFFI.identitySign(
                    handle: identity.handle, challengeBase64: challenge, deviceID: state.deviceID) else {
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
            let merged = try await engine.sync(rms: rms, localStore: vault.currentStore)
            await persistRenewedToken(from: client)
            vault.applyMergedStore(merged)
            AuditLog.shared.record("vault_sync", "\(merged.items.count) item(s)")
            return "Synced \(merged.items.count) item(s)"
        }
    }

    /// Backfill a share keypair for accounts created before sharing existed.
    /// Generates the keypair locally, registers the public half, persists both.
    /// Best-effort and a no-op once a share key is present.
    private func ensureShareKey(client: VelaClient) async {
        guard var state = account, state.shareEK.isEmpty else { return }
        guard let identity = store.identityHandle(for: state),
              let rotated = VelaCoreFFI.identityRotateShareKey(
                sealKey: store.sealKey(), handle: identity.handle) else { return }
        do {
            try await client.putMyShareEK(rotated.shareEK)
            state.shareEK = rotated.shareEK
            state.sealedIdentity = rotated.sealed
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
            // The code is `{session id}#{fingerprint}#{link_nonce}`; fetch the
            // browser's ephemeral key from the server (keeps the QR small enough
            // to scan).
            let (sessionID, expectedFP, linkNonce) = try parseWebSessionID(codeJSON)
            let client = client()
            let epoch = try await client.vaultEpoch()
            await persistRenewedToken(from: client)
            guard epoch.state == "active" else {
                throw Failure("A vault key rotation is in progress; approve web access after it completes.")
            }
            let (ephemeralPK, webVK) = try await client.getWebSessionKeys(sessionID: sessionID)
            // The fingerprint/capsule checks below can return early. Persist a
            // token renewed by the keys request before any of those exits.
            await persistRenewedToken(from: client)

            // Verify the fingerprint to detect server-side key substitution.
            guard let keyData = Data(base64Encoded: ephemeralPK) else {
                throw Failure("Invalid ephemeral key from server")
            }
            let actual = ekFingerprint(keyData)
            guard actual == expectedFP else {
                throw Failure("Key fingerprint mismatch — possible server-side key substitution. Expected \(expectedFP), got \(actual). Approval aborted.")
            }

            let envelope: String
            if mode == "rw" {
                guard !webVK.isEmpty else {
                    throw Failure("This browser did not offer read-write access; choose read-only.")
                }
                guard let rms = vault.currentRMS else { throw Failure("unlock the vault first") }
                // Per-chunk vault keys, not the RMS: the browser can read and
                // rewrite the vault for the session, but never holds the root of
                // the key hierarchy (audit D-2).
                guard let chunkKeys = VelaCoreFFI.webSessionChunkKeys(rms: rms) else {
                    throw Failure("Could not derive the session's vault keys")
                }
                let keysJSON = String(
                    decoding: try JSONSerialization.data(withJSONObject: chunkKeys), as: UTF8.self)
                envelope = "{\"v\":2,\"mode\":\"rw\",\"chunk_keys\":\(keysJSON)}"
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
                ttlSecs: ttlSecs, linkNonce: linkNonce, keyEpoch: epoch.epoch)
            await persistRenewedToken(from: client)
            AuditLog.shared.record(
                "web_session_granted",
                "\(mode == "rw" ? "read-write" : "read-only") · \(ttlSecs / 60) min")
            return "Web access granted until \(expiresAt.prefix(16))"
        }
    }

    /// The scanned/pasted code must be the full `{id}#{fingerprint}#{link_nonce}`.
    /// The shorter legacy forms skip the key-substitution check (no fingerprint)
    /// or the browser binding (no nonce), so they are refused, not downgraded.
    private func parseWebSessionID(_ code: String) throws -> (String, String, String) {
        let t = code.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = t.split(separator: "#", maxSplits: 2, omittingEmptySubsequences: false)
            .map(String.init)
        guard parts.count == 3, !parts[0].isEmpty, !parts[1].isEmpty, !parts[2].isEmpty else {
            throw Failure("This web access code is incomplete or from an unsupported version. Reload the web page and scan the new code.")
        }
        return (parts[0], parts[1], parts[2])
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
            guard let shares = VelaCoreFFI.splitRecovery(rms: rms, threshold: threshold, n: total),
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
            let recoveryEpoch = try await client.vaultEpoch()
            guard recoveryEpoch.state == "active" else {
                throw Failure("vault key rotation is in progress; retry recovery setup after it completes")
            }
            try await client.putRecoveryShare(shares[1], keyEpoch: recoveryEpoch.epoch)
            await persistRenewedToken(from: client)
            CloudRecoveryBackup.upload(userID: account.userID, shareBase64: shares[0])
            let confirmedEpoch = try await client.vaultEpoch()
            guard confirmedEpoch.state == "active", confirmedEpoch.epoch == recoveryEpoch.epoch else {
                throw Failure("vault key rotation changed during recovery setup; start again")
            }
            await persistRenewedToken(from: client)
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
            let base = try Self.validatedBase(serverURL)
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

            guard let identity = VelaCoreFFI.identityCreate(sealKey: store.sealKey()) else {
                throw Failure("identity generation failed")
            }
            let deviceID = try await client.enrollDeviceViaRecovery(
                userID: userID, recoveryGrant: recoverResp.recoveryGrant,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK, deviceName: deviceName)

            let challenge = try await client.challenge()
            guard let signature = VelaCoreFFI.identitySign(
                handle: identity.handle, challengeBase64: challenge, deviceID: deviceID) else {
                throw Failure("signing failed")
            }
            let verified = try await client.verify(deviceID: deviceID, challenge: challenge,
                                                    signature: signature, deviceName: deviceName, deviceType: "ios")

            try vault.adoptVault(rms: rms, mode: secure, password: password)

            var state = AccountState(
                serverURL: serverURL, userID: verified.user_id, deviceID: deviceID,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK,
                token: await client.currentToken ?? verified.token)
            state.shareEK = identity.shareEK
            state.sealedIdentity = identity.sealed
            try store.save(state)
            account = state

            let merged = try await SyncEngine(client: client, repo: VaultRepository()).sync(rms: rms, localStore: vault.currentStore)
            await persistRenewedToken(from: client)
            vault.applyMergedStore(merged)
            AuditLog.shared.record("account_recovered", String(deviceID.prefix(8)))
            return "Account recovered on device \(deviceID.prefix(8))…; \(merged.items.count) item(s)"
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
            let base = try Self.validatedBase(effectiveServer)

            // Authenticate as the device the primary already registered.
            let client = VelaClient(baseURL: base)
            // The code carries the signing key the primary generated; hand it to
            // the native side once and never hold it here (audit C-1).
            guard let identity = VelaCoreFFI.identityImport(
                sealKey: store.sealKey(),
                hybridSKBase64: payload.hybrid_sk,
                hybridEKBase64: payload.hybrid_ek) else {
                throw Failure("could not adopt the enrolled identity")
            }
            let challenge = try await client.challenge()
            guard let signature = VelaCoreFFI.identitySign(
                handle: identity.handle, challengeBase64: challenge, deviceID: payload.device_id) else {
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

            var state = AccountState(
                serverURL: effectiveServer, userID: verified.user_id, deviceID: payload.device_id,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK,
                token: await client.currentToken ?? verified.token)
            state.shareEK = identity.shareEK
            state.sealedIdentity = identity.sealed
            try store.save(state)
            account = state

            // First sync pulls the vault down.
            let merged = try await SyncEngine(client: client, repo: VaultRepository()).sync(rms: rms, localStore: vault.currentStore)
            await persistRenewedToken(from: client)
            vault.applyMergedStore(merged)
            AuditLog.shared.record("device_enrolled", String(payload.device_id.prefix(8)))
            return "Enrolled device \(payload.device_id.prefix(8))…; \(merged.items.count) item(s)"
        }
    }

    // MARK: - Enrollment v3 (audit P-1)
    //
    // The v2 path above adopts a signing key and an RMS transfer key that both
    // travelled inside the enrollment code, so reading the code was holding the
    // vault, permanently. Here this device generates its own identity, sends
    // only the public halves, and the RMS comes back sealed to a key that never
    // left it. An intercepted code buys an enrollment attempt.

    /// This device's own fingerprint while a v3 join is in flight.
    ///
    /// Set from `identityEnrollmentFingerprint`, which derives it natively from
    /// the key just generated. It must never be assigned a value from a server
    /// response: the comparison only means something because the two devices
    /// agree about a *key*, and a number off the wire would let them agree
    /// about nothing.
    @Published var joinFingerprint: String?

    func joinWithV3Code(serverURL: String, code: String, deviceName: String,
                        secure: VaultViewModel.UnlockMode, password: String?) {
        run("Joining") { [self] in
            guard case .v3(let locatorURL, let grantID) = try EnrollmentCode.parse(code) else {
                throw Failure("not a v3 enrollment code")
            }
            var effectiveServer = serverURL.trimmingCharacters(in: .whitespaces)
            if effectiveServer.isEmpty { effectiveServer = locatorURL ?? defaultServer }
            let base = try Self.validatedBase(effectiveServer)
            let client = VelaClient(baseURL: base)

            // Generated here, and the private halves never leave the native side.
            guard let identity = VelaCoreFFI.identityCreate(sealKey: store.sealKey()) else {
                throw Failure("could not generate this device's identity")
            }
            try await client.claimEnrollmentGrant(
                grantID: grantID,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK,
                deviceName: deviceName, deviceType: "ios")

            guard let fingerprint = VelaCoreFFI.identityEnrollmentFingerprint(handle: identity.handle) else {
                throw Failure("could not compute this device's fingerprint")
            }
            joinFingerprint = fingerprint
            defer { joinFingerprint = nil }

            // Wait for the other device's user to pick this fingerprint. No
            // session is possible yet — the device_id being asked for is what a
            // session would need — so the proof is a signature under the key
            // this device claimed with.
            guard let resultSignature = VelaCoreFFI.identitySignEnrollmentResult(
                handle: identity.handle, grantID: grantID) else {
                throw Failure("could not sign the enrollment result request")
            }
            var deviceID: String?
            // Bound the wait to the grant's own lifetime (server TTL is 15
            // minutes): an unconfirmed grant must not keep this device polling
            // (and the UI stuck) forever.
            let deadline = Date().addingTimeInterval(Self.v3JoinMaxWaitSeconds)
            while deviceID == nil {
                guard Date() < deadline else {
                    throw Failure("no confirmation from your other device within "
                        + "\(Int(Self.v3JoinMaxWaitSeconds / 60)) minutes — generate a fresh code and try again")
                }
                try await Task.sleep(nanoseconds: Self.v3JoinPollIntervalNanos)
                deviceID = try await client.collectEnrollmentResult(
                    grantID: grantID, signature: resultSignature)
            }
            guard let deviceID = deviceID else { throw Failure("enrollment was not confirmed") }

            let challenge = try await client.challenge()
            guard let signature = VelaCoreFFI.identitySign(
                handle: identity.handle, challengeBase64: challenge, deviceID: deviceID) else {
                throw Failure("signing failed")
            }
            let verified = try await client.verify(deviceID: deviceID, challenge: challenge,
                                                   signature: signature, deviceType: "ios")

            // Opens with the key generated above and nowhere else.
            let capsule = try await client.getCapsule()
            guard let rmsB64 = VelaCoreFFI.identityOpenEnrollmentCapsule(
                handle: identity.handle, capsuleBase64: capsule),
                  let rms = Data(base64Encoded: rmsB64) else {
                throw Failure("the vault key was not sealed to this device")
            }
            try vault.adoptVault(rms: rms, mode: secure, password: password)

            var state = AccountState(
                serverURL: effectiveServer, userID: verified.user_id, deviceID: deviceID,
                hybridEK: identity.hybridEK, hybridVK: identity.hybridVK,
                token: await client.currentToken ?? verified.token)
            state.shareEK = identity.shareEK
            state.sealedIdentity = identity.sealed
            try store.save(state)
            account = state
            return "Joined"
        }
    }

    /// How often the joining device asks whether the other device's user has
    /// confirmed. Slow enough not to hammer the server for the minute or two a
    /// person takes to compare two screens.
    private static let v3JoinPollIntervalNanos: UInt64 = 2_000_000_000
    /// How long the joining device waits for the other device's user to pick
    /// its fingerprint before giving up (the server's grant TTL is 5 minutes —
    /// `GRANT_TTL_SECS` in the server's rendezvous module).
    private static let v3JoinMaxWaitSeconds: TimeInterval = 5 * 60

    private func resolvePayload(code: String, serverOverride: inout String) async throws -> EnrollmentPayload {
        switch try EnrollmentCode.parse(code) {
        case .direct(let payload):
            return payload
        case .v2(let url, let token, let key):
            let server = serverOverride.isEmpty ? (url ?? "") : serverOverride
            guard !server.isEmpty else { throw Failure("server URL required") }
            let base = try Self.validatedBase(server)
            let ciphertext = try await VelaClient(baseURL: base).getEnrollmentPackage(token: token)
            if serverOverride.isEmpty { serverOverride = server }
            return try EnrollmentCode.decodeV2Package(ciphertextB64URL: ciphertext, packageKeyB64URL: key)
        case .v3:
            // There is no payload to resolve: a v3 code carries no key material
            // at all. `joinWithV3Code` runs that flow instead.
            throw Failure("this is a v3 enrollment code — use joinWithV3Code")
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
