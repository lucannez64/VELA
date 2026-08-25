import XCTest
@testable import VELA

/// Phase 4: server sync / sharing / recovery — FFI round-trips, merge logic,
/// account persistence, and the URLSession client (via a mock protocol).
final class Phase4Tests: XCTestCase {

    func testRecoveryPublicationJournalResumesTheSameFinalizedSplit() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vela-recovery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = RecoveryPublicationJournalStore(directory: directory)
        var expected = RecoveryPublicationJournal(
            accountID: "account-1", keyEpoch: 7,
            splitID: "0f8fad5b-d9cb-469f-a165-70867728950e",
            cloudShareBase64: "cloud", serverShareBase64: "server",
            trustedContactShareBase64: "contact")
        try store.save(expected)
        expected.serverStaged = true
        expected.cloudCandidateDurable = true
        expected.serverFinalized = true
        try store.save(expected)

        XCTAssertEqual(try RecoveryPublicationJournalStore(directory: directory).load(), expected)
    }

    func testRecoveryPublicationJournalRejectsImpossibleActiveState() throws {
        let malformed = RecoveryPublicationJournal(
            accountID: "account-1", keyEpoch: 7,
            splitID: "0f8fad5b-d9cb-469f-a165-70867728950e",
            cloudShareBase64: "cloud", serverShareBase64: "server",
            trustedContactShareBase64: "contact", cloudActive: true)
        XCTAssertThrowsError(try malformed.validate())
    }

    // MARK: FFI

    func testRecoverySplitThenCombine() {
        let rmsBytes = Data(repeating: 7, count: 32)
        guard let shares = VelaCoreFFI.splitRecovery(rms: rmsBytes, threshold: 2, n: 3) else {
            return XCTFail("split failed")
        }
        XCTAssertEqual(shares.count, 3)
        let combined = VelaCoreFFI.combineRecovery(sharesBase64: [shares[0], shares[2]])
        XCTAssertEqual(combined, rmsBytes.base64EncodedString())
    }

    func testVaultChunkRoundTripBindsChunkID() {
        let rms = Data(repeating: 5, count: 32)
        let vaultJSON = "{\"items\":[]}"
        guard let cipher = VelaCoreFFI.encryptVaultChunk(
            rms: rms, chunkID: "vault", vaultJSON: vaultJSON,
            lamportClock: 1, keyEpoch: 1) else {
            return XCTFail("encrypt failed")
        }
        XCTAssertEqual(
            VelaCoreFFI.decryptVaultChunk(
                rms: rms, chunkID: "vault", ciphertextBase64: cipher,
                lamportClock: 1, keyEpoch: 1),
            vaultJSON)
        // A different chunk id derives a different key → must fail.
        XCTAssertNil(VelaCoreFFI.decryptVaultChunk(
            rms: rms, chunkID: "other", ciphertextBase64: cipher,
            lamportClock: 1, keyEpoch: 1))
        // And an older revision of the same chunk must fail too — the rollback
        // the seal exists to stop (audit C-2).
        XCTAssertNil(VelaCoreFFI.decryptVaultChunk(
            rms: rms, chunkID: "vault", ciphertextBase64: cipher,
            lamportClock: 0, keyEpoch: 1))
    }

    func testRotatedVaultChunkBindsEpochAndRejectsLegacyCiphertext() {
        let rms = Data(repeating: 6, count: 32)
        let vaultJSON = #"{"items":[]}"#
        let rotated = VelaCoreFFI.encryptVaultChunk(
            rms: rms, chunkID: "vault-data-000000", vaultJSON: vaultJSON,
            lamportClock: 8, keyEpoch: 2)
        XCTAssertNotNil(rotated)
        XCTAssertEqual(
            rotated.flatMap {
                VelaCoreFFI.decryptVaultChunk(
                    rms: rms, chunkID: "vault-data-000000", ciphertextBase64: $0,
                    lamportClock: 8, keyEpoch: 2)
            },
            vaultJSON)
        XCTAssertNil(rotated.flatMap {
            VelaCoreFFI.decryptVaultChunk(
                rms: rms, chunkID: "vault-data-000000", ciphertextBase64: $0,
                lamportClock: 8, keyEpoch: 3)
        })

        let legacy = VelaCoreFFI.encryptVaultChunk(
            rms: rms, chunkID: "vault-data-000000", vaultJSON: vaultJSON,
            lamportClock: 8, keyEpoch: 1)
        XCTAssertNil(legacy.flatMap {
            VelaCoreFFI.decryptVaultChunk(
                rms: rms, chunkID: "vault-data-000000", ciphertextBase64: $0,
                lamportClock: 8, keyEpoch: 2)
        })
    }

    /// Audit C-1: the identity comes back as a handle plus public halves. No
    /// private key crosses the FFI, and signing happens on the native side.
    func testIdentityHandleSignsWithoutExposingKeys() {
        let sealKey = Data(repeating: 4, count: 32)
        guard let id = VelaCoreFFI.identityCreate(sealKey: sealKey) else {
            return XCTFail("no identity")
        }
        XCTAssertFalse(id.hybridEK.isEmpty)
        XCTAssertFalse(id.hybridVK.isEmpty)
        XCTAssertFalse(id.shareEK.isEmpty)
        XCTAssertFalse(id.sealed.isEmpty)

        let challenge = Data(repeating: 9, count: 32).base64EncodedString()
        XCTAssertNotNil(VelaCoreFFI.identitySign(
            handle: id.handle, challengeBase64: challenge, deviceID: "device-123"))

        // Reopening the sealed blob yields the same device...
        guard let reopened = VelaCoreFFI.identityOpen(sealKey: sealKey, sealedBase64: id.sealed) else {
            return XCTFail("could not reopen the sealed identity")
        }
        XCTAssertEqual(reopened.hybridVK, id.hybridVK)
        // ...but not with the wrong seal key.
        XCTAssertNil(VelaCoreFFI.identityOpen(
            sealKey: Data(repeating: 7, count: 32), sealedBase64: id.sealed))

        // And a forgotten handle can no longer sign.
        VelaCoreFFI.identityForget(handle: id.handle)
        XCTAssertNil(VelaCoreFFI.identitySign(
            handle: id.handle, challengeBase64: challenge, deviceID: "device-123"))
    }

    // MARK: Merge

    func testMergePrefersNewerUpdatedAt() {
        var older = VaultItem.newLogin(name: "GitHub", url: "https://github.com", username: "old", password: "p", totp: nil)
        older.updatedAt = "2026-01-01T00:00:00Z"
        var newer = older
        newer.username = "new"
        newer.updatedAt = "2026-06-01T00:00:00Z"

        let merged = VaultMerge.merge(local: [older], remote: [newer])
        XCTAssertEqual(merged.count, 1)
        XCTAssertEqual(merged.first?.username ?? "", "new")
    }

    func testMergeUnionsDistinctItems() {
        let a = VaultItem.newLogin(name: "A", url: "https://a.com", username: "a", password: "p", totp: nil)
        let b = VaultItem.newLogin(name: "B", url: "https://b.com", username: "b", password: "p", totp: nil)
        let merged = VaultMerge.merge(local: [a], remote: [b])
        XCTAssertEqual(Set(merged.map { $0.name }), ["A", "B"])
    }

    private static let iso: ISO8601DateFormatter = ISO8601DateFormatter()

    /// Timestamps relative to *now* so retention pruning (30 days) can't rot
    /// these tests as wall-clock time advances.
    private static func stamp(daysAgo: Double) -> String {
        iso.string(from: Date().addingTimeInterval(-daysAgo * 86_400))
    }

    func testTombstoneSuppressesStaleRemoteCopy() {
        // Deleted locally; the server still serves an older copy. The merge
        // must not resurrect it (deletions used to vanish on the next sync).
        var item = VaultItem.newLogin(name: "GitHub", url: "https://github.com", username: "u", password: "p", totp: nil)
        item.updatedAt = Self.stamp(daysAgo: 10)
        let tombstone = Tombstone(id: item.id, deletedAt: Self.stamp(daysAgo: 5))

        let merged = VaultMerge.mergeStores(
            local: VaultStore(items: [], tombstones: [tombstone]),
            remote: VaultStore(items: [item]))
        XCTAssertTrue(merged.items.isEmpty, "deleted item must stay deleted")
        XCTAssertEqual(merged.tombstones.count, 1, "the tombstone must be retained for propagation")
    }

    func testNewerEditBeatsOlderTombstone() {
        // Edited elsewhere *after* this device deleted it — the edit wins.
        var item = VaultItem.newLogin(name: "GitHub", url: "https://github.com", username: "edited", password: "p", totp: nil)
        item.updatedAt = Self.stamp(daysAgo: 1)
        let tombstone = Tombstone(id: item.id, deletedAt: Self.stamp(daysAgo: 5))

        let merged = VaultMerge.mergeStores(
            local: VaultStore(items: [], tombstones: [tombstone]),
            remote: VaultStore(items: [item]))
        XCTAssertEqual(merged.items.first?.username, "edited")
        XCTAssertEqual(merged.tombstones.count, 1, "the older tombstone is kept for propagation bookkeeping")
    }

    func testVaultStoreRoundTripsTombstonesThroughJSON() throws {
        // The Rust core's shape uses snake_case keys and tolerates absence of
        // `tombstones` (older chunks); both directions must round-trip.
        let store = VaultStore(
            items: [],
            tombstones: [Tombstone(id: "i-1", deletedAt: "2026-06-01T00:00:00Z", deletedBy: "device-9")])

        let data = try JSONEncoder().encode(store)
        let decoded = try JSONDecoder().decode(VaultStore.self, from: data)
        XCTAssertEqual(decoded, store)
        let json = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(json.contains("\"deleted_at\""), "must use the wire key the core expects")

        // Legacy chunk without a tombstones field decodes to an empty set.
        let legacy = try JSONDecoder().decode(VaultStore.self, from: Data(#"{"items":[]}"#.utf8))
        XCTAssertEqual(legacy.tombstones, [])
    }

    // MARK: Account persistence

    func testAccountStoreRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = AccountStore(directory: dir)
        XCTAssertNil(store.load())

        var state = AccountState(serverURL: "https://vault.klyt.eu", userID: "u", deviceID: "d",
                                 hybridEK: "ek", hybridVK: "vk", token: "tok")
        state.sealedIdentity = "sealed-blob"
        state.keyEpoch = 4
        try store.save(state)
        XCTAssertEqual(store.load(), state)

        store.clear()
        XCTAssertNil(store.load())
    }

    func testLegacyAccountDefaultsToEpochOne() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let accountURL = dir.appendingPathComponent("account.json")
        let legacy = #"{"serverURL":"https://vault.klyt.eu","userID":"u","deviceID":"d","hybridEK":"ek","hybridVK":"vk","token":"tok","shareEK":"","sealedIdentity":""}"#
        try Data(legacy.utf8).write(to: accountURL)

        XCTAssertEqual(AccountStore(directory: dir).load()?.keyEpoch, 1)
    }

    func testVaultEpochMarkerIsAuthenticatedByTheRMS() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let repo = VaultRepository(directory: dir)
        let rms = Data(repeating: 0x41, count: 32)
        XCTAssertNil(try repo.loadKeyEpoch(rms: rms))

        try repo.saveKeyEpoch(5, rms: rms)
        XCTAssertEqual(try repo.loadKeyEpoch(rms: rms), 5)
        XCTAssertThrowsError(try repo.loadKeyEpoch(rms: Data(repeating: 0x42, count: 32)))
    }

    // MARK: Networking (mock URLProtocol)

    private func mockClient() -> VelaClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return VelaClient(baseURL: URL(string: "https://vault.example")!, session: URLSession(configuration: config))
    }

    func testRegisterParsesResponseAndStoresToken() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/account/register")
            XCTAssertEqual(req.httpMethod, "POST")
            let body = #"{"user_id":"U1","device_id":"D1","token":"TOK"}"#
            return (Self.ok(req), Data(body.utf8))
        }
        let client = mockClient()
        let resp = try await client.register(hybridEK: "ek", hybridVK: "vk", deviceName: "iPhone")
        XCTAssertEqual(resp.user_id, "U1")
        XCTAssertEqual(resp.device_id, "D1")
        let token = await client.currentToken
        XCTAssertEqual(token, "TOK")
    }

    func testAuthorizationHeaderAndTokenRenewal() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer OLD")
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil,
                                       headerFields: ["X-New-Token": "RENEWED"])!
            return (resp, Data(#"{"chunks":[]}"#.utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let client = VelaClient(baseURL: URL(string: "https://vault.example")!, token: "OLD",
                                session: URLSession(configuration: config))
        _ = try await client.syncManifest()
        let token = await client.currentToken
        XCTAssertEqual(token, "RENEWED", "should adopt the rotated token")
    }

    func testTokenRenewalIgnoredOnErrorResponse() async throws {
        // A hostile server must not be able to plant a token of its choosing
        // via an error response.
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(url: req.url!, statusCode: 401, httpVersion: nil,
                                       headerFields: ["X-New-Token": "EVIL"])!
            return (resp, Data("denied".utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let client = VelaClient(baseURL: URL(string: "https://vault.example")!, token: "OLD",
                                session: URLSession(configuration: config))
        do {
            _ = try await client.syncManifest()
            XCTFail("expected 401")
        } catch {}
        let token = await client.currentToken
        XCTAssertEqual(token, "OLD", "must not adopt X-New-Token from an error response")
    }

    func testRecoveryShareWritesDeclareTheirEpoch() async throws {
        var requestNumber = 0
        MockURLProtocol.handler = { req in
            requestNumber += 1
            if requestNumber == 1 {
                XCTAssertEqual(req.url?.path, "/recovery/share")
                XCTAssertEqual(req.httpMethod, "PUT")
                let body: Data
                if let directBody = req.httpBody {
                    body = directBody
                } else {
                    // URLSession converts request bodies to streams before a
                    // custom URLProtocol sees them on current iOS runtimes.
                    let stream = try XCTUnwrap(req.httpBodyStream)
                    stream.open()
                    defer { stream.close() }
                    var buffer = [UInt8](repeating: 0, count: 4096)
                    let count = stream.read(&buffer, maxLength: buffer.count)
                    XCTAssertGreaterThan(count, 0)
                    body = Data(buffer.prefix(max(count, 0)))
                }
                let json = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any])
                XCTAssertEqual(json["share"] as? String, "share-two")
                XCTAssertEqual(json["key_epoch"] as? Int, 4)
                XCTAssertEqual(
                    json["split_id"] as? String,
                    "35E9710A-938B-4A95-AE25-61F8C3C71B97")
            } else if requestNumber == 2 {
                XCTAssertEqual(req.url?.path, "/recovery/share/finalize")
                XCTAssertEqual(req.httpMethod, "POST")
            } else {
                XCTAssertEqual(req.url?.path, "/recovery/share")
                XCTAssertEqual(req.httpMethod, "DELETE")
                XCTAssertEqual(req.value(forHTTPHeaderField: "X-Vela-Epoch"), "4")
            }
            return (Self.ok(req), Data())
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let client = VelaClient(
            baseURL: URL(string: "https://vault.example")!, token: "TOKEN",
            session: URLSession(configuration: config))

        try await client.putRecoveryShare(
            "share-two", keyEpoch: 4,
            splitID: "35E9710A-938B-4A95-AE25-61F8C3C71B97",
            possessionHashBase64: "cG9zc2Vzc2lvbg==")
        try await client.finalizeRecoveryShare(
            keyEpoch: 4, splitID: "35E9710A-938B-4A95-AE25-61F8C3C71B97")
        try await client.deleteRecoveryShare(keyEpoch: 4)
        XCTAssertEqual(requestNumber, 3)
    }

    func testVaultWritesDeclareTheirEpoch() async throws {
        var requestNumber = 0
        MockURLProtocol.handler = { req in
            requestNumber += 1
            XCTAssertEqual(req.value(forHTTPHeaderField: "X-Vela-Epoch"), "7")
            XCTAssertEqual(req.value(forHTTPHeaderField: "If-Match"), "3")
            if requestNumber == 1 {
                XCTAssertEqual(req.httpMethod, "PUT")
                XCTAssertEqual(req.value(forHTTPHeaderField: "X-Lamport-Clock"), "9")
                return (Self.ok(req), Data(#"{"version":4}"#.utf8))
            }
            XCTAssertEqual(req.httpMethod, "DELETE")
            return (Self.ok(req), Data())
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let client = VelaClient(
            baseURL: URL(string: "https://vault.example")!, token: "TOKEN",
            session: URLSession(configuration: config))

        let version = try await client.putChunk(
            "vault-data-000000", ciphertextBase64: Data([1, 2, 3]).base64EncodedString(),
            ifMatch: 3, lamportClock: 9, keyEpoch: 7)
        XCTAssertEqual(version, 4)
        try await client.deleteChunk("vault-data-000000", ifMatch: 3, keyEpoch: 7)
        XCTAssertEqual(requestNumber, 2)
    }

    func testRecoveryResponseCarriesEpoch() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/recovery/recover")
            let json = #"{"share":"share-two","recovery_grant":"grant","key_epoch":6}"#
            return (Self.ok(req), Data(json.utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let client = VelaClient(
            baseURL: URL(string: "https://vault.example")!,
            session: URLSession(configuration: config))

        let result = try await client.recoverAccount(
            userID: "user", recoveryID: "recovery", credentialJSON: [:])
        XCTAssertEqual(result.shareBase64, "share-two")
        XCTAssertEqual(result.recoveryGrant, "grant")
        XCTAssertEqual(result.keyEpoch, 6)
    }

    func testRedirectPolicyRefusesCrossHost() {
        // URLSession re-sends the Authorization header when following a
        // redirect; a cross-host hop would hand the bearer token to whatever
        // host the 302 points at.
        XCTAssertFalse(VelaRedirectGuard.shouldFollow(
            original: URL(string: "https://vault.example/vault/sync"),
            target: URL(string: "https://evil.example/harvest")))
    }

    func testRedirectPolicyAllowsSameHost() {
        XCTAssertTrue(VelaRedirectGuard.shouldFollow(
            original: URL(string: "https://vault.example/vault/sync"),
            target: URL(string: "https://vault.example/vault/sync/next")))
        XCTAssertTrue(VelaRedirectGuard.shouldFollow(
            original: URL(string: "https://VAULT.EXAMPLE/vault/sync"),
            target: URL(string: "https://vault.example/other")))
    }

    func testRedirectPolicyFailsClosedWithoutHosts() {
        XCTAssertFalse(VelaRedirectGuard.shouldFollow(
            original: nil, target: URL(string: "https://evil.example/")))
        XCTAssertFalse(VelaRedirectGuard.shouldFollow(
            original: URL(string: "https://vault.example/"), target: nil))
    }

    func testPerChunkRollbackHiddenBehindFreshChunkIsRejected() async throws {
        // A hostile server rolls one chunk back while keeping another ahead:
        // the manifest-max check passes, so the per-chunk baseline must catch
        // it. Key names mirror SyncEngine's private constants.
        let defaults = UserDefaults(suiteName: AppGroup.identifier) ?? .standard
        defaults.set(5, forKey: "vela.sync.lastSeenLamport")
        let baseline: [String: Int] = ["vault-data-000000": 5]
        defaults.set(String(decoding: try JSONEncoder().encode(baseline), as: UTF8.self),
                     forKey: "vela.sync.lastSeenLamportByChunk")
        defer {
            defaults.removeObject(forKey: "vela.sync.lastSeenLamport")
            defaults.removeObject(forKey: "vela.sync.lastSeenLamportByChunk")
        }

        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/vault/sync")
            let body = """
            {"chunks":[{"chunk_id":"vault-data-000000","version":1,"lamport_clock":3,"last_writer":null},{"chunk_id":"vault-data-000001","version":1,"lamport_clock":9,"last_writer":null}]}
            """
            return (Self.ok(req), Data(body.utf8))
        }
        let repo = VaultRepository(
            directory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
        let engine = SyncEngine(client: mockClient(), repo: repo, keyEpoch: 1)
        do {
            _ = try await engine.sync(rms: Data(repeating: 1, count: 32), localStore: VaultStore(items: []))
            XCTFail("expected the rolled-back chunk to be rejected")
        } catch let error as LocalizedError {
            XCTAssertTrue(error.errorDescription?.contains("older revision") == true,
                          "unexpected error: \(error.localizedDescription)")
        }
    }

    private static func ok(_ req: URLRequest) -> HTTPURLResponse {
        HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
    }
}

/// Minimal in-memory URLProtocol so client tests never hit the network.
final class MockURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
