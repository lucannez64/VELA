import XCTest
@testable import VELA

/// Phase 4: server sync / sharing / recovery — FFI round-trips, merge logic,
/// account persistence, and the URLSession client (via a mock protocol).
final class Phase4Tests: XCTestCase {

    // MARK: FFI

    func testRecoverySplitThenCombine() {
        let rms = Data(repeating: 7, count: 32).base64EncodedString()
        guard let shares = VelaCoreFFI.splitRecovery(rmsBase64: rms, threshold: 2, n: 3) else {
            return XCTFail("split failed")
        }
        XCTAssertEqual(shares.count, 3)
        let combined = VelaCoreFFI.combineRecovery(sharesBase64: [shares[0], shares[2]])
        XCTAssertEqual(combined, rms)
    }

    func testVaultChunkRoundTripBindsChunkID() {
        let rms = Data(repeating: 5, count: 32).base64EncodedString()
        let vaultJSON = "{\"items\":[]}"
        guard let cipher = VelaCoreFFI.encryptVaultChunk(rmsBase64: rms, chunkID: "vault", vaultJSON: vaultJSON) else {
            return XCTFail("encrypt failed")
        }
        XCTAssertEqual(VelaCoreFFI.decryptVaultChunk(rmsBase64: rms, chunkID: "vault", ciphertextBase64: cipher), vaultJSON)
        // A different chunk id derives a different key → must fail.
        XCTAssertNil(VelaCoreFFI.decryptVaultChunk(rmsBase64: rms, chunkID: "other", ciphertextBase64: cipher))
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

    // MARK: Account persistence

    func testAccountStoreRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = AccountStore(directory: dir)
        XCTAssertNil(store.load())

        var state = AccountState(serverURL: "https://vault.klyt.eu", userID: "u", deviceID: "d",
                                 hybridEK: "ek", hybridVK: "vk", token: "tok")
        state.sealedIdentity = "sealed-blob"
        try store.save(state)
        XCTAssertEqual(store.load(), state)

        store.clear()
        XCTAssertNil(store.load())
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
