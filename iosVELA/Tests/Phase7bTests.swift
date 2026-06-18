import XCTest
@testable import VELA

/// Phase 7b — enrollment (joining side), background-sync plumbing, security model.
final class Phase7bTests: XCTestCase {

    // MARK: Enrollment code parsing

    func testParseV1DirectCode() throws {
        let json = """
        {"device_id":"D1","hybrid_ek":"EK","hybrid_vk":"VK","hybrid_sk":"SK",
         "transfer_key":"TK","server_url":"https://vault.klyt.eu"}
        """
        let code = Data(json.utf8).base64EncodedString()
        guard case let .direct(payload) = try EnrollmentCode.parse(code) else {
            return XCTFail("expected direct payload")
        }
        XCTAssertEqual(payload.device_id, "D1")
        XCTAssertEqual(payload.transfer_key, "TK")
        XCTAssertEqual(payload.server_url, "https://vault.klyt.eu")
    }

    func testParseV2LocatorCode() throws {
        let locator = #"{"v":2,"u":"https://vault.klyt.eu","t":"tok123","k":"a-b_c"}"#
        let b64url = Data(locator.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let code = EnrollmentCode.v2Prefix + b64url
        guard case let .v2(url, token, key) = try EnrollmentCode.parse(code) else {
            return XCTFail("expected v2 locator")
        }
        XCTAssertEqual(url, "https://vault.klyt.eu")
        XCTAssertEqual(token, "tok123")
        XCTAssertEqual(key, "a-b_c")
    }

    func testMalformedCodeThrows() {
        XCTAssertThrowsError(try EnrollmentCode.parse("!!!not base64!!!"))
    }

    func testBase64URLDecoding() {
        // "Ma" url-safe variants with/without padding decode identically.
        XCTAssertEqual(EnrollmentCode.dataFromBase64URL("TWE"), Data("Ma".utf8))
        XCTAssertEqual(EnrollmentCode.dataFromBase64URL("TWE="), Data("Ma".utf8))
    }

    // MARK: Adopt a recovered RMS

    func testRepositoryAdoptBiometricAndPassword() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let recovered = Data((0..<32).map { _ in UInt8.random(in: 0...255) })

        let repoBio = VaultRepository(directory: dir)
        try repoBio.adoptRMSBiometric(recovered)              // FileRMSStore on simulator
        try repoBio.save(VaultStore(items: []), rms: recovered)
        XCTAssertTrue(repoBio.hasVault())
        XCTAssertEqual(try repoBio.loadRMS(), recovered)

        let dir2 = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let repoPw = VaultRepository(directory: dir2)
        try repoPw.adoptRMSWithPassword(recovered, password: "guardians-assemble")
        XCTAssertTrue(repoPw.usesPasswordUnlock)
        XCTAssertEqual(try repoPw.loadRMSWithPassword("guardians-assemble"), recovered)
        XCTAssertThrowsError(try repoPw.loadRMSWithPassword("nope"))
    }

    // MARK: Capsule client

    func testGetCapsuleParses() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/device/capsule")
            return (HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    Data(#"{"capsule":"Y2Fwc3VsZQ=="}"#.utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let client = VelaClient(baseURL: URL(string: "https://vault.example")!, token: "T",
                                session: URLSession(configuration: config))
        let capsule = try await client.getCapsule()
        XCTAssertEqual(capsule, "Y2Fwc3VsZQ==")
    }
}
