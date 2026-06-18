import XCTest
@testable import VELA

/// Phase 6 — management: device/linked-share client methods and list filtering.
/// Reuses `MockURLProtocol` from Phase4Tests.
final class Phase6Tests: XCTestCase {

    private func client(token: String? = nil) -> VelaClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return VelaClient(baseURL: URL(string: "https://vault.example")!, token: token,
                          session: URLSession(configuration: config))
    }

    func testListDevicesParses() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/devices")
            let body = """
            {"devices":[
              {"id":"D1","name":"iPhone","device_type":"ios","enrolled_by":null,
               "last_active":"2026-06-18T00:00:00Z","revoked":false,"pending":false,
               "created_at":"2026-06-01T00:00:00Z"}
            ]}
            """
            return (Self.ok(req), Data(body.utf8))
        }
        let devices = try await client(token: "T").listDevices()
        XCTAssertEqual(devices.count, 1)
        XCTAssertEqual(devices.first?.name, "iPhone")
        XCTAssertFalse(devices.first?.revoked ?? true)
    }

    func testRevokeDeviceHitsEndpoint() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/device/revoke")
            XCTAssertEqual(req.httpMethod, "POST")
            return (Self.ok(req), Data("{}".utf8))
        }
        try await client(token: "T").revokeDevice(targetDeviceID: "D2")
    }

    func testLinkedSharesParses() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/share/linked")
            let body = """
            {"items":[
              {"id":"S1","sender_user_id":"U1","recipient_user_id":"U2","capsule":"AA==",
               "created_at":"2026-06-18T00:00:00Z","updated_at":"2026-06-18T00:00:00Z","revoked":false}
            ]}
            """
            return (Self.ok(req), Data(body.utf8))
        }
        let shares = try await client(token: "T").linkedShares()
        XCTAssertEqual(shares.first?.recipient_user_id, "U2")
    }

    func testDeleteLinkedShareHitsEndpoint() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/share/linked/S1")
            XCTAssertEqual(req.httpMethod, "DELETE")
            return (Self.ok(req), Data())
        }
        try await client(token: "T").deleteLinkedShare("S1")
    }

    // MARK: Filtering

    func testFilterByQueryAndKind() {
        let items = [
            VaultItem.newLogin(name: "GitHub", url: "https://github.com", username: "alice", password: "p", totp: nil),
            VaultItem.newCard(name: "Visa", number: "4111111111111111", exp: "12/29", cvv: "1", pin: nil, cardholderName: "Bob", notes: nil),
            VaultItem.newNote(name: "Wifi", content: "secret"),
        ]
        XCTAssertEqual(ItemFilter.apply(items, query: "git", kind: nil).map { $0.name }, ["GitHub"])
        XCTAssertEqual(ItemFilter.apply(items, query: "", kind: .creditCard).map { $0.name }, ["Visa"])
        // Subtitle match: cardholder "Bob".
        XCTAssertEqual(ItemFilter.apply(items, query: "bob", kind: nil).map { $0.name }, ["Visa"])
        XCTAssertEqual(ItemFilter.apply(items, query: "  ", kind: nil).count, 3)
    }

    private static func ok(_ req: URLRequest) -> HTTPURLResponse {
        HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
    }
}
