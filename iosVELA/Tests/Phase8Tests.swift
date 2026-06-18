import XCTest
@testable import VELA

/// Phase 8 — breach monitor (k-anonymity) and the local audit log.
final class Phase8Tests: XCTestCase {

    private func mockSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    /// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 → prefix 5BAA6, suffix 1E4C9...
    func testPasswordBreachDetectedViaKAnonymity() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.host, "api.pwnedpasswords.com")
            XCTAssertEqual(req.url?.lastPathComponent, "5BAA6") // only the prefix is sent
            // Return the matching suffix with a count, plus noise.
            let body = "0000000000000000000000000000000000:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42"
            return (Self.ok(req), Data(body.utf8))
        }
        let result = try await BreachService.checkPassword("password", session: mockSession())
        XCTAssertTrue(result.breached)
        XCTAssertEqual(result.count, 42)
    }

    func testPasswordNotBreached() async throws {
        MockURLProtocol.handler = { req in
            (Self.ok(req), Data("ABCDEF0000000000000000000000000000:3".utf8))
        }
        let result = try await BreachService.checkPassword("password", session: mockSession())
        XCTAssertFalse(result.breached)
        XCTAssertEqual(result.count, 0)
    }

    func testEmailRequiresApiKeyOn401() async throws {
        MockURLProtocol.handler = { req in
            (HTTPURLResponse(url: req.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!, Data())
        }
        do {
            _ = try await BreachService.checkEmail("a@b.com", session: mockSession())
            XCTFail("should require an API key")
        } catch {
            XCTAssertTrue("\(error)".localizedCaseInsensitiveContains("api key"))
        }
    }

    func testEmailNotFoundReturnsEmpty() async throws {
        MockURLProtocol.handler = { req in
            (HTTPURLResponse(url: req.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!, Data())
        }
        let breaches = try await BreachService.checkEmail("a@b.com", session: mockSession())
        XCTAssertTrue(breaches.isEmpty)
    }

    // MARK: Audit log

    func testAuditLogRecordsNewestFirstAndCaps() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let log = AuditLog(directory: dir)
        XCTAssertTrue(log.entries().isEmpty)

        log.record("vault_unlocked", "biometric")
        log.record("item_added", "login")
        let entries = log.entries()
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries.first?.action, "item_added") // newest first
        XCTAssertEqual(entries.first?.detail, "login")

        log.clear()
        XCTAssertTrue(log.entries().isEmpty)
    }

    private static func ok(_ req: URLRequest) -> HTTPURLResponse {
        HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
    }
}
