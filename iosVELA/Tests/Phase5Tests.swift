import XCTest
@testable import VELA

/// Phase 5 — item depth: TOTP, password generator, and multi-type Codable
/// round-trips through the Rust core.
final class Phase5Tests: XCTestCase {

    // MARK: TOTP (RFC 6238)

    func testTotpRfc6238Vector() {
        // RFC 6238 test secret "12345678901234567890" in Base32, SHA1, 6 digits.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        guard let totp = TOTP(string: secret) else { return XCTFail("parse failed") }
        XCTAssertEqual(totp.code(at: Date(timeIntervalSince1970: 59)), "287082")
        XCTAssertEqual(totp.code(at: Date(timeIntervalSince1970: 1111111109)), "081804")
    }

    func testTotpParsesOtpauthURL() {
        let url = "otpauth://totp/VELA:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
        guard let totp = TOTP(string: url) else { return XCTFail("parse failed") }
        XCTAssertEqual(totp.code(at: Date(timeIntervalSince1970: 59)), "287082")
    }

    func testTotpRejectsGarbage() {
        XCTAssertNil(TOTP(string: ""))
        XCTAssertNil(TOTP(string: "10")) // '0','1' aren't Base32 → no bytes
    }

    func testSecondsRemainingWithinPeriod() {
        guard let totp = TOTP(string: "GEZDGNBVGY3TQOJQ") else { return XCTFail("parse") }
        let remaining = totp.secondsRemaining(at: Date(timeIntervalSince1970: 25))
        XCTAssertEqual(remaining, 5)
    }

    // MARK: Password generator

    func testGeneratorLengthAndCharset() {
        let pwd = PasswordGenerator.generate(length: 32, uppercase: false, symbols: false)
        XCTAssertEqual(pwd.count, 32)
        XCTAssertFalse(pwd.contains { PasswordGenerator.symbols.contains($0) })
        XCTAssertFalse(pwd.contains { $0.isUppercase })
    }

    func testGeneratorCanIncludeSymbols() {
        // Statistically a 200-char password will include at least one symbol.
        let pwd = PasswordGenerator.generate(length: 200, uppercase: true, symbols: true)
        XCTAssertTrue(pwd.contains { PasswordGenerator.symbols.contains($0) })
    }

    // MARK: Multi-type round-trip through the core

    private let rms = Data(repeating: 8, count: 32).base64EncodedString()

    private func roundTrip(_ item: VaultItem) throws -> VaultItem {
        let json = String(decoding: try JSONEncoder().encode(VaultStore(items: [item])), as: UTF8.self)
        let cipher = try XCTUnwrap(VelaCoreFFI.encryptVault(rmsBase64: rms, vaultJSON: json))
        let back = try XCTUnwrap(VelaCoreFFI.decryptVault(rmsBase64: rms, ciphertextBase64: cipher))
        let store = try JSONDecoder().decode(VaultStore.self, from: Data(back.utf8))
        return try XCTUnwrap(store.items.first)
    }

    func testCreditCardRoundTrip() throws {
        let card = VaultItem.newCard(name: "Visa", number: "4111111111111111", exp: "12/29",
                                     cvv: "123", pin: "4321", cardholderName: "Alice Smith", notes: "main")
        let back = try roundTrip(card)
        XCTAssertEqual(back.kind, .creditCard)
        XCTAssertEqual(back.item_type, "creditCard")
        XCTAssertEqual(back.number ?? "", "4111111111111111")
        XCTAssertEqual(back.exp ?? "", "12/29")
        XCTAssertEqual(back.cvv ?? "", "123")
        XCTAssertEqual(back.cardholderName ?? "", "Alice Smith")
        XCTAssertEqual(back.maskedCardNumber, "•••• 1111")
    }

    func testSecureNoteRoundTrip() throws {
        let note = VaultItem.newNote(name: "Recovery codes", content: "abc-123\nxyz-789")
        let back = try roundTrip(note)
        XCTAssertEqual(back.kind, .secureNote)
        XCTAssertEqual(back.content ?? "", "abc-123\nxyz-789")
        XCTAssertEqual(back.title ?? "", "Recovery codes")
    }

    func testLoginStillRoundTripsWithTotp() throws {
        let login = VaultItem.newLogin(name: "GitHub", url: "https://github.com",
                                       username: "alice", password: "hunter2", totp: "GEZDGNBVGY3TQOJQ")
        let back = try roundTrip(login)
        XCTAssertEqual(back.kind, .login)
        XCTAssertEqual(back.password ?? "", "hunter2")
        XCTAssertEqual(back.totp ?? "", "GEZDGNBVGY3TQOJQ")
    }

    func testTouchedUpdatesTimestamp() {
        let item = VaultItem.newNote(name: "x", content: "y")
        let before = item.updatedAt
        let after = item.touched().updatedAt
        XCTAssertGreaterThanOrEqual(after, before)
    }
}
