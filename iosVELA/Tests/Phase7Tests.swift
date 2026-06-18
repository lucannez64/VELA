import XCTest
@testable import VELA

/// Phase 7 — password-based unlock (PBKDF2-HMAC-SHA256 + AES-GCM).
final class Phase7Tests: XCTestCase {
    private func tempDir() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("vela7-\(UUID().uuidString)", isDirectory: true)
    }

    func testPasswordStoreWrapUnwrapRoundTrip() throws {
        let store = PasswordRMSStore(directory: tempDir())
        XCTAssertFalse(store.exists())

        let rms = Data((0..<32).map { UInt8($0) })
        try store.wrap(rms: rms, password: "correct horse battery staple")
        XCTAssertTrue(store.exists())

        XCTAssertEqual(try store.unwrap(password: "correct horse battery staple"), rms)

        store.delete()
        XCTAssertFalse(store.exists())
    }

    func testWrongPasswordThrows() throws {
        let store = PasswordRMSStore(directory: tempDir())
        try store.wrap(rms: Data(repeating: 7, count: 32), password: "right")
        XCTAssertThrowsError(try store.unwrap(password: "wrong")) // AES-GCM tag mismatch
    }

    func testRepositoryPasswordVaultLifecycle() throws {
        let repo = VaultRepository(directory: tempDir())
        XCTAssertFalse(repo.hasVault())

        let rms = try repo.generatePasswordRMS(password: "s3cret-pass")
        try repo.save(VaultStore(items: [
            .newLogin(name: "GitHub", url: "https://github.com", username: "a", password: "p", totp: nil)
        ]), rms: rms)

        XCTAssertTrue(repo.hasVault())
        XCTAssertTrue(repo.usesPasswordUnlock)

        let reloaded = try repo.loadRMSWithPassword("s3cret-pass")
        XCTAssertEqual(reloaded, rms)
        XCTAssertEqual(try repo.load(rms: reloaded).items.first?.name, "GitHub")

        XCTAssertThrowsError(try repo.loadRMSWithPassword("nope"))
    }

    func testDeriveKeyIsDeterministic() throws {
        let salt = Data(repeating: 9, count: 16)
        let a = try PasswordRMSStore.deriveKey(password: "pw", salt: salt, iterations: 1000)
        let b = try PasswordRMSStore.deriveKey(password: "pw", salt: salt, iterations: 1000)
        XCTAssertEqual(a, b)
        let c = try PasswordRMSStore.deriveKey(password: "pw2", salt: salt, iterations: 1000)
        XCTAssertNotEqual(a, c)
    }
}
