import XCTest
@testable import VELA

/// Verifies the Phase 1b vault lifecycle on iOS: create, add, persist, reload,
/// decrypt, and wrong-key rejection — all going through the Rust core's crypto.
final class VaultRepositoryTests: XCTestCase {
    private func tempRepo() -> VaultRepository {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("velatests-\(UUID().uuidString)", isDirectory: true)
        return VaultRepository(directory: dir)
    }

    func testCreateAddPersistReloadDecrypt() throws {
        let repo = tempRepo()
        let rms = try repo.generateAndStoreRMS()
        try repo.save(VaultStore(items: []), rms: rms)
        XCTAssertTrue(repo.hasVault())

        var store = try repo.load(rms: rms)
        XCTAssertEqual(store.items.count, 0)

        store.items.append(.newLogin(
            name: "GitHub", url: "https://github.com",
            username: "alice", password: "hunter2", totp: nil
        ))
        try repo.save(store, rms: rms)

        let reloaded = try repo.load(rms: rms)
        XCTAssertEqual(reloaded.items.count, 1)
        XCTAssertEqual(reloaded.items[0].name, "GitHub")
        XCTAssertEqual(reloaded.items[0].username ?? "", "alice")
        XCTAssertEqual(reloaded.items[0].password ?? "", "hunter2")
        XCTAssertEqual(reloaded.items[0].kind, .login)
        XCTAssertEqual(reloaded.items[0].item_type, "login")
    }

    func testWrongRmsCannotDecrypt() throws {
        let repo = tempRepo()
        let rms = try repo.generateAndStoreRMS()
        try repo.save(VaultStore(items: [
            .newLogin(name: "X", url: "https://x.com", username: "u", password: "p", totp: nil)
        ]), rms: rms)

        var wrong = Data(repeating: 0, count: 32)
        wrong[0] = 0xFF
        XCTAssertThrowsError(try repo.load(rms: wrong))
    }

    func testCoreVersionAvailable() {
        XCTAssertTrue(VelaCoreFFI.version().hasPrefix("vela-apple-bridge/"))
    }

    // MARK: - Phase 2: RMS store

    func testRmsRoundTripAndReset() throws {
        let repo = tempRepo()
        XCTAssertFalse(repo.hasVault())

        let rms = try repo.generateAndStoreRMS()
        try repo.save(VaultStore(items: []), rms: rms)
        XCTAssertTrue(repo.hasVault())

        // loadRMS returns the same seed (FileRMSStore ignores the LAContext).
        let reloaded = try repo.loadRMS()
        XCTAssertEqual(reloaded, rms)

        repo.reset()
        XCTAssertFalse(repo.hasVault())
        XCTAssertThrowsError(try repo.loadRMS())
    }

    func testFileRmsStoreGeneratesDistinctSeeds() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("velarms-\(UUID().uuidString)", isDirectory: true)
        let store = FileRMSStore(directory: dir)
        XCTAssertFalse(store.exists())

        let a = try store.generate()
        XCTAssertEqual(a.count, 32)
        XCTAssertTrue(store.exists())

        let b = try store.generate()
        XCTAssertNotEqual(a, b, "each generate() must mint a fresh RMS")
        XCTAssertEqual(try store.load(context: nil), b)

        store.delete()
        XCTAssertFalse(store.exists())
    }
}
