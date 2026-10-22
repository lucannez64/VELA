import XCTest
@testable import VELA

/// Import fidelity on iOS: the parser runs in the shared Rust crate over FFI,
/// and `VaultViewModel.importVault` maps entries onto the vault.
final class ImportTests: XCTestCase {
    private func tempDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("vela-import-\(UUID().uuidString)", isDirectory: true)
    }

    func testImportParserAnswersThroughTheCore() throws {
        let csv = "name,url,username,password\nGitHub,https://github.com,octo,pw"
        let response = try VelaCoreFFI.parseImport([
            "dataBase64": Data(csv.utf8).base64EncodedString(),
        ])
        XCTAssertEqual(response["source"] as? String, "Browser CSV")
        let entries = response["entries"] as? [[String: Any]]
        XCTAssertEqual(entries?.first?["name"] as? String, "GitHub")
        XCTAssertEqual(entries?.first?["kind"] as? String, "login")
    }

    @MainActor
    func testSchemaOneImportFoldsOrganizationIntoNotes() throws {
        let directory = tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let vm = VaultViewModel(repo: VaultRepository(directory: directory))
        try vm.createVault()

        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
            "Work,1,login,GitHub,,\"[{\"name\":\"Recovery\",\"value\":\"R-1\",\"type\":0}]\",0,https://github.com,octo,hunter2,\n"
        let summary = vm.importVault(data: Data(csv.utf8))

        XCTAssertEqual(summary.added, 1)
        XCTAssertEqual(summary.preserved, 0)
        XCTAssertGreaterThan(summary.converted, 0)
        let item = vm.items.first { $0.name == "GitHub" }
        XCTAssertNotNil(item)
        XCTAssertNil(item?.folderId)
        XCTAssertTrue(item?.notes?.contains("Folder: Work") == true)
        XCTAssertTrue(item?.notes?.contains("Recovery: R-1") == true)
    }

    @MainActor
    func testSchemaTwoImportCreatesCollectionsAndRichFields() throws {
        let directory = tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let vm = VaultViewModel(repo: VaultRepository(directory: directory))
        try vm.createVault()
        try vm.enableCollections()

        let json = """
        {
          "encrypted": false,
          "folders": [{ "id": "f1", "name": "Work" }],
          "items": [{
            "type": 1, "name": "GitHub", "folderId": "f1",
            "login": { "username": "octo", "password": "pw",
                       "uris": [{ "uri": "https://github.com" },
                                { "uri": "https://gist.github.com" }] },
            "fields": [{ "name": "Recovery", "value": "R-1", "type": 0 }]
          }]
        }
        """
        let summary = vm.importVault(data: Data(json.utf8))

        XCTAssertEqual(summary.added, 1)
        XCTAssertEqual(summary.preserved, 1)
        XCTAssertEqual(summary.converted, 0)
        let item = vm.items.first { $0.name == "GitHub" }
        XCTAssertNotNil(item?.folderId)
        XCTAssertEqual(item?.customFields?.count, 1)
        XCTAssertEqual(item?.additionalUrls?.count, 1)
        XCTAssertTrue(vm.organization.folders.contains { $0.name == "Work" })
    }
}
