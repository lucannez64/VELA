import XCTest
@testable import VELA

/// Schema-2 support on iOS: unknown keys survive, edits don't resurrect
/// cleared fields, records keep their extra properties, and the core
/// validates and merges organization data.
final class RichItemsTests: XCTestCase {
    private let json = """
    {"schemaVersion":2,"folders":[],"tags":[],"organizationTombstones":[],"tombstones":[],
     "items":[{"item_type":"login","id":"a","name":"Site","createdAt":"2026-01-01T00:00:00Z",
               "updatedAt":"2026-01-01T00:00:00Z","totp":"JBSWY3DPEHPK3PXP",
               "futureKey":{"nested":[1,2,3]}}]}
    """

    func testUnknownItemKeysSurviveRoundTrip() throws {
        let store = try JSONDecoder().decode(VaultStore.self, from: Data(json.utf8))
        XCTAssertEqual(store.unknownItemKeys["a"]?.keys.sorted(), ["futureKey"])
        let encoded = try JSONEncoder().encode(store)
        let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        let item = (object?["items"] as? [[String: Any]])?.first
        XCTAssertNotNil(item?["futureKey"])
    }

    func testClearedFieldIsNotResurrected() throws {
        var store = try JSONDecoder().decode(VaultStore.self, from: Data(json.utf8))
        store.items[0].totp = nil
        let encoded = try JSONEncoder().encode(store)
        let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        let item = (object?["items"] as? [[String: Any]])?.first
        XCTAssertNil(item?["totp"])
        XCTAssertNotNil(item?["futureKey"])
    }

    func testMissingMetadataFlagsUseCoreDefaults() throws {
        let store = try JSONDecoder().decode(VaultStore.self, from: Data(json.utf8))
        XCTAssertFalse(store.items[0].favorite)
        XCTAssertFalse(store.items[0].shared)
        // Malformed flags are rejected instead of silently changing their meaning.
        let malformed = json.replacingOccurrences(of: "\"name\":\"Site\"", with: "\"name\":\"Site\",\"favorite\":\"yes\"")
        XCTAssertThrowsError(try JSONDecoder().decode(VaultStore.self, from: Data(malformed.utf8)))
    }

    func testInvalidOrganizationAbortsMerge() {
        let invalid = VaultStore(items: [], schemaVersion: 2, folders: [.object(["id": .string("broken")])])
        XCTAssertThrowsError(try VaultMerge.mergeStores(local: invalid, remote: VaultStore(items: [])))
    }

    func testMergeRepairsDeletedAssignmentsWithoutChangingSecrets() throws {
        let folderID = UUID().uuidString.lowercased()
        let tagID = UUID().uuidString.lowercased()
        var item = VaultItem.newLogin(name: "Example", url: "https://example.test", username: "a", password: "secret", totp: nil)
        item.folderId = folderID
        item.tagIds = [tagID]
        let store = VaultStore(items: [item], schemaVersion: 2)
        let merged = try VaultMerge.mergeStores(local: store, remote: VaultStore(items: [], schemaVersion: 2))
        XCTAssertEqual(merged.items.first?.folderId, "")
        XCTAssertEqual(merged.items.first?.tagIds, [])
        XCTAssertEqual(merged.items.first?.password, "secret")
    }

    func testIdentityWireNamesAndItemKinds() throws {
        let raw = """
        {"item_type":"identity","id":"identity-1","name":"Alex","createdAt":"2026-01-01T00:00:00Z",
         "updatedAt":"2026-01-01T00:00:00Z","first_name":"Alex","last_name":"Demo","ssn":""}
        """
        let item = try JSONDecoder().decode(VaultItem.self, from: Data(raw.utf8))
        XCTAssertEqual(item.kind, .identity)
        XCTAssertEqual(item.firstName, "Alex")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(item)) as? [String: Any])
        XCTAssertEqual(object["first_name"] as? String, "Alex")
        XCTAssertNil(object["firstName"])
        let legacy = raw.replacingOccurrences(of: "first_name", with: "firstName").replacingOccurrences(of: "last_name", with: "lastName")
        XCTAssertEqual(try JSONDecoder().decode(VaultItem.self, from: Data(legacy.utf8)).firstName, "Alex")
        var future = item
        future.item_type = "future-item"
        XCTAssertEqual(future.kind, .unsupported)
        future.item_type = "passkey"
        XCTAssertEqual(future.kind, .passkey)
    }

    func testCustomFieldKeepsExtraProperties() {
        let record = PreservedJSON.object([
            "id": .string(UUID().uuidString.lowercased()), "label": .string("PIN"),
            "type": .string("concealed"), "value": .string("1234"), "hint": .string("from v3"),
        ])
        var draft = CustomFieldDraft(record: record)!
        draft.text = "9999"
        let out = draft.record.objectValue!
        XCTAssertEqual(out["value"]?.stringValue, "9999")
        XCTAssertEqual(out["hint"]?.stringValue, "from v3")
    }

    func testCoreValidatesCustomFieldsAndMergesFolders() throws {
        var field = CustomFieldDraft(kind: .text)
        field.label = "Recovery email"
        field.text = "a@example.test"
        var item = VaultItem.newLogin(name: "Site", url: "https://example.test", username: "a", password: "p", totp: nil)
        item.customFields = [field.record]
        XCTAssertNoThrow(try VelaCoreFFI.richItems(["operation": "validate", "organization": [:], "rich": item.richObject]))

        var unnamed = CustomFieldDraft(kind: .text)
        unnamed.text = "value"
        item.customFields = [unnamed.record]
        XCTAssertThrowsError(try VelaCoreFFI.richItems(["operation": "validate", "organization": [:], "rich": item.richObject]))

        let org = try VelaCoreFFI.richItems(["operation": "mutate", "deviceId": "ios-test", "organization": [:],
                                             "action": ["operation": "createFolder", "name": "Work"]])
        let local = VaultStore(items: [], schemaVersion: 2,
                               folders: ((org["folders"] as? [Any]) ?? []).compactMap { PreservedJSON(any: $0) })
        let merged = try VaultMerge.mergeStores(local: local, remote: VaultStore(items: [], schemaVersion: 2))
        XCTAssertEqual(VaultOrganization(store: merged).folders.map(\.name), ["Work"])
    }
}
