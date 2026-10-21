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
        let merged = VaultMerge.mergeStores(local: local, remote: VaultStore(items: [], schemaVersion: 2))
        XCTAssertEqual(VaultOrganization(store: merged).folders.map(\.name), ["Work"])
    }
}
