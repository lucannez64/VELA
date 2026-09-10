import XCTest
@testable import VELA

/// The vault event stream's pure framing and filtering rules. The socket side
/// is exercised by the desktop and web clients' tests; this covers what iOS
/// itself would mis-read: split frames, data lines, and self-writes.
final class VaultEventStreamTests: XCTestCase {

    func testPayloadJoinsDataLinesAndTakesOneLeadingSpace() {
        let payload = VelaClient.payload(fromEventLines: [
            "event: change",
            "data: {\"a\":1}",
            "data: second",
            ": keep-alive",
        ])
        XCTAssertEqual(payload, "{\"a\":1}\nsecond")

        // A keep-alive comment or a hello frame carries no data.
        XCTAssertNil(VelaClient.payload(fromEventLines: ["event: hello", ": keep-alive"]))
        XCTAssertEqual(VelaClient.payload(fromEventLines: ["data:leading"]), "leading")
    }

    func testOwnWritesAndControlFramesDoNotRequestSync() {
        let me = "11111111-1111-1111-1111-111111111111"
        XCTAssertFalse(VelaClient.eventRequestsSync(
            VelaClient.VaultEvent(revision: 7, writer: me, epoch: 1, kind: "chunk"),
            deviceID: me))
        XCTAssertTrue(VelaClient.eventRequestsSync(
            VelaClient.VaultEvent(revision: 8, writer: "22222222-2222-2222-2222-222222222222", epoch: 1, kind: "chunk"),
            deviceID: me))
        // Epoch commit / lagged resync: no useful writer, always sync.
        XCTAssertTrue(VelaClient.eventRequestsSync(
            VelaClient.VaultEvent(revision: nil, writer: nil, epoch: nil, kind: "epoch"),
            deviceID: me))
        // Opening hello: no kind, informational only.
        XCTAssertFalse(VelaClient.eventRequestsSync(
            VelaClient.VaultEvent(revision: 4, writer: nil, epoch: 1, kind: nil),
            deviceID: me))
    }
}
