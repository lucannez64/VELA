import XCTest
@testable import VELA

/// iOS inserts one value at a time, so a card must be offered as its number,
/// expiry, CVV and cardholder separately — and a login must never be offered.
final class CardInsertTests: XCTestCase {

    func testCardValuesAreOfferedIndividually() {
        let card = VaultItem.newCard(name: "Visa", number: "4111111111111111", exp: "12/29",
                                     cvv: "123", pin: "4321", cardholderName: "Alice Smith", notes: nil)
        let insertables = CardInsert.insertables(from: [card])
        XCTAssertEqual(insertables.map(\.value), ["4111111111111111", "12/29", "123", "Alice Smith"])
        XCTAssertEqual(insertables.first?.label, "Visa · Card number")
    }

    func testEmptyFieldsAreOmitted() {
        let card = VaultItem.newCard(name: "Visa", number: "4111111111111111", exp: "", cvv: "",
                                     pin: nil, cardholderName: nil, notes: nil)
        let insertables = CardInsert.insertables(from: [card])
        XCTAssertEqual(insertables.count, 1)
        XCTAssertEqual(insertables.first?.value, "4111111111111111")
    }

    func testLoginsAreNotOffered() {
        let login = VaultItem.newLogin(name: "GitHub", url: "https://github.com",
                                       username: "alice", password: "hunter2", totp: nil)
        XCTAssertTrue(CardInsert.insertables(from: [login]).isEmpty)
    }
}
