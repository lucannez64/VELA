import XCTest
@testable import VELA

/// Phase 3: domain matching used by the AutoFill credential provider to pick
/// which stored logins to offer for a requested service.
final class AutofillMatchTests: XCTestCase {
    func testExactHostMatches() {
        XCTAssertTrue(AutofillMatch.domainsMatch(query: "https://github.com/login", stored: "github.com"))
        XCTAssertTrue(AutofillMatch.domainsMatch(query: "github.com", stored: "https://github.com"))
    }

    func testWwwIsIgnored() {
        XCTAssertTrue(AutofillMatch.domainsMatch(query: "https://www.github.com", stored: "github.com"))
    }

    func testSubdomainQueryMatchesRegistrableStored() {
        // Requested mail.google.com should match a stored google.com login.
        XCTAssertTrue(AutofillMatch.domainsMatch(query: "https://mail.google.com", stored: "google.com"))
    }

    func testStoredSubdomainDoesNotMatchBareQuery() {
        // Stored is more specific than the request → no match.
        XCTAssertFalse(AutofillMatch.domainsMatch(query: "google.com", stored: "mail.google.com"))
    }

    func testDifferentDomainsDoNotMatch() {
        XCTAssertFalse(AutofillMatch.domainsMatch(query: "https://evil.com", stored: "github.com"))
        // Suffix-but-not-on-a-boundary must not match.
        XCTAssertFalse(AutofillMatch.domainsMatch(query: "https://notgithub.com", stored: "github.com"))
    }

    func testIPAddressesMatchOnlyExactly() {
        XCTAssertTrue(AutofillMatch.domainsMatch(query: "https://192.168.1.10", stored: "192.168.1.10"))
        XCTAssertFalse(AutofillMatch.domainsMatch(query: "https://192.168.1.10", stored: "168.1.10"))
    }

    func testLoginsFiltersByServiceIdentifiers() {
        let items = [
            VaultItem.newLogin(name: "GitHub", url: "https://github.com", username: "alice", password: "x", totp: nil),
            VaultItem.newLogin(name: "Google", url: "https://google.com", username: "bob", password: "y", totp: nil),
        ]
        let github = AutofillMatch.logins(items, matching: ["https://github.com/session"])
        XCTAssertEqual(github.map { $0.name }, ["GitHub"])

        let google = AutofillMatch.logins(items, matching: ["accounts.google.com"])
        XCTAssertEqual(google.map { $0.name }, ["Google"])
    }

    func testNoServiceIdentifiersReturnsAllLogins() {
        let items = [
            VaultItem.newLogin(name: "A", url: "https://a.com", username: "a", password: "p", totp: nil),
            VaultItem.newLogin(name: "B", url: "https://b.com", username: "b", password: "p", totp: nil),
        ]
        XCTAssertEqual(AutofillMatch.logins(items, matching: []).count, 2)
        XCTAssertEqual(AutofillMatch.logins(items, matching: ["   "]).count, 2)
    }
}
