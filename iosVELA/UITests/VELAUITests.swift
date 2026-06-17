import XCTest

/// Drives the whole app through its features so CI can screen-record a walkthrough:
/// create vault → add two logins → open detail → reveal password → delete.
/// Paced with short sleeps so the recorded video is watchable.
final class VELAUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    func testFullWalkthrough() {
        let app = XCUIApplication()
        app.launchEnvironment["VELA_RESET"] = "1" // always start from a fresh vault
        app.launch()

        // 1) Welcome → create a new vault
        let createButton = app.buttons["createVaultButton"]
        XCTAssertTrue(createButton.waitForExistence(timeout: 15), "welcome screen")
        sleep(2)
        createButton.tap()

        // 2) Empty vault → add the first login
        let addButton = app.buttons["addItemButton"]
        XCTAssertTrue(addButton.waitForExistence(timeout: 15), "vault list")
        sleep(1)
        addButton.tap()
        addLogin(app, name: "GitHub", url: "https://github.com", username: "alice", password: "h7Kp2qZ")
        XCTAssertTrue(app.staticTexts["GitHub"].waitForExistence(timeout: 15), "GitHub row")
        sleep(1)

        // 3) Add a second login
        addButton.tap()
        addLogin(app, name: "Proton Mail", url: "https://proton.me", username: "alice@proton.me", password: "Zq9vT3m")
        XCTAssertTrue(app.staticTexts["Proton Mail"].waitForExistence(timeout: 15), "Proton row")
        sleep(1)

        // 4) Open GitHub detail and reveal the password
        app.staticTexts["GitHub"].firstMatch.tap()
        let reveal = app.buttons["revealButton"]
        XCTAssertTrue(reveal.waitForExistence(timeout: 15), "detail screen")
        sleep(1)
        reveal.tap()
        sleep(2)

        // 5) Delete it, return to the list (Proton remains)
        let deleteButton = app.buttons["deleteButton"]
        XCTAssertTrue(deleteButton.waitForExistence(timeout: 15), "delete button")
        deleteButton.tap()
        sleep(2)
        XCTAssertTrue(app.staticTexts["Proton Mail"].waitForExistence(timeout: 15), "back on list")
        XCTAssertFalse(app.staticTexts["GitHub"].exists, "GitHub deleted")
        sleep(2)

        // 6) Relaunch without a reset → vault is locked → unlock (Phase 2: Face ID).
        app.terminate()
        app.launchEnvironment["VELA_RESET"] = "0" // keep the existing vault on disk
        app.launch()
        let unlockButton = app.buttons["unlockButton"]
        XCTAssertTrue(unlockButton.waitForExistence(timeout: 15), "lock screen")
        sleep(2)
        unlockButton.tap()
        XCTAssertTrue(app.staticTexts["Proton Mail"].waitForExistence(timeout: 15), "unlocked vault")
        sleep(2)
    }

    private func addLogin(_ app: XCUIApplication, name: String, url: String, username: String, password: String) {
        let nameField = app.textFields["nameField"]
        XCTAssertTrue(nameField.waitForExistence(timeout: 15), "add sheet")
        nameField.tap(); nameField.typeText(name); sleep(1)
        let urlField = app.textFields["urlField"]
        urlField.tap(); urlField.typeText(url); sleep(1)
        let userField = app.textFields["usernameField"]
        userField.tap(); userField.typeText(username); sleep(1)
        let passField = app.secureTextFields["passwordField"]
        passField.tap(); passField.typeText(password); sleep(1)
        app.buttons["saveButton"].tap()
    }
}
