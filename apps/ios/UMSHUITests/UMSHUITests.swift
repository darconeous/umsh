import XCTest

@MainActor
final class UMSHUITests: XCTestCase {
    func testFailedNameSavePreservesInputAndAllowsRetry() throws {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchEnvironment["UMSH_UI_TESTING"] = "1"
        app.launch()
        let name = app.textFields["Name"]
        XCTAssertTrue(name.waitForExistence(timeout: 10))
        name.tap()
        name.typeText("Ridge Medic")
        app.buttons["onboarding.continue"].tap()
        XCTAssertTrue(app.staticTexts["Changes could not be saved. Please try again."].waitForExistence(timeout: 5))
        XCTAssertEqual(name.value as? String, "Ridge Medic")
        XCTAssertFalse(app.navigationBars["Connect a Radio"].exists)
        app.buttons["Try Again"].tap()
        XCTAssertTrue(app.navigationBars["Connect a Radio"].waitForExistence(timeout: 5))
    }
}
