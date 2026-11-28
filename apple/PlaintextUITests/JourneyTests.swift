import XCTest

/// Drives the iPhone app through every core screen against a local server and
/// keeps a screenshot of each. Run by apple/screenshots.sh, which starts the
/// server, seeds the other people with the CLI and collects the images:
/// PT_SERVER, PT_INVITE (from bob) and PT_IMPORT_FILE come from it.
final class JourneyTests: XCTestCase {
    let app = XCUIApplication()
    var env: [String: String] { ProcessInfo.processInfo.environment }
    var n = 0

    override func setUp() {
        continueAfterFailure = false
        app.launchEnvironment["PT_IMPORT_FILE"] = env["PT_IMPORT_FILE"]
    }

    func shot(_ name: String) {
        n += 1
        sleep(1)
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = String(format: "%02d-%@", n, name)
        a.lifetime = .keepAlways
        add(a)
    }

    /// Waits for `e`, scrolling to it when it's off screen in a list.
    func tap(_ e: XCUIElement, _ timeout: TimeInterval = 15) {
        if !e.waitForExistence(timeout: min(timeout, 4)) || !e.isHittable {
            for _ in 0..<4 where !(e.exists && e.isHittable) { app.swipeUp() }
            for _ in 0..<8 where !(e.exists && e.isHittable) { app.swipeDown() }
        }
        XCTAssertTrue(e.waitForExistence(timeout: timeout), "missing \(e)")
        e.tap()
    }

    func type(_ e: XCUIElement, _ text: String) {
        tap(e)
        e.typeText(text)
    }

    var password = ""

    func hideKeyboard() {
        let r = app.keyboards.buttons.matching(NSPredicate(format: "label ==[c] 'return' OR label ==[c] 'done'")).firstMatch
        if r.exists { r.tap() }
    }

    func testJourney() throws {
        let server = try XCTUnwrap(env["PT_SERVER"])
        let invite = try XCTUnwrap(env["PT_INVITE"])
        app.launch()

        // First run.
        XCTAssertTrue(app.buttons["Create account"].waitForExistence(timeout: 20))
        shot("welcome")
        tap(app.buttons["Create account"])
        type(app.textFields["vault.example.com"], server)
        app.swipeDown()
        shot("server")
        tap(app.buttons["Continue"])
        type(app.textFields["alex"], "alice")
        tap(app.buttons["Suggest one"])
        password = try XCTUnwrap(app.textFields["A long, memorable password"].value as? String)
        type(app.textFields["Paste the invite code"], invite)
        app.swipeDown()
        shot("create-account")
        tap(app.buttons["Create account"])
        XCTAssertTrue(app.buttons["I've saved it"].waitForExistence(timeout: 60))
        shot("emergency-kit")
        tap(app.buttons["I've saved it"])
        shot("biometrics")
        let turnOn = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Turn on'")).firstMatch
        if turnOn.waitForExistence(timeout: 3) { turnOn.tap() } else { tap(app.buttons["Not now"]) }

        // Empty home, then import the 1PUX export.
        XCTAssertTrue(app.tabBars.buttons["Items"].waitForExistence(timeout: 20))
        sleep(2)
        shot("home-empty")
        tap(app.buttons["Import"])
        tap(app.buttons["Choose file…"])
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Imported'")).firstMatch.waitForExistence(timeout: 60))
        shot("import-done")
        tap(app.buttons["Done"])

        // A login of our own with the generator.
        tap(app.buttons["New item"])
        shot("kind-picker")
        tap(app.buttons["Login"])
        type(app.textFields["Title"], "GitHub")
        type(app.textFields["Username"], "alice@example.com")
        hideKeyboard()
        tap(app.buttons["Generator options"])
        shot("editor")
        tap(app.buttons["Save"])
        sleep(2)

        // The list, search and the vault picker.
        app.swipeDown()
        shot("home")
        tap(app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Vault:'")).firstMatch)
        shot("vault-picker")
        tap(app.buttons["All items"])

        // Item detail: reveal, large type.
        tap(app.staticTexts["GitHub"])
        shot("item-detail")
        tap(app.buttons["Reveal password"])
        tap(app.buttons["Show password in large type"])
        shot("large-type")
        tap(app.buttons["Done"])
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // bob's shared login with a one-time code.
        tap(app.staticTexts["Family email"], 60)
        shot("item-detail-code")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        tap(app.staticTexts["GitHub"])
        tap(app.buttons["Edit"])
        shot("edit-item")
        tap(app.buttons["Cancel"])

        // Share the item: to a person and as a link.
        tap(app.buttons["More actions"])
        shot("item-actions")
        tap(app.buttons["Share…"])
        type(app.textFields["Their username"], "bob")
        shot("share-item-person")
        tap(app.buttons["Send"])
        sleep(3)
        tap(app.buttons["More actions"])
        tap(app.buttons["Share…"])
        tap(app.buttons["Create a link"])
        tap(app.buttons["Create"])
        XCTAssertTrue(app.buttons["Copy link"].waitForExistence(timeout: 20))
        shot("share-item-link")
        tap(app.buttons["Done"])
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // Watchtower and Inbox.
        tap(app.tabBars.buttons["Watchtower"])
        shot("watchtower")
        tap(app.tabBars.buttons["Inbox"])
        app.swipeDown()
        sleep(3)
        shot("inbox")

        // Vaults: share the imported Shared vault with bob, then verify him.
        tap(app.tabBars.buttons["Settings"])
        shot("settings")
        tap(app.buttons["Vaults and sharing"])
        shot("vaults")
        tap(app.staticTexts["Shared"])
        tap(app.buttons["Share vault"])
        type(app.textFields["Their username"], "bob")
        tap(app.buttons["Find"])
        hideKeyboard()
        sleep(2)
        shot("share-vault")
        tap(app.buttons["Share"])
        sleep(3)
        shot("vault-members")
        // bob is verified already (his invite carried his fingerprint): open Verify from his row.
        app.staticTexts["bob"].firstMatch.press(forDuration: 1.2)
        tap(app.buttons["Verify…"])
        shot("verify")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        app.navigationBars.buttons.element(boundBy: 0).tap()
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // An agent with access to the Shared vault.
        tap(app.buttons["Agents"])
        tap(app.buttons["New agent"])
        type(app.textFields["deploy-bot"], "deploy-bot")
        shot("new-agent")
        tap(app.buttons["Create"])
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'ptk_'")).firstMatch.waitForExistence(timeout: 30))
        shot("agent-key")
        tap(app.buttons["Done"])
        sleep(2)
        shot("agents")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // The account, devices and adding a device.
        tap(app.staticTexts["alice"])
        sleep(2)
        shot("account")
        tap(app.buttons["Add a device"])
        tap(app.buttons["Show the code"])
        shot("add-device")
        tap(app.buttons["Done"])
        // Only admins (and everyone on an open server) can invite; alice is neither here.
        XCTAssertFalse(app.buttons["Invite someone"].exists)
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // Lock and unlock with the password.
        tap(app.buttons["Lock now"])
        sleep(2)
        shot("unlock")
        let bio = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Unlock with'")).firstMatch
        if bio.exists { bio.tap() } else { type(app.secureTextFields["Password"], password + "\n") }
        XCTAssertTrue(app.tabBars.buttons["Items"].waitForExistence(timeout: 60))
    }
}
