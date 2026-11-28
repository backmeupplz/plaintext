import XCTest
@testable import Plaintext

/// The Swift side of the bridge: the shared formats and tools the screens rely on.
final class PlaintextTests: XCTestCase {
    func testServerAddresses() throws {
        XCTAssertEqual(try serverAddress(address: "vault.example.com").url, "https://vault.example.com")
        XCTAssertTrue(try serverAddress(address: "http://192.168.1.4:7878").insecure)
        XCTAssertThrowsError(try serverAddress(address: "http://vault.example.com")) { e in
            XCTAssertTrue(errorText(e).contains("https"))
        }
    }

    func testCodesRoundTrip() throws {
        XCTAssertThrowsError(try normalizeSecretKey(secretKey: "A1-NOPE"))
        let invite = inviteLink(server: "https://vault.example.com", code: "abc.def")
        XCTAssertEqual(parseInviteLink(link: invite)?.server, "https://vault.example.com")
        XCTAssertNil(parseDeviceCode(code: "plaintext:device:nope"))
    }

    func testGeneratorAndStrength() {
        let pw = generatePassword(recipe: .random(length: 24, digits: true, symbols: true))
        XCTAssertEqual(pw.count, 24)
        XCTAssertEqual(passwordStrength(password: pw).level, 3)
        XCTAssertEqual(generatePassword(recipe: .pin(length: 6)).count, 6)
        XCTAssertEqual(passwordStrength(password: "hunter2").level, 0)
    }

    func testTemplatesAndKinds() {
        XCTAssertEqual(itemKinds().first?.id, "login")
        XCTAssertTrue(itemTemplate(kind: "card").sections.flatMap(\.fields).contains { $0.kind == "card_number" })
        XCTAssertEqual(kindIcon("wifi"), "wifi")
        XCTAssertNotNil(totpCode(spec: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
    }

    func testKnownAccountNames() {
        let k = KnownAccount(id: "x", server: "https://vault.example.com:8443", username: "alice")
        XCTAssertEqual(k.name, "alice@vault.example.com:8443")
    }

    @MainActor
    func testLockedAppHasNothing() {
        let app = PlaintextApp(dir: NSTemporaryDirectory() + UUID().uuidString, device: "test")
        XCTAssertFalse(app.isUnlocked())
        XCTAssertTrue(app.items(account: nil, vault: nil, query: "", archived: false).isEmpty)
        XCTAssertThrowsError(try app.sync(account: "nobody"))
    }
}
