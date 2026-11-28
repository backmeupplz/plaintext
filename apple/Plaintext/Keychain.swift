import Foundation
import LocalAuthentication
import Security

/// An account this device knows, signed in or not. Its keychain entries are
/// keyed `<username>@<host> secret-key` and `<username>@<host> session`.
struct KnownAccount: Codable, Hashable, Identifiable {
    var id: String
    var server: String
    var username: String

    /// `vault.example.com:8443` for `https://vault.example.com:8443`.
    var host: String { server.components(separatedBy: "://").last ?? server }
    var name: String { "\(username)@\(host)" }
}

/// What unlocks an account without its password: the session token and the
/// Account Key. It sits in the keychain behind Face ID / Touch ID or the device
/// passcode. The password itself is never stored.
struct StoredSession: Codable {
    var token: String
    var accountId: Data
    var accountKey: Data

    init(_ u: UnlockData) { (token, accountId, accountKey) = (u.token, u.accountId, u.accountKey) }
    var unlock: UnlockData { UnlockData(token: token, accountId: accountId, accountKey: accountKey) }
}

enum Keychain {
    private static let service = "com.borodutch.plaintext"

    static func saveSecretKey(_ sk: String, for a: KnownAccount) {
        set(Data(sk.utf8), key: "\(a.name) secret-key", protected: false)
    }

    static func secretKey(for a: KnownAccount) -> String? {
        get("\(a.name) secret-key", context: nil).flatMap { String(data: $0, encoding: .utf8) }
    }

    /// `protected`: only after Face ID / Touch ID or the device passcode.
    @discardableResult
    static func saveSession(_ u: UnlockData, for a: KnownAccount, protected: Bool) -> Bool {
        guard let data = try? JSONEncoder().encode(StoredSession(u)) else { return false }
        return set(data, key: "\(a.name) session", protected: protected)
    }

    /// Reading with a context the user already authenticated asks nothing more,
    /// so one prompt opens every account.
    static func session(for a: KnownAccount, context: LAContext?) -> UnlockData? {
        get("\(a.name) session", context: context).flatMap { try? JSONDecoder().decode(StoredSession.self, from: $0) }?.unlock
    }

    static func hasSession(for a: KnownAccount) -> Bool {
        var q = base("\(a.name) session")
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = ctx
        let s = SecItemCopyMatching(q as CFDictionary, nil)
        return s == errSecSuccess || s == errSecInteractionNotAllowed || (legacy && SecItemCopyMatching(base("\(a.name) session", legacy: true) as CFDictionary, nil) == errSecSuccess)
    }

    static func forget(_ a: KnownAccount, sessionOnly: Bool = false) {
        for what in sessionOnly ? ["session"] : ["session", "secret-key"] {
            SecItemDelete(base("\(a.name) \(what)") as CFDictionary)
            SecItemDelete(base("\(a.name) \(what)", legacy: true) as CFDictionary)
        }
    }

    // A Debug Mac build without a signing team can't use the data-protection
    // keychain (errSecMissingEntitlement). It falls back to the login keychain,
    // and the app still asks for Touch ID or the Mac password before reading.
    // Release builds are always signed, so they never do.
    private static var legacy: Bool {
        get {
            #if DEBUG
            return UserDefaults.standard.bool(forKey: "keychain.legacy")
            #else
            return false
            #endif
        }
        set { UserDefaults.standard.set(newValue, forKey: "keychain.legacy") }
    }

    private static func base(_ key: String, legacy: Bool = false) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key]
        #if os(macOS)
        if !legacy { q[kSecUseDataProtectionKeychain as String] = true }
        #endif
        return q
    }

    @discardableResult
    private static func set(_ data: Data, key: String, protected: Bool) -> Bool {
        SecItemDelete(base(key) as CFDictionary)
        SecItemDelete(base(key, legacy: true) as CFDictionary)
        var q = base(key)
        q[kSecValueData as String] = data
        if protected {
            // Fail closed: never store a session without the presence check.
            guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, nil) else { return false }
            q[kSecAttrAccessControl as String] = ac
        } else {
            q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        var status = SecItemAdd(q as CFDictionary, nil)
        #if os(macOS) && DEBUG
        if status == errSecMissingEntitlement {
            legacy = true
            var l = base(key, legacy: true)
            l[kSecValueData as String] = data
            status = SecItemAdd(l as CFDictionary, nil)
        }
        #endif
        return status == errSecSuccess
    }

    private static func get(_ key: String, context: LAContext?) -> Data? {
        for useLegacy in legacy ? [false, true] : [false] {
            var q = base(key, legacy: useLegacy)
            q[kSecReturnData as String] = true
            if let context { q[kSecUseAuthenticationContext as String] = context }
            var out: AnyObject?
            if SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data { return d }
        }
        return nil
    }
}

enum Biometrics {
    /// "Face ID", "Touch ID", "Optic ID", or nil when there's none.
    static var name: String? {
        let c = LAContext()
        guard c.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return nil }
        switch c.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return nil
        }
    }

    /// Biometrics, or the device passcode / Mac password.
    static var available: Bool { LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) }

    static var icon: String {
        switch name {
        case "Face ID": return "faceid"
        case "Optic ID": return "opticid"
        default: return "touchid"
        }
    }
}
