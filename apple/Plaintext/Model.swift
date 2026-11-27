import Foundation
import LocalAuthentication
import SwiftUI

extension PlaintextError {
    /// The sentence to show (written in Rust, so every app says the same).
    var message: String {
        switch self {
        case .Network(let m), .SignedOut(let m), .WrongPassword(let m), .BadSecretKey(let m), .BadInvite(let m), .BadUsername(let m),
             .KeyChanged(let m), .Rollback(let m), .ManifestMismatch(let m), .ReadOnly(let m), .Server(let m), .NotFound(let m),
             .Invalid(let m), .Locked(let m):
            return m
        }
    }
}

func errorText(_ e: Error) -> String {
    (e as? PlaintextError)?.message ?? e.localizedDescription
}

/// Points at one item of one account.
struct ItemRef: Hashable, Identifiable {
    var account: String
    var vault: String
    var item: String
    var id: String { "\(account)/\(vault)/\(item)" }
}

extension ItemSummary {
    var ref: ItemRef { ItemRef(account: accountId, vault: vaultId, item: id) }
    var key: String { ref.id }
}

extension VaultInfo {
    var key: String { "\(accountId)/\(id)" }
}

/// Sidebar sections (Mac and iPad) and the phone's vault picker.
enum Nav: Hashable {
    case all, favorites, archive, watchtower, inbox, agents, vaults
    case vault(account: String, id: String)
    case tag(String)
}

/// An item open in the editor.
struct EditorRequest: Identifiable {
    let id = UUID()
    var account: String
    var vault: String
    /// nil for a new item.
    var item: String?
    var data: ItemData
}

enum Prefs {
    static let autoLockMinutes = "autoLockMinutes"
    static let clipboardSeconds = "clipboardSeconds"
    static let linkPage = "linkPage"
    static let biometrics = "biometrics"
    static let hideOnShare = "hideOnScreenShare"
    static let recentServers = "recentServers"
    static let breachCheck = "breachCheck"
    static let sortRecent = "sortRecent"

    static func register() {
        UserDefaults.standard.register(defaults: [autoLockMinutes: 10, clipboardSeconds: 90, linkPage: defaultLinkPage(), biometrics: true, hideOnShare: true])
    }

    static var clipboard: Int { UserDefaults.standard.integer(forKey: clipboardSeconds) }
}

@MainActor
final class AppModel: ObservableObject {
    let core: PlaintextApp

    /// Accounts on this device (signed in, locked or needing their password).
    @Published var known: [KnownAccount] { didSet { saveKnown() } }
    @Published var accounts: [AccountInfo] = []
    @Published var locked = true
    @Published var unlocking = false
    /// The first account's onboarding is still on screen (Emergency Kit, biometrics)
    /// although `known` already holds the account.
    @Published var onboarding = false

    @Published var vaults: [VaultInfo] = []
    @Published var items: [ItemSummary] = []
    @Published var tags: [String] = []
    @Published var watch: [WatchItem] = []
    @Published var inbox: [String: [InboxEntry]] = [:]
    /// Passwords found in breaches (by item key), once the check ran.
    @Published var breached: [String: UInt64] = [:]

    @Published var nav: Nav? = .all { didSet { reload() } }
    @Published var query = "" { didSet { reload() } }
    @Published var selection: String?
    @Published var focusSearch = false
    /// The search field has focus, so ⌘C copies its text, not a password.
    @Published var searching = false

    @Published var editor: EditorRequest?
    @Published var toast: Toast?
    @Published var banner: String?
    @Published var syncing = false
    /// An invite or device link opened from outside, for the first-run flow.
    @Published var incoming: IncomingLink?
    /// Hidden from lists while its undo toast is up.
    private var deleting: Set<String> = []

    struct Toast: Identifiable, Equatable {
        let id = UUID()
        var text: String
        var icon = "checkmark.circle.fill"
        var undo: (() -> Void)?
        static func == (a: Toast, b: Toast) -> Bool { a.id == b.id }
    }

    enum IncomingLink: Equatable {
        case invite(server: String?, code: String)
        case device(DeviceCode)
    }

    init() {
        Prefs.register()
        let dir = AppModel.dataDirectory()
        core = PlaintextApp(dir: dir.path, device: Device.name)
        known = (UserDefaults.standard.data(forKey: "accounts")).flatMap { try? JSONDecoder().decode([KnownAccount].self, from: $0) } ?? []
    }

    /// The shared app-group container when it's available (the AutoFill and
    /// Safari extensions read it), else this app's own Application Support.
    static func dataDirectory() -> URL {
        let fm = FileManager.default
        // A build without the app-group entitlement gets a group path it can't write to.
        for base in [fm.containerURL(forSecurityApplicationGroupIdentifier: "group.com.borodutch.plaintext"), fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first] {
            guard let dir = base?.appendingPathComponent("Plaintext", isDirectory: true) else { continue }
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
            if fm.isWritableFile(atPath: dir.path) { return dir }
        }
        return fm.temporaryDirectory
    }

    private func saveKnown() {
        UserDefaults.standard.set(try? JSONEncoder().encode(known), forKey: "accounts")
    }

    /// Run a blocking Rust call off the main thread.
    nonisolated func call<T>(_ work: @escaping (PlaintextApp) throws -> T) async throws -> T {
        let core = self.core
        return try await Task.detached(priority: .userInitiated) { try work(core) }.value
    }

    func show(_ e: Error) {
        if case PlaintextError.SignedOut = e { reload() }
        banner = errorText(e)
    }

    func flash(_ text: String, icon: String = "checkmark.circle.fill", undo: (() -> Void)? = nil) {
        withAnimation(.easeOut(duration: 0.2)) { toast = Toast(text: text, icon: icon, undo: undo) }
    }

    func copy(_ text: String, what: String) {
        Clipboard.copy(text, seconds: Prefs.clipboard)
        flash("\(what) copied")
    }

    // MARK: Accounts

    func known(_ id: String) -> KnownAccount? { known.first { $0.id == id } }

    func account(_ id: String) -> AccountInfo? { accounts.first { $0.id == id } }
    var lockedAccounts: [KnownAccount] { known.filter { k in !accounts.contains { $0.id == k.id } } }

    /// Right after signup or sign-in: keep the account and its Secret Key, before
    /// the Emergency Kit is even on screen (the app may be killed there).
    func remember(_ info: AccountInfo, secretKey: String) {
        let k = KnownAccount(id: info.id, server: info.server, username: info.username)
        if known.isEmpty { onboarding = true }
        // Same name, same keychain items: an old account of a reset server is gone.
        known.removeAll { $0.id == k.id || $0.name == k.name }
        known.append(k)
        Keychain.saveSecretKey(secretKey, for: k)
    }

    /// Onboarding is done: store what unlocks the account and open it.
    func added(_ info: AccountInfo, unlock: UnlockData, secretKey: String) {
        remember(info, secretKey: secretKey)
        onboarding = false
        guard let k = known(info.id) else { return }
        saveSession(unlock, for: k)
        locked = false
        Task {
            // The app locked meanwhile (say, while writing the kit down): open it again.
            if account(info.id) == nil, !core.accounts().contains(where: { $0.id == info.id }) {
                do { _ = try await call { try $0.resume(server: k.server, unlock: unlock) } } catch { show(error) }
            }
            reload()
            await syncAll()
        }
    }

    func saveSession(_ u: UnlockData, for k: KnownAccount) {
        if sessionsStored { Keychain.saveSession(u, for: k, protected: true) } else { Keychain.forget(k, sessionOnly: true) }
    }

    /// Re-store every unlocked account's session after the biometrics setting changes.
    func biometricsChanged() {
        Task {
            for k in known where account(k.id) != nil {
                guard let u = try? await call({ try $0.unlockData(account: k.id) }) else { continue }
                saveSession(u, for: k)
            }
        }
    }

    /// Nothing in the keychain can resume a session: biometrics are off or unavailable.
    private var sessionsStored: Bool { UserDefaults.standard.bool(forKey: Prefs.biometrics) && Biometrics.available }

    private func authenticate(reason: String) async -> LAContext? {
        let ctx = LAContext()
        ctx.localizedFallbackTitle = "Use Passcode"
        do {
            try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            return ctx
        } catch {
            return nil
        }
    }

    /// One Face ID / Touch ID prompt opens every account that has a stored session.
    func unlockWithBiometrics() async {
        guard locked, !unlocking, known.contains(where: Keychain.hasSession) else { return }
        unlocking = true
        defer { unlocking = false }
        guard let ctx = await authenticate(reason: "Unlock your vaults") else { return }
        await resumeAll(context: ctx)
    }

    private func resumeAll(context: LAContext) async {
        var errors: [String] = []
        for k in known {
            guard account(k.id) == nil, let u = Keychain.session(for: k, context: context) else { continue }
            do {
                _ = try await call { try $0.resume(server: k.server, unlock: u) }
            } catch PlaintextError.SignedOut {
                Keychain.forget(k, sessionOnly: true)
                errors.append("\(k.name) was signed out. Enter its password to sign in again.")
            } catch {
                errors.append(errorText(error))
            }
        }
        reload()
        if !accounts.isEmpty { locked = false }
        banner = errors.first
        if !locked { Task { await syncAll() } }
    }

    /// Unlock one account with its password (online: the password opens the
    /// account through the server, with the Secret Key kept on this device).
    func unlock(_ k: KnownAccount, password: String) async throws {
        guard let sk = Keychain.secretKey(for: k) else {
            throw PlaintextError.BadSecretKey(message: "This device lost its copy of the Secret Key. Sign in again with your Emergency Kit.")
        }
        let r = try await call { try $0.login(server: k.server, secretKey: sk, password: password) }
        saveSession(r.unlock, for: k)
        reload()
        locked = false
        Task { await syncAll() }
    }

    func lock() {
        // Without a stored session the next unlock signs in again, so end these.
        // Not mid-onboarding, though: that session is about to be stored.
        core.lock(endSessions: !sessionsStored && !onboarding)
        accounts = []
        items = []
        vaults = []
        watch = []
        inbox = [:]
        selection = nil
        editor = nil
        locked = true
    }

    func signOut(_ id: String) {
        guard let k = known(id) else { return }
        Keychain.forget(k)
        known.removeAll { $0.id == id }
        inbox[id] = nil
        Task {
            _ = try? await call { $0.signOut(account: id) }
            reload()
            if known.isEmpty { lock() }
        }
    }

    // MARK: Data

    /// Re-read lists from Rust's in-memory copies (cheap; no network).
    func reload() {
        accounts = core.accounts()
        vaults = core.vaults()
        tags = core.tags()
        watch = core.watchtower()
        var list: [ItemSummary]
        switch nav ?? .all {
        case .vault(let a, let v): list = core.items(account: a, vault: v, query: query, archived: false)
        case .archive: list = core.items(account: nil, vault: nil, query: query, archived: true)
        case .favorites: list = core.items(account: nil, vault: nil, query: query, archived: false).filter(\.favorite)
        case .tag(let t): list = core.items(account: nil, vault: nil, query: query, archived: false).filter { $0.tags.contains(t) }
        default: list = core.items(account: nil, vault: nil, query: query, archived: false)
        }
        if UserDefaults.standard.bool(forKey: Prefs.sortRecent) { list.sort { $0.updated > $1.updated } }
        items = list.filter { !deleting.contains($0.key) }
    }

    func syncAll() async {
        guard !locked, !syncing else { return }
        syncing = true
        defer { syncing = false }
        let ids = accounts.map(\.id)
        var firstError: Error?
        await withTaskGroup(of: (String, Error?, [InboxEntry]?).self) { g in
            for id in ids {
                g.addTask { [core] in
                    await Task.detached {
                        do {
                            try core.sync(account: id)
                            return (id, nil, try? core.inbox(account: id))
                        } catch {
                            return (id, error, nil)
                        }
                    }.value
                }
            }
            for await (id, err, box) in g {
                if let box { inbox[id] = box }
                if let err, !(err is CancellationError) {
                    if case PlaintextError.Network = err { continue }
                    if case PlaintextError.Locked = err { continue }
                    if case PlaintextError.SignedOut = err, let k = known(id) {
                        // Keep this device's copies: they hold the rollback guard and pins.
                        Keychain.forget(k, sessionOnly: true)
                        core.forget(account: id)
                    }
                    firstError = firstError ?? err
                }
            }
        }
        reload()
        // The server signed this device out of its only open account.
        if accounts.isEmpty, !locked { lock() }
        if let firstError {
            show(firstError)
        } else if let p = accounts.lazy.flatMap(\.problems).first {
            // The client's text can end with a CLI hint; the app has its own Verify screen.
            banner = capitalized(p.components(separatedBy: " (plaintext ").first ?? p)
        }
    }

    private func capitalized(_ s: String) -> String { s.prefix(1).uppercased() + s.dropFirst() }

    var navTitle: String {
        switch nav ?? .all {
        case .all: return "All items"
        case .favorites: return "Favorites"
        case .archive: return "Archive"
        case .vault(let a, let v): return vault(account: a, id: v)?.name ?? "Vault"
        case .tag(let t): return "#\(t)"
        default: return "Items"
        }
    }

    var inboxCount: Int { inbox.values.reduce(0) { $0 + $1.filter { !$0.id.isEmpty }.count } }

    func vault(_ ref: ItemRef) -> VaultInfo? { vaults.first { $0.accountId == ref.account && $0.id == ref.vault } }
    func canEdit(_ ref: ItemRef) -> Bool { vault(ref)?.role.map { $0 != .reader } ?? false }
    func vault(account: String, id: String) -> VaultInfo? { vaults.first { $0.accountId == account && $0.id == id } }

    /// Where a new item goes: the selected vault if it's writable, else the
    /// default vault of the selected (or first) account.
    func newItemTarget() -> (String, String)? {
        if case .vault(let a, let v)? = nav, let vi = vault(account: a, id: v), let r = vi.role, r != .reader { return (a, v) }
        let acct: String? = { if case .vault(let a, _)? = nav { return a }; return accounts.first?.id }()
        guard let acct, let d = vaults.first(where: { $0.accountId == acct && $0.isDefault }) else { return nil }
        return (acct, d.id)
    }

    func newItem(kind: String = "login") {
        guard let (a, v) = newItemTarget() else {
            banner = "There's no vault you can add items to yet."
            return
        }
        var data = itemTemplate(kind: kind)
        if kind == "login" || kind == "password" {
            data.password = generatePassword(recipe: .random(length: 20, digits: true, symbols: true))
        }
        editor = EditorRequest(account: a, vault: v, item: nil, data: data)
    }

    func edit(_ ref: ItemRef) {
        guard let data = try? core.item(account: ref.account, vault: ref.vault, id: ref.item) else { return }
        editor = EditorRequest(account: ref.account, vault: ref.vault, item: ref.item, data: data)
    }

    func summary(_ key: String?) -> ItemSummary? {
        guard let key else { return nil }
        return items.first { $0.key == key } ?? core.items(account: nil, vault: nil, query: "", archived: false).first { $0.key == key }
            ?? core.items(account: nil, vault: nil, query: "", archived: true).first { $0.key == key }
    }

    func setFlags(_ ref: ItemRef, favorite: Bool, archived: Bool) {
        Task {
            do {
                try await call { try $0.setFlags(account: ref.account, vault: ref.vault, id: ref.item, favorite: favorite, archived: archived) }
                reload()
            } catch { show(error) }
        }
    }

    /// Deleting waits a few seconds behind an undo toast instead of asking first.
    func delete(_ ref: ItemRef, title: String) {
        deleting.insert(ref.id)
        if selection == ref.id { selection = nil }
        reload()
        var undone = false
        flash("Deleted \(title)", icon: "trash", undo: { [weak self] in
            undone = true
            self?.deleting.remove(ref.id)
            self?.reload()
        })
        Task {
            try? await Task.sleep(for: .seconds(Device.undoSeconds))
            guard !undone else { return }
            do { try await call { try $0.deleteItem(account: ref.account, vault: ref.vault, id: ref.item) } } catch { show(error) }
            deleting.remove(ref.id)
            reload()
        }
    }

    /// Copy one field of an item from a list row or a shortcut.
    func copyField(_ ref: ItemRef, _ which: String) {
        guard let d = try? core.item(account: ref.account, vault: ref.vault, id: ref.item) else { return }
        switch which {
        case "username": if !d.username.isEmpty { copy(d.username, what: "Username") }
        case "totp": if let c = totpCode(spec: d.totp) { copy(c.code, what: "One-time code") }
        default: if !d.password.isEmpty { copy(d.password, what: "Password") }
        }
    }

    func open(_ url: URL) {
        let s = url.absoluteString
        if let d = parseDeviceCode(code: s) { incoming = .device(d); return }
        if s.hasPrefix("plaintext:invite:"), let l = parseInviteLink(link: s) { incoming = .invite(server: l.server, code: l.code) }
    }

    /// The breach check: only five characters of each password's SHA-1 leave the device.
    func runBreachCheck() async {
        var found: [String: UInt64] = [:]
        var seen: [String: UInt64] = [:]
        for s in core.items(account: nil, vault: nil, query: "", archived: false) where s.hasPassword {
            guard let d = try? core.item(account: s.accountId, vault: s.vaultId, id: s.id) else { continue }
            let pw = d.password
            let n: UInt64
            if let cached = seen[pw] { n = cached } else {
                guard let c = try? await call({ _ in try breachCount(password: pw) }) else { continue }
                seen[pw] = c
                n = c
            }
            if n > 0 { found[s.key] = n }
        }
        breached = found
    }
}
