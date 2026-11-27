#if DEBUG && os(macOS)
import AppKit
import SwiftUI

/// Mac screenshots for design review (Debug builds only). Agents on the shared
/// Mac can't show windows or record the screen, so this draws each screen
/// off-screen into PNGs in the app's container (tmp/shots):
/// PT_SHOTS=1, PT_LOGIN="server<TAB>secret key<TAB>password" for the account to
/// show, PT_INVITE2 for a throwaway signup that reaches the Emergency Kit.
@MainActor
enum ShotDriver {
    static var dir: URL { FileManager.default.temporaryDirectory.appendingPathComponent("shots", isDirectory: true) }
    static let size = NSSize(width: 1180, height: 740)
    static let sheet = NSSize(width: 560, height: 640)

    static func start() {
        guard ProcessInfo.processInfo.environment["PT_SHOTS"] != nil else { return }
        Task { @MainActor in
            await run(AppModel())
            exit(0)
        }
    }

    static func run(_ model: AppModel) async {
        Self.model = model
        let env = ProcessInfo.processInfo.environment
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        UserDefaults.standard.set(false, forKey: Prefs.biometrics)
        let login = (env["PT_LOGIN"] ?? "").components(separatedBy: "\t")
        guard login.count == 3 else { return }
        let (server, sk, password) = (login[0], login[1], login[2])

        // First run, with a throwaway account for the Emergency Kit.
        let flow = Flow()
        flow.custom = server
        flow.server = server
        flow.info = try? serverInfo(server: server)
        flow.username = "carol"
        flow.password = "a long and lovely password"
        flow.invite = env["PT_INVITE2"] ?? ""
        flow.signup = try? model.core.signup(server: server, username: "carol", password: flow.password, invite: flow.invite)
        let first: [(String, [Flow.Step])] = [("welcome", []), ("server", [.server]), ("create-account", [.server, .create]), ("emergency-kit", [.server, .create, .kit]), ("biometrics", [.server, .create, .kit, .biometrics])]
        for (name, path) in first {
            flow.path = path
            await snap(name, size) { Onboarding(flow: flow) }
        }
        if let c = flow.signup { model.core.signOut(account: c.account.id) }

        // bob, signed in, with what alice shared.
        do {
            let r = try await model.call { try $0.login(server: server, secretKey: sk, password: password) }
            model.added(r.account, unlock: r.unlock, secretKey: sk)
        } catch {
            NSLog("PT_SHOTS login failed: %@", errorText(error))
            return
        }
        await model.syncAll()
        model.nav = .all
        model.selection = model.items.first { $0.hasTotp }?.key ?? model.items.first?.key
        await snap("home", size) { home }
        if let v = model.vaults.first(where: { $0.name == "Family" }) ?? model.vaults.first {
            model.nav = .vault(account: v.accountId, id: v.id)
            model.selection = model.items.first?.key
            await snap("shared-vault", size) { home }
        }
        model.nav = .all
        if let s = model.items.first(where: { $0.hasTotp }) ?? model.items.first {
            model.edit(s.ref)
            if let req = model.editor { await snap("edit-item", sheet) { ItemEditor(request: req) } }
        }
        model.newItem()
        if let req = model.editor { await snap("kind-picker", sheet) { ItemEditor(request: req) } }
        model.editor = nil
        for (nav, name) in [(Nav.watchtower, "watchtower"), (.inbox, "inbox"), (.vaults, "vaults"), (.agents, "agents")] {
            model.nav = nav
            await snap(name, size) { home }
        }
        await snap("settings", sheet) { NavigationStack { SettingsView() } }
        if let k = model.known.first {
            await snap("account", sheet) { NavigationStack { AccountSettings(known: k) } }
        }
        model.lock()
        await snap("unlock", size) { UnlockView() }
        NSLog("PT_SHOTS done: %@", dir.path)
    }

    /// The three columns. AppKit doesn't draw the sidebar column off-screen, so
    /// it's drawn beside the other two.
    private static var home: some View {
        HStack(spacing: 0) {
            NavigationStack { Sidebar() }.frame(width: 230)
            Divider()
            SplitHome(columns: .doubleColumn)
        }
    }

    /// Draw `view` with the app's model in light and dark.
    private static func snap<V: View>(_ name: String, _ size: NSSize, @ViewBuilder _ view: () -> V) async {
        for (theme, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            let appearance = NSAppearance(named: look)!
            let host = NSHostingView(rootView: view().environmentObject(model!).tint(Palette.accent).frame(width: size.width, height: size.height).background(Palette.bg))
            host.appearance = appearance
            let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: true)
            window.appearance = appearance
            window.contentView = host
            host.frame = NSRect(origin: .zero, size: size)
            try? await Task.sleep(for: .seconds(2.5))
            host.layoutSubtreeIfNeeded()
            appearance.performAsCurrentDrawingAppearance {
                guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
                host.cacheDisplay(in: host.bounds, to: rep)
                try? rep.representation(using: .png, properties: [:])?.write(to: dir.appendingPathComponent("\(name)-mac-\(theme).png"))
            }
            window.contentView = nil
        }
    }

    private static var model: AppModel?
}
#endif
