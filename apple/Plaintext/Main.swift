import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

@main
struct PlaintextMain: App {
    @StateObject private var model = AppModel()
    #if os(iOS)
    @UIApplicationDelegateAdaptor private var delegate: AppDelegate
    #endif

    init() {
        #if DEBUG && os(macOS)
        ShotDriver.start()
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .tint(Palette.accent)
                #if os(macOS)
                .frame(minWidth: 820, minHeight: 520)
                #endif
        }
        .commands { AppCommands(model: model) }
        #if os(macOS)
        Settings {
            NavigationStack { SettingsView() }
                .environmentObject(model)
                .tint(Palette.accent)
                .frame(width: 560, height: 640)
        }
        #endif
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var phase

    var body: some View {
        ZStack {
            Palette.bg.ignoresSafeArea()
            if model.known.isEmpty || model.onboarding {
                Onboarding()
            } else if model.locked {
                UnlockView()
            } else {
                HomeView()
            }
        }
        .overlay(alignment: .bottom) { ToastView() }
        .overlay(alignment: .top) { BannerView() }
        .onReceive(Timer.publish(every: 60, on: .main, in: .common).autoconnect()) { _ in
            if phase == .active { Task { await model.syncAll() } }
        }
    }
}

/// Locking, the privacy cover and clearing the clipboard, for the app's whole
/// life: a Mac app keeps running with its window closed.
@MainActor
enum Guard {
    private static var started = false
    private static var autoLock: Int { UserDefaults.standard.integer(forKey: Prefs.autoLockMinutes) }
    /// No touch, typing or click for this long locks. "Immediately" locks on
    /// leaving the app, and after a minute without use while in it.
    static var idleLimit: TimeInterval { Double(max(autoLock, 1) * 60) }

    static func start(_ model: AppModel) {
        guard !started else { return }
        started = true
        func on(_ name: Notification.Name, _ f: @escaping @MainActor (Notification) -> Void) {
            NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { n in MainActor.assumeIsolated { f(n) } }
        }
        Activity.onIdle = { [weak model] in
            guard let model, !model.locked else { return false }
            model.lock()
            return true
        }
        Activity.watch()
        RunLoop.main.add(Timer(timeInterval: 15, repeats: true) { _ in MainActor.assumeIsolated { _ = Activity.check() } }, forMode: .common)
        #if os(iOS)
        on(UIApplication.didEnterBackgroundNotification) { _ in if autoLock == 0 { model.lock() } }
        // Time away counts as time without use.
        on(UIApplication.willEnterForegroundNotification) { _ in Activity.check() }
        on(UIApplication.protectedDataWillBecomeUnavailableNotification) { _ in model.lock() }
        // The app switcher snapshot shows nothing, onboarding (the Secret Key) included.
        on(UIScene.willDeactivateNotification) { n in PrivacyCover.set(n.object as? UIWindowScene, true) }
        on(UIScene.didActivateNotification) { n in
            PrivacyCover.set(n.object as? UIWindowScene, PrivacyCover.capturedHidden)
            TouchWatcher.install() // a new iPad window too
        }
        on(UIScreen.capturedDidChangeNotification) { _ in PrivacyCover.refresh() }
        on(UserDefaults.didChangeNotification) { _ in PrivacyCover.refresh() }
        #else
        DistributedNotificationCenter.default().addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { model.lock() }
        }
        on(NSApplication.didResignActiveNotification) { _ in if autoLock == 0 { model.lock() } }
        on(NSApplication.didBecomeActiveNotification) { _ in Activity.check() }
        on(NSApplication.willTerminateNotification) { _ in Clipboard.clear() }
        // Sheets and Settings are windows of their own: hide each one as it appears.
        on(NSWindow.didBecomeKeyNotification) { _ in NoCapture.apply() }
        on(UserDefaults.didChangeNotification) { _ in NoCapture.apply() }
        #endif
    }
}

struct ToastView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if let t = model.toast {
            HStack(spacing: 10) {
                Image(systemName: t.icon).foregroundStyle(Palette.accent).symbolEffect(.bounce, value: t.id)
                Text(t.text).font(.subheadline.weight(.medium)).lineLimit(2)
                if let undo = t.undo {
                    Button("Undo") {
                        undo()
                        model.toast = nil
                    }
                    .font(.subheadline.weight(.semibold))
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(.regularMaterial, in: Capsule())
            .overlay(Capsule().stroke(Palette.line))
            .padding(.bottom, 24)
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .task(id: t.id) {
                AccessibilityNotification.Announcement(t.undo == nil ? t.text : "\(t.text). Undo is available.").post()
                try? await Task.sleep(for: .seconds(t.undo == nil ? 2 : Device.undoSeconds))
                withAnimation(.easeIn(duration: 0.2)) { if model.toast?.id == t.id { model.toast = nil } }
            }
            .accessibilityAddTraits(.updatesFrequently)
        }
    }
}

struct BannerView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if let text = model.banner {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "exclamationmark.circle.fill").foregroundStyle(Palette.warn)
                Text(text).font(.subheadline).foregroundStyle(Palette.fg).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button { model.banner = nil } label: { Image(systemName: "xmark").foregroundStyle(Palette.muted) }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Dismiss")
            }
            .padding(14)
            .background(Palette.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Palette.line))
            .padding(.horizontal, 16)
            .padding(.top, 8)
            .frame(maxWidth: 560)
            .transition(.move(edge: .top).combined(with: .opacity))
            .task(id: text) {
                AccessibilityNotification.Announcement(text).post()
                try? await Task.sleep(for: .seconds(Device.voiceOver ? 20 : 8))
                withAnimation { if model.banner == text { model.banner = nil } }
            }
        }
    }
}

struct AppCommands: Commands {
    @ObservedObject var model: AppModel

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("New Item") { model.newItem() }
                .keyboardShortcut("n")
                .disabled(model.locked)
        }
        #if os(macOS)
        // ⌘C copies the selected item's password unless text is being edited.
        CommandGroup(replacing: .pasteboard) {
            Button("Cut") { NSApp.sendAction(#selector(NSText.cut(_:)), to: nil, from: nil) }.keyboardShortcut("x")
            Button("Copy") {
                if NSApp.keyWindow?.firstResponder is NSText || model.editor != nil {
                    NSApp.sendAction(#selector(NSText.copy(_:)), to: nil, from: nil)
                } else if let s = model.summary(model.selection) {
                    model.copyField(s.ref, "password")
                } else {
                    NSApp.sendAction(#selector(NSText.copy(_:)), to: nil, from: nil)
                }
            }
            .keyboardShortcut("c")
            Button("Paste") { NSApp.sendAction(#selector(NSText.paste(_:)), to: nil, from: nil) }.keyboardShortcut("v")
            Button("Select All") { NSApp.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil) }.keyboardShortcut("a")
        }
        #endif
        CommandMenu("Item") {
            Button("Find") { model.focusSearch = true }
                .keyboardShortcut("f")
                .disabled(model.locked)
            Divider()
            #if os(iOS)
            Button("Copy Password") { model.summary(model.selection).map { model.copyField($0.ref, "password") } }
                .keyboardShortcut("c")
                .disabled(model.selection == nil || model.editor != nil || model.searching)
            #endif
            Button("Copy Username") { model.summary(model.selection).map { model.copyField($0.ref, "username") } }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(model.selection == nil)
            Button("Copy One-Time Code") { model.summary(model.selection).map { model.copyField($0.ref, "totp") } }
                .keyboardShortcut("c", modifiers: [.command, .option])
                .disabled(model.summary(model.selection)?.hasTotp != true)
            Divider()
            Button("Edit") { model.summary(model.selection).map { model.edit($0.ref) } }
                .keyboardShortcut("e")
                .disabled(model.summary(model.selection).map { !model.canEdit($0.ref) } ?? true)
            Divider()
            Button("Lock") { model.lock() }
                .keyboardShortcut("l", modifiers: [.command, .control])
                .disabled(model.locked)
        }
    }
}
