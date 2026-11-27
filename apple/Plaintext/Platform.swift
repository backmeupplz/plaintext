import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

extension View {
    /// Usernames, codes and addresses: no capitals or autocorrect.
    func plainInput() -> some View {
        #if os(iOS)
        return self.textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        return self.autocorrectionDisabled()
        #endif
    }

    func inlineTitle() -> some View {
        #if os(iOS)
        return self.navigationBarTitleDisplayMode(.inline)
        #else
        return self
        #endif
    }

    func urlKeyboard() -> some View {
        #if os(iOS)
        return self.keyboardType(.URL)
        #else
        return self
        #endif
    }
}

enum Haptics {
    static func tap() {
        #if os(iOS)
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        #endif
    }
}

enum Device {
    static var name: String {
        #if os(iOS)
        return UIDevice.current.name
        #else
        return Host.current().localizedName ?? "Mac"
        #endif
    }

    static var isPhone: Bool {
        #if os(iOS)
        return UIDevice.current.userInterfaceIdiom == .phone
        #else
        return false
        #endif
    }

    static var voiceOver: Bool {
        #if os(iOS)
        return UIAccessibility.isVoiceOverRunning
        #else
        return NSWorkspace.shared.isVoiceOverEnabled
        #endif
    }

    /// How long an undo stays offered: longer while VoiceOver has to reach the button.
    static var undoSeconds: Double { voiceOver ? 15 : 5 }
}

/// Copied secrets leave the clipboard after a while, stay on this device (no
/// Universal Clipboard) and are marked concealed. Locking and quitting clear them.
@MainActor
enum Clipboard {
    /// The pasteboard's change count right after our last copy.
    private static var ours: Int?

    static func copy(_ text: String, seconds: Int) {
        #if os(iOS)
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: text]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(TimeInterval(seconds))])
        ours = UIPasteboard.general.changeCount
        #else
        let pb = NSPasteboard.general
        pb.prepareForNewContents(with: .currentHostOnly)
        pb.setString(text, forType: .string)
        pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        ours = count
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(seconds)) {
            if pb.changeCount == count { pb.clearContents() }
        }
        #endif
        Haptics.tap()
    }

    /// Remove what we copied, unless something else was copied since.
    static func clear() {
        #if os(iOS)
        if UIPasteboard.general.changeCount == ours { UIPasteboard.general.items = [] }
        #else
        if NSPasteboard.general.changeCount == ours { NSPasteboard.general.clearContents() }
        #endif
        ours = nil
    }
}

/// When someone last used the app: auto-lock counts from here, so an iPad on a
/// stand or a Mac left on another app still locks.
@MainActor
enum Activity {
    private(set) static var last = Date()
    /// Called when the app has gone unused for `Guard.idleLimit`.
    static var onIdle: () -> Void = {}

    /// Someone used the app. The first use after too long locks instead (a
    /// timer may not have fired while the app was away or napping).
    static func touch() {
        check()
        last = Date()
    }

    /// Unlocked: count from now.
    static func reset() { last = Date() }

    static func check() {
        if Date().timeIntervalSince(last) >= Guard.idleLimit { onIdle() }
    }

    /// Start counting touches, typing, VoiceOver moves and clicks (once).
    static func watch() {
        #if os(iOS)
        for name in [UITextField.textDidChangeNotification, UITextView.textDidChangeNotification, UIAccessibility.elementFocusedNotification] {
            NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { _ in MainActor.assumeIsolated { touch() } }
        }
        NotificationCenter.default.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { TouchWatcher.install() }
        }
        #else
        NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel]) { e in
            MainActor.assumeIsolated { touch() }
            return e
        }
        #endif
    }
}

#if os(iOS)
import UIKit.UIGestureRecognizerSubclass

/// Sees every touch in a window (sheets included) without taking any.
private final class TouchWatcher: UIGestureRecognizer, UIGestureRecognizerDelegate {
    static func install() {
        for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
            for w in scene.windows where !(w.gestureRecognizers ?? []).contains(where: { $0 is TouchWatcher }) {
                let g = TouchWatcher()
                g.cancelsTouchesInView = false
                g.delaysTouchesBegan = false
                g.delaysTouchesEnded = false
                g.delegate = g
                w.addGestureRecognizer(g)
            }
        }
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        Activity.touch()
        state = .failed
    }

    func gestureRecognizer(_ g: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool { true }
}

/// Covers everything, sheets and alerts included, in the app switcher and while
/// the screen is recorded or mirrored: its own window above them all.
@MainActor
enum PrivacyCover {
    private static var windows: [UIWindow] = []

    /// Recording or mirroring the screen, with "hide while sharing" on.
    static var capturedHidden: Bool { UIScreen.main.isCaptured && UserDefaults.standard.bool(forKey: Prefs.hideOnShare) }

    /// Each window scene is covered on its own (iPad has several).
    static func set(_ scene: UIWindowScene?, _ on: Bool) {
        guard let scene else { return }
        windows.removeAll { $0.windowScene == nil }
        if let w = windows.first(where: { $0.windowScene === scene }) {
            w.isHidden = !on
        } else if on {
            let w = UIWindow(windowScene: scene)
            w.windowLevel = .alert + 1
            w.rootViewController = UIHostingController(rootView: CoverView())
            w.isHidden = false
            windows.append(w)
        }
    }

    static func refresh() {
        for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
            set(scene, scene.activationState != .foregroundActive || capturedHidden)
        }
    }
}

struct CoverView: View {
    var body: some View {
        ZStack {
            Palette.bg
            Wordmark()
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    /// Third-party keyboards could read the Secret Key, revealed passwords and codes.
    func application(_ application: UIApplication, shouldAllowExtensionPointIdentifier id: UIApplication.ExtensionPointIdentifier) -> Bool {
        id != .keyboard
    }
}
#else
/// Keeps its window out of screenshots and screen sharing, whatever the setting.
struct NoCapture: NSViewRepresentable {
    /// Windows that stay hidden even with "hide while sharing" off.
    @MainActor private static let always = NSHashTable<NSWindow>.weakObjects()

    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        DispatchQueue.main.async { v.window.map(NoCapture.hide) }
        return v
    }

    func updateNSView(_ v: NSView, context: Context) { v.window.map(NoCapture.hide) }

    @MainActor private static func hide(_ w: NSWindow) {
        always.add(w)
        w.sharingType = .none
    }

    /// Every window as the setting says.
    @MainActor static func apply() {
        let hide = UserDefaults.standard.bool(forKey: Prefs.hideOnShare)
        for w in NSApp.windows { w.sharingType = hide || always.contains(w) ? .none : .readOnly }
    }
}
#endif

import UniformTypeIdentifiers
