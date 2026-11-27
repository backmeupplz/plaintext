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

/// Copied secrets leave the clipboard after a while and are marked concealed.
enum Clipboard {
    static func copy(_ text: String, seconds: Int) {
        #if os(iOS)
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: text]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(TimeInterval(seconds))])
        #else
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(seconds)) {
            if pb.changeCount == count { pb.clearContents() }
        }
        #endif
        Haptics.tap()
    }
}

import UniformTypeIdentifiers
