import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

extension Color {
    /// A color with a light and a dark variant (UI.md tokens).
    init(light: UInt32, dark: UInt32) {
        func rgb(_ v: UInt32) -> (CGFloat, CGFloat, CGFloat) {
            (CGFloat((v >> 16) & 0xff) / 255, CGFloat((v >> 8) & 0xff) / 255, CGFloat(v & 0xff) / 255)
        }
        let (l, d) = (rgb(light), rgb(dark))
        #if os(iOS)
        self.init(uiColor: UIColor { t in
            let c = t.userInterfaceStyle == .dark ? d : l
            return UIColor(red: c.0, green: c.1, blue: c.2, alpha: 1)
        })
        #else
        self.init(nsColor: NSColor(name: nil) { a in
            let c = a.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? d : l
            return NSColor(srgbRed: c.0, green: c.1, blue: c.2, alpha: 1)
        })
        #endif
    }
}

enum Palette {
    static let bg = Color(light: 0xfbfbf8, dark: 0x111110)
    static let surface = Color(light: 0xf3f2ec, dark: 0x191917)
    static let code = Color(light: 0xefeee7, dark: 0x1d1d1b)
    static let line = Color(light: 0xe4e3dc, dark: 0x282825)
    static let fg = Color(light: 0x1b1b19, dark: 0xecebe5)
    static let muted = Color(light: 0x66665f, dark: 0x9a9991)
    static let accent = Color(light: 0x1f7a4d, dark: 0x4cc38a)
    static let accentFg = Color(light: 0xffffff, dark: 0x0d1f16)
    static let warn = Color(light: 0xb4561c, dark: 0xf0a060)
    static let danger = Color(light: 0xb42318, dark: 0xf97066)
}

/// `plain` + `text`, monospace and bold.
struct Wordmark: View {
    var size: CGFloat = 34
    var body: some View {
        (Text("plain").foregroundColor(Palette.fg) + Text("text").foregroundColor(Palette.accent))
            .font(.system(size: size, weight: .bold, design: .monospaced))
            .accessibilityLabel("Plaintext")
    }
}

/// The first letter of the title on a tint derived from the title. Never a
/// favicon: fetching those would tell a server which sites you use.
struct Monogram: View {
    let title: String
    var size: CGFloat = 40
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let hue = Double(title.lowercased().unicodeScalars.reduce(UInt32(7)) { ($0 &* 31) &+ $1.value } % 360) / 360
        RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
            .fill(Color(hue: hue, saturation: 0.32, brightness: 0.78).opacity(scheme == .dark ? 0.22 : 0.35))
            .overlay(
                Text(title.first.map { String($0).uppercased() } ?? "•")
                    .font(.system(size: size * 0.45, weight: .semibold, design: .rounded))
                    .foregroundStyle(Color(hue: hue, saturation: scheme == .dark ? 0.35 : 0.55, brightness: scheme == .dark ? 0.9 : 0.42))
            )
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

/// SF Symbols for item kinds, shared by the kind picker, rows and detail.
func kindIcon(_ kind: String) -> String {
    switch kind {
    case "login": return "person.badge.key"
    case "password": return "key"
    case "note": return "note.text"
    case "card": return "creditcard"
    case "identity": return "person.text.rectangle"
    case "document": return "doc"
    case "ssh_key": return "terminal"
    case "api_credential": return "chevron.left.forwardslash.chevron.right"
    case "bank": return "building.columns"
    case "database": return "cylinder.split.1x2"
    case "server": return "server.rack"
    case "wifi": return "wifi"
    case "passport": return "globe"
    case "driver_license": return "car"
    case "membership": return "wallet.pass"
    case "crypto_wallet": return "bitcoinsign.circle"
    case "software_license": return "checkmark.seal"
    default: return "square.dashed"
    }
}

func kindName(_ kind: String) -> String {
    itemKinds().first { $0.id == kind }?.name ?? kind.replacingOccurrences(of: "_", with: " ").capitalized
}

struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .frame(maxWidth: .infinity, minHeight: 50)
            .foregroundStyle(Palette.accentFg)
            .background(Palette.accent.opacity(enabled ? (configuration.isPressed ? 0.8 : 1) : 0.4), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .frame(maxWidth: .infinity, minHeight: 50)
            .foregroundStyle(Palette.accent)
            .background(Palette.surface.opacity(configuration.isPressed ? 0.6 : 1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Palette.line))
    }
}

/// Secrets, codes and fingerprints: monospace on the `code` background.
struct CodeBlock: View {
    let text: String
    var size: Font = .title3
    var body: some View {
        Text(text)
            .font(size.monospaced())
            .foregroundStyle(Palette.fg)
            .textSelection(.enabled)
            .multilineTextAlignment(.center)
            .padding(14)
            .frame(maxWidth: .infinity)
            .background(Palette.code, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

/// A one-line warning (`warn` color) or note under a field.
struct Note: View {
    let text: String
    var icon = "exclamationmark.triangle"
    var color = Palette.warn
    var body: some View {
        Label(text, systemImage: icon).font(.footnote).foregroundStyle(color)
    }
}

/// Strength as four bars plus a word.
struct StrengthMeter: View {
    let password: String
    var body: some View {
        let s = passwordStrength(password: password)
        let words = ["Weak", "Fair", "Good", "Strong"]
        let colors = [Palette.danger, Palette.warn, Palette.accent, Palette.accent]
        HStack(spacing: 8) {
            HStack(spacing: 3) {
                ForEach(0..<4) { i in
                    Capsule().fill(password.isEmpty || i > Int(s.level) ? Palette.line : colors[Int(s.level)]).frame(height: 4)
                }
            }
            Text(password.isEmpty ? " " : words[Int(s.level)]).font(.caption).foregroundStyle(Palette.muted).frame(width: 48, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(password.isEmpty ? "No password yet" : "Strength: \(words[Int(s.level)])")
    }
}
