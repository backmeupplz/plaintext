import PDFKit
import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// The printable Emergency Kit: Secret Key, server, username, a blank line for
/// the password, and the sign-in QR for a new device.
enum EmergencyKit {
    @MainActor
    static func write(secretKey: String, server: String, username: String) -> URL? {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Plaintext Emergency Kit - \(username).pdf")
        let page = KitPage(secretKey: secretKey, server: server, username: username, qr: deviceCode(server: server, username: username, secretKey: secretKey))
            .environment(\.colorScheme, .light)
        let r = ImageRenderer(content: page)
        var ok = false
        r.render { size, draw in
            var box = CGRect(origin: .zero, size: size)
            guard let ctx = CGContext(url as CFURL, mediaBox: &box, nil) else { return }
            ctx.beginPDFPage(nil)
            draw(ctx)
            ctx.endPDFPage()
            ctx.closePDF()
            ok = true
        }
        return ok ? url : nil
    }

    /// The PDF holds the Secret Key: don't leave it in the temporary folder.
    static func discard(_ url: URL?) {
        if let url { try? FileManager.default.removeItem(at: url) }
    }

    /// At launch: kits left behind when the app was quit with one on screen.
    static func discardLeftovers() {
        let tmp = FileManager.default.temporaryDirectory
        for name in (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? [] where name.hasPrefix("Plaintext Emergency Kit") {
            discard(tmp.appendingPathComponent(name))
        }
    }

    @MainActor
    static func print(_ url: URL) {
        #if os(iOS)
        let pc = UIPrintInteractionController.shared
        pc.printingItem = url
        pc.present(animated: true)
        #else
        guard let doc = PDFDocument(url: url), let op = doc.printOperation(for: NSPrintInfo.shared, scalingMode: .pageScaleToFit, autoRotate: true) else { return }
        op.runModal(for: NSApp.keyWindow ?? NSWindow(), delegate: nil, didRun: nil, contextInfo: nil)
        #endif
    }
}

private struct KitPage: View {
    let secretKey: String
    let server: String
    let username: String
    let qr: String

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack {
                (Text("plain").foregroundColor(.black) + Text("text").foregroundColor(Color(red: 0x1f / 255, green: 0x7a / 255, blue: 0x4d / 255)))
                    .font(.system(size: 30, weight: .bold, design: .monospaced))
                Spacer()
                Text("Emergency Kit").font(.system(size: 20, weight: .semibold))
            }
            Text("Created for \(username) on \(Date.now.formatted(date: .long, time: .omitted)).").font(.system(size: 12)).foregroundColor(.gray)
            Text("Your Secret Key and your password together open your account. Nobody can recover them for you, not even whoever runs your server. Keep this page somewhere safe, like with your passport.")
                .font(.system(size: 13))
                .fixedSize(horizontal: false, vertical: true)
            row("Server", server)
            row("Username", username)
            VStack(alignment: .leading, spacing: 6) {
                Text("SECRET KEY").font(.system(size: 10, weight: .semibold)).foregroundColor(.gray)
                Text(secretKey).font(.system(size: 20, weight: .semibold, design: .monospaced))
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(red: 0.94, green: 0.93, blue: 0.9))
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("PASSWORD").font(.system(size: 10, weight: .semibold)).foregroundColor(.gray)
                Rectangle().fill(.black).frame(height: 1).padding(.top, 34)
                Text("Write it here, by hand, only if you keep this page locked away.").font(.system(size: 10)).foregroundColor(.gray)
            }
            HStack(alignment: .top, spacing: 18) {
                if let img = QRImage.cgImage(qr) {
                    Image(decorative: img, scale: 1).interpolation(.none).resizable().frame(width: 130, height: 130)
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text("Sign in on a new device").font(.system(size: 13, weight: .semibold))
                    Text("Choose Sign in, then Scan from another device, and scan this code. It holds your server, username and Secret Key, but not your password.")
                        .font(.system(size: 12))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
        }
        .padding(48)
        .frame(width: 612, height: 792)
        .background(.white)
        .foregroundColor(.black)
    }

    private func row(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundColor(.gray)
            Text(value).font(.system(size: 15, design: .monospaced))
        }
    }
}
