import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import UniformTypeIdentifiers
#if os(iOS)
import VisionKit
#endif

/// A QR code drawn crisp at any size.
struct QRImage: View {
    let text: String

    var body: some View {
        if let img = QRImage.cgImage(text) {
            Image(decorative: img, scale: 1)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .padding(12)
                .background(.white, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .accessibilityLabel("QR code")
        }
    }

    static func cgImage(_ text: String) -> CGImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage else { return nil }
        return CIContext().createCGImage(out, from: out.extent)
    }

    /// The first QR code in an image file (Mac: a screenshot or a saved code).
    static func read(_ url: URL) -> String? {
        guard let img = CIImage(contentsOf: url),
              let d = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        else { return nil }
        return d.features(in: img).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first
    }
}

/// Scan a QR with the camera where there is one; paste the code, or (Mac) pick
/// an image of it, everywhere. `onCode` returns an error to show, or nil when done.
struct CodeScanner: View {
    let title: String
    let prompt: String
    let onCode: @MainActor (String) async -> String?
    @Environment(\.dismiss) private var dismiss
    @State private var checking = false
    @State private var pasted = ""
    @State private var error: String?
    @State private var picking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                #if os(iOS)
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    Scanner { submit($0) }
                        .frame(maxWidth: .infinity, minHeight: 280)
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
                #endif
                Text(prompt).font(.subheadline).foregroundStyle(Palette.muted).multilineTextAlignment(.center)
                Field(label: "Or paste the code") {
                    TextField("plaintext:…", text: $pasted).plainInput().font(.body.monospaced()).onSubmit { submit(pasted) }
                }
                #if os(macOS)
                Button { picking = true } label: { Label("Choose an image of the code…", systemImage: "photo") }
                #endif
                if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
                Spacer()
                Button("Use this code") { submit(pasted) }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(pasted.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(24)
            .background(Palette.bg.ignoresSafeArea())
            .navigationTitle(title)
            .inlineTitle()
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.image]) { r in
                guard case .success(let url) = r else { return }
                let ok = url.startAccessingSecurityScopedResource()
                defer { if ok { url.stopAccessingSecurityScopedResource() } }
                if let code = QRImage.read(url) { submit(code) } else { error = "There's no QR code in that image." }
            }
        }
        #if os(macOS)
        .frame(width: 460, height: 420)
        #endif
    }

    private func submit(_ code: String) {
        let c = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !c.isEmpty, !checking else { return }
        checking = true
        Task {
            defer { checking = false }
            if let e = await onCode(c) { error = e } else { dismiss() }
        }
    }
}

#if os(iOS)
private struct Scanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced, isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        try? vc.startScanning()
        return vc
    }

    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ s: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let b) in items {
                if let v = b.payloadStringValue { found(v); return }
            }
        }
    }
}
#endif
