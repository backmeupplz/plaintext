import SwiftUI

/// Biometrics right away; a password below as the fallback.
struct UnlockView: View {
    @EnvironmentObject var model: AppModel
    @State private var password = ""
    @State private var accountId = ""
    @State private var busy = false
    @State private var error: String?
    @State private var signingIn = false
    @FocusState private var focused: Bool

    private var target: KnownAccount? { model.known(accountId) ?? model.lockedAccounts.first }
    private var canBiometric: Bool { model.known.contains(where: Keychain.hasSession) }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Wordmark(size: 36)
            if canBiometric {
                Button {
                    Task { await model.unlockWithBiometrics() }
                } label: {
                    VStack(spacing: 10) {
                        Image(systemName: Biometrics.icon).font(.system(size: 52, weight: .light))
                        Text("Unlock with \(Biometrics.name ?? "passcode")").font(.headline)
                    }
                    .foregroundStyle(Palette.accent)
                    .frame(minWidth: 200, minHeight: 120)
                }
                .buttonStyle(.plain)
                .disabled(model.unlocking)
            }
            VStack(alignment: .leading, spacing: 10) {
                if model.known.count > 1 {
                    Picker("Account", selection: $accountId) {
                        ForEach(model.lockedAccounts) { k in Text(k.name).tag(k.id) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                }
                HStack {
                    SecureField(model.known.count > 1 ? "Password for \(target?.username ?? "")" : "Password", text: $password)
                        .textContentType(.password)
                        .focused($focused)
                        .onSubmit(unlock)
                    Button(action: unlock) {
                        if busy { ProgressView() } else { Image(systemName: "arrow.right.circle.fill").font(.title2) }
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Palette.accent)
                    .disabled(password.isEmpty || busy)
                    .accessibilityLabel("Unlock")
                }
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .frame(minHeight: 48)
                .background(Palette.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).stroke(Palette.line))
                if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
            }
            .frame(maxWidth: 360)
            Spacer()
            Button("Sign in with your Emergency Kit") { signingIn = true }
                .font(.footnote)
                .foregroundStyle(Palette.muted)
                .buttonStyle(.plain)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.bg.ignoresSafeArea())
        .task {
            accountId = model.lockedAccounts.first?.id ?? ""
            #if DEBUG
            // UI tests photograph this screen before asking.
            if ProcessInfo.processInfo.environment["PT_IMPORT_FILE"] != nil || ProcessInfo.processInfo.environment["PT_SHOTS"] != nil { return }
            #endif
            if canBiometric { await model.unlockWithBiometrics() } else { focused = true }
        }
        .sheet(isPresented: $signingIn) {
            Onboarding(adding: true) { signingIn = false }
                #if os(macOS)
                .frame(width: 520, height: 640)
                #endif
        }
    }

    private func unlock() {
        guard let k = target, !password.isEmpty else { return }
        busy = true
        error = nil
        let pw = password
        Task {
            defer { busy = false }
            do {
                try await model.unlock(k, password: pw)
                password = ""
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
