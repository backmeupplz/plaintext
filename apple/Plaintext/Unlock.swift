import SwiftUI

/// Biometrics right away; a password below as the fallback.
struct UnlockView: View {
    @EnvironmentObject var model: AppModel
    @State private var password = ""
    @State private var accountId = ""
    @State private var busy = false
    @State private var error: String?
    @State private var signingIn = false
    @State private var keyLost = false
    @State private var confirmRemove = false
    /// The account a sign-in is waiting on its security key for.
    @State private var keyFor: KnownAccount?
    @State private var keyGen = 0
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
                if let k = keyFor, model.keyPage != nil {
                    KeyStepView { r in model.unlocked(k, r, since: keyGen) }
                } else {
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
                }
                if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
                // No passcode, so no lock-screen sign-in: an account this device can't
                // open any more (its Secret Key is gone) can at least be removed.
                if keyLost, let k = target {
                    Button("Remove \(k.name) from this device", role: .destructive) { confirmRemove = true }
                        .font(.footnote)
                        .buttonStyle(.plain)
                        .confirmationDialog("Remove \(k.name) from this device?", isPresented: $confirmRemove, titleVisibility: .visible) {
                            Button("Remove", role: .destructive) {
                                error = nil
                                keyLost = false
                                model.removeFromDevice(k.id)
                                accountId = model.lockedAccounts.first?.id ?? ""
                            }
                        } message: {
                            Text("To use it here again, sign in with your Emergency Kit. Changes that didn't sync yet are kept for that.")
                        }
                }
            }
            .frame(maxWidth: 360)
            Spacer()
            // Needs the device owner's check, so not on a device without a passcode:
            // signing out of every account there brings back first run.
            if Biometrics.available {
                Button("Sign in with your Emergency Kit") {
                    Task {
                        if await model.confirmOwnerToAdd() {
                            model.cancelKeyStep()
                            keyFor = nil
                            signingIn = true
                        }
                    }
                }
                .font(.footnote)
                .foregroundStyle(Palette.muted)
                .buttonStyle(.plain)
            }
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
        .onChange(of: model.addAborted) { _, _ in signingIn = false }
        .onChange(of: accountId) { _, _ in keyLost = false; error = nil }
        .sheet(isPresented: $signingIn, onDismiss: model.endOwnerCheck) {
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
            } catch PlaintextError.KeyNeeded {
                keyFor = k
                keyGen = model.lockGen
                password = ""
            } catch {
                self.error = errorText(error)
                if case PlaintextError.BadSecretKey = error, !Biometrics.available { keyLost = true }
            }
        }
    }
}

/// A sign-in waiting for the account's security key (DESIGN "Signing in with a
/// security key"): the server's page in the browser asks the key (over NFC or
/// USB), then Continue finishes here. Or a recovery code.
struct KeyStepView: View {
    @EnvironmentObject var model: AppModel
    let done: (LoginResult) -> Void
    @State private var code = ""
    @State private var busy = false
    @State private var error: String?
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("This account needs your security key to sign in on this device.").font(.headline)
            Button {
                if let p = model.keyPage, let u = URL(string: p) {
                    model.external = true
                    openURL(u)
                }
            } label: {
                Label("Approve with my security key", systemImage: "key")
            }
            Text("That opens a page on your server in the browser, which asks your key: hold it to the device or plug it in. Then come back here and continue. Only approve a sign-in you just started yourself. After that, this device is remembered.")
                .font(.footnote)
                .foregroundStyle(Palette.muted)
            TextField("Or a recovery code", text: $code)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                #endif
                .font(.body.monospaced())
            if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
            HStack {
                Button("Cancel") { model.cancelKeyStep() }
                Spacer()
                Button(action: finish) {
                    if busy { ProgressView() } else { Text("Continue") }
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy)
            }
        }
    }

    private func finish() {
        busy = true
        error = nil
        let c = code.trimmingCharacters(in: .whitespaces)
        Task {
            defer { busy = false }
            do {
                let r = try await model.call { try $0.finishLogin(recovery: c.isEmpty ? nil : c) }
                model.keyPage = nil
                done(r)
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
