import SwiftUI

/// Welcome → Server → Create account → Emergency Kit → biometrics, or
/// Welcome → Server → username → Secret Key (scan or type) → password.
/// Also the *Add account* flow from Settings.
struct Onboarding: View {
    var adding = false
    var onDone: () -> Void = {}
    @EnvironmentObject var model: AppModel
    @StateObject private var flow: Flow

    init(adding: Bool = false, flow: Flow? = nil, onDone: @escaping () -> Void = {}) {
        self.adding = adding
        self.onDone = onDone
        _flow = StateObject(wrappedValue: flow ?? Flow())
    }

    var body: some View {
        NavigationStack(path: $flow.path) {
            Welcome(adding: adding)
                .navigationDestination(for: Flow.Step.self) { step in
                    Group {
                        switch step {
                        case .server: ServerStep()
                        case .create: CreateStep()
                        case .kit: KitStep()
                        case .biometrics: BiometricsStep()
                        case .username: UsernameStep()
                        case .secretKey: SecretKeyStep()
                        case .password: PasswordStep()
                        }
                    }
                    .frame(maxWidth: 520)
                    .frame(maxWidth: .infinity)
                    .background(Palette.bg.ignoresSafeArea())
                }
        }
        .environmentObject(flow)
        .onAppear { flow.finish = onDone }
        // Closed before finishing (say, Add account cancelled on the kit step).
        .onDisappear { model.settingUp = false }
    }
}

@MainActor
final class Flow: ObservableObject {
    enum Step: Hashable { case server, create, kit, biometrics, username, secretKey, password }
    enum Mode { case create, signIn }

    @Published var path: [Step] = []
    var mode = Mode.create
    var finish: () -> Void = {}
    @Published var useCloud = false
    @Published var custom = ""
    @Published var server = ""
    @Published var info: ServerInfo?
    @Published var username = ""
    @Published var password = ""
    @Published var invite = ""
    /// Show the invite field on an open server too.
    @Published var hasInvite = false
    @Published var secretKey = ""
    var signup: SignupResult?
    var login: LoginResult?
}

private struct StepPage<Content: View, Actions: View>: View {
    let title: String
    var subtitle: String?
    @ViewBuilder var content: Content
    @ViewBuilder var actions: Actions

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text(title).font(.largeTitle.bold()).foregroundStyle(Palette.fg).fixedSize(horizontal: false, vertical: true)
                    if let subtitle { Text(subtitle).foregroundStyle(Palette.muted).fixedSize(horizontal: false, vertical: true) }
                    content
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .scrollDismissesKeyboard(.interactively)
            VStack(spacing: 12) { actions }
                .padding(.horizontal, 24)
                .padding(.vertical, 16)
        }
        .inlineTitle()
    }
}

/// A labeled input in the onboarding style.
struct Field<Input: View>: View {
    let label: String
    var note: String?
    @ViewBuilder var input: Input

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.subheadline.weight(.medium)).foregroundStyle(Palette.muted)
            input
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .frame(minHeight: 48)
                .background(Palette.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).stroke(Palette.line))
            if let note { Text(note).font(.footnote).foregroundStyle(Palette.muted).fixedSize(horizontal: false, vertical: true) }
        }
    }
}

struct Welcome: View {
    var adding: Bool
    @EnvironmentObject var flow: Flow

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.shield").font(.system(size: 44, weight: .light)).foregroundStyle(Palette.accent).accessibilityHidden(true)
            Wordmark(size: 40)
            Text(adding ? "Add an account on any server: your family's, your work's, or Plaintext Cloud." : "Your passwords, encrypted on your devices. Your server only ever sees ciphertext.")
                .font(.title3)
                .multilineTextAlignment(.center)
                .foregroundStyle(Palette.muted)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 420)
            Spacer()
            VStack(spacing: 12) {
                Button("Create account") {
                    flow.mode = .create
                    flow.path = [.server]
                }
                .buttonStyle(PrimaryButtonStyle())
                Button("Sign in") {
                    flow.mode = .signIn
                    flow.path = [.server]
                }
                .buttonStyle(SecondaryButtonStyle())
            }
            .frame(maxWidth: 420)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.bg.ignoresSafeArea())
    }
}

struct ServerStep: View {
    @EnvironmentObject var flow: Flow
    @State private var busy = false
    @State private var error: String?
    @AppStorage(Prefs.recentServers) private var recentsRaw = ""
    private var recents: [String] { recentsRaw.split(separator: "\n").map(String.init).filter { $0 != cloudServer() } }

    private var insecure: Bool {
        !flow.useCloud && ((try? serverAddress(address: flow.custom))?.insecure ?? false)
    }

    var body: some View {
        StepPage(title: "Where are your vaults?", subtitle: "Pick the server that keeps your encrypted vaults. You can add accounts on other servers later.") {
            choice(cloud: true, title: "Plaintext Cloud", detail: "We run the server for you, so there's nothing to set up.", icon: "cloud")
            choice(cloud: false, title: "My own server", detail: "The Plaintext server you or your family run.", icon: "server.rack")
            if !flow.useCloud {
                Field(label: "Server address", note: "A domain, an IP address or a Tailscale name, with a port if it needs one.") {
                    TextField("vault.example.com", text: $flow.custom)
                        .plainInput()
                        .urlKeyboard()
                        .onSubmit(next)
                }
                if insecure { Note(text: "Without https, anyone on your network can see which server you use.") }
                if !recents.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Recent").font(.subheadline.weight(.medium)).foregroundStyle(Palette.muted)
                        ForEach(recents, id: \.self) { r in
                            Button { flow.custom = r } label: {
                                Label(r, systemImage: "clock.arrow.circlepath").font(.callout.monospaced())
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Palette.accent)
                        }
                    }
                }
            }
            if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
        } actions: {
            Button(action: next) {
                if busy { ProgressView().tint(Palette.accentFg) } else { Text("Continue") }
            }
            .buttonStyle(PrimaryButtonStyle())
            .disabled(busy || (!flow.useCloud && flow.custom.trimmingCharacters(in: .whitespaces).isEmpty))
        }
    }

    private func choice(cloud: Bool, title: String, detail: String, icon: String) -> some View {
        Button {
            withAnimation(.easeOut(duration: 0.15)) { flow.useCloud = cloud }
        } label: {
            HStack(spacing: 14) {
                Image(systemName: icon).font(.title2).frame(width: 32).foregroundStyle(Palette.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.headline).foregroundStyle(Palette.fg)
                    Text(detail).font(.subheadline).foregroundStyle(Palette.muted).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Image(systemName: flow.useCloud == cloud ? "checkmark.circle.fill" : "circle")
                    .font(.title3)
                    .foregroundStyle(flow.useCloud == cloud ? Palette.accent : Palette.line)
            }
            .padding(16)
            .background(Palette.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(flow.useCloud == cloud ? Palette.accent : Palette.line))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(flow.useCloud == cloud ? .isSelected : [])
    }

    private func next() {
        error = nil
        let typed = flow.useCloud ? cloudServer() : flow.custom
        let address: ServerAddress
        do { address = try serverAddress(address: typed) } catch { self.error = errorText(error); return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let info = try await Task.detached { try serverInfo(server: address.url) }.value
                flow.server = address.url
                flow.info = info
                recentsRaw = ([address.url] + recents.filter { $0 != address.url }).prefix(5).joined(separator: "\n")
                if flow.path.last == .server {
                    flow.path.append(flow.mode == .create ? .create : .username)
                }
            } catch {
                self.error = errorText(error)
            }
        }
    }
}

struct CreateStep: View {
    @EnvironmentObject var flow: Flow
    @EnvironmentObject var model: AppModel
    @State private var reveal = false
    @State private var busy = false
    @State private var error: String?
    @State private var scanning = false

    private var needsInvite: Bool { !(flow.info?.open ?? true) }
    private var setup: Bool { flow.info?.setup ?? false }
    private var ready: Bool {
        validUsername(username: flow.username) && passwordStrength(password: flow.password).level >= 1 && (!needsInvite || setup || !flow.invite.isEmpty) && (!setup || !flow.invite.isEmpty)
    }

    var body: some View {
        StepPage(title: "Create your account", subtitle: "on \(flow.server.components(separatedBy: "://").last ?? flow.server)") {
            Field(label: "Username", note: "Lowercase letters, digits, dots, dashes or underscores. People share vaults with you by this name.") {
                TextField("alex", text: $flow.username).plainInput().textContentType(.username)
            }
            VStack(alignment: .leading, spacing: 8) {
                Field(label: "Password") {
                    HStack {
                        Group {
                            if reveal { TextField("A long, memorable password", text: $flow.password) } else { SecureField("A long, memorable password", text: $flow.password) }
                        }
                        .plainInput()
                        .textContentType(.newPassword)
                        .font(reveal ? .body.monospaced() : .body)
                        Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                            .buttonStyle(.plain)
                            .foregroundStyle(Palette.muted)
                            .accessibilityLabel(reveal ? "Hide password" : "Show password")
                    }
                }
                StrengthMeter(password: flow.password)
                Button {
                    flow.password = generatePassword(recipe: .memorable(words: 4, separator: "-", capitalize: false))
                    reveal = true
                } label: { Label("Suggest one", systemImage: "wand.and.stars") }
                    .font(.subheadline.weight(.medium))
                    .buttonStyle(.plain)
                    .foregroundStyle(Palette.accent)
            }
            if setup {
                Field(label: "Setup code", note: "The code the person who runs this server set, so nobody else can claim it first.") {
                    TextField("Setup code", text: $flow.invite).plainInput()
                }
            } else if needsInvite || flow.hasInvite {
                Field(label: needsInvite ? "Invite code" : "Invite code (optional)", note: "From the person who invited you. It also confirms who they are.") {
                    HStack {
                        TextField("Paste the invite code", text: $flow.invite).plainInput().font(.body.monospaced())
                        Button { scanning = true } label: { Image(systemName: "qrcode.viewfinder") }
                            .buttonStyle(.plain)
                            .foregroundStyle(Palette.accent)
                            .accessibilityLabel("Scan an invite")
                    }
                }
            } else {
                Button { flow.hasInvite = true } label: { Label("I have an invite", systemImage: "envelope.open") }
                    .font(.subheadline.weight(.medium))
                    .buttonStyle(.plain)
                    .foregroundStyle(Palette.accent)
            }
            if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
        } actions: {
            Button(action: create) {
                if busy { ProgressView().tint(Palette.accentFg) } else { Text("Create account") }
            }
            .buttonStyle(PrimaryButtonStyle())
            .disabled(!ready || busy)
        }
        .sheet(isPresented: $scanning) {
            CodeScanner(title: "Scan an invite", prompt: "Scan the invite code the person who invited you shows, or paste their invite link.") { code in
                guard let l = parseInviteLink(link: code) else { return "That isn't a Plaintext invite." }
                if let s = l.server, (try? serverAddress(address: s))?.url != flow.server {
                    return "This invite is for \(s). Go back and choose that server."
                }
                flow.invite = l.code
                return nil
            }
        }
    }

    private func create() {
        error = nil
        busy = true
        let (server, username, password) = (flow.server, flow.username.lowercased(), flow.password)
        let invite = flow.invite.trimmingCharacters(in: .whitespaces)
        Task {
            defer { busy = false }
            do {
                let r = try await model.call { try $0.signup(server: server, username: username, password: password, invite: invite.isEmpty ? nil : invite) }
                flow.signup = r
                model.remember(r.account, secretKey: r.secretKey)
                flow.password = ""
                flow.path.append(.kit)
            } catch {
                self.error = errorText(error)
            }
        }
    }
}

struct KitStep: View {
    @EnvironmentObject var flow: Flow
    @EnvironmentObject var model: AppModel
    @State private var pdf: Data?
    @State private var saving = false

    var body: some View {
        let r = flow.signup
        StepPage(title: "Save your Emergency Kit", subtitle: "Your Secret Key and your password together open your account. Nobody can recover them for you, not even whoever runs your server, so keep this kit somewhere safe.") {
            if let r {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Secret Key").font(.subheadline.weight(.medium)).foregroundStyle(Palette.muted)
                    CodeBlock(text: r.secretKey, size: .title2)
                        .accessibilityLabel("Secret Key \(r.secretKey.map { String($0) }.joined(separator: " "))")
                    Button { model.copy(r.secretKey, what: "Secret Key") } label: { Label("Copy", systemImage: "doc.on.doc") }
                        .font(.subheadline.weight(.medium))
                        .buttonStyle(.plain)
                        .foregroundStyle(Palette.accent)
                }
                LabeledRow(label: "Server", value: r.account.server)
                LabeledRow(label: "Username", value: r.account.username)
                if let w = r.warning { Note(text: w, icon: "exclamationmark.triangle", color: Palette.warn) }
            }
        } actions: {
            if let pdf, let r {
                HStack(spacing: 12) {
                    Button { saving = true } label: { Label("Save as PDF", systemImage: "square.and.arrow.down") }
                        .buttonStyle(SecondaryButtonStyle())
                    Button { EmergencyKit.print(pdf) } label: { Label("Print", systemImage: "printer") }
                        .buttonStyle(SecondaryButtonStyle())
                }
                .kitExporter(isPresented: $saving, pdf: pdf, username: r.account.username)
                Button("I've saved it") { flow.path.append(.biometrics) }
                .buttonStyle(PrimaryButtonStyle())
            }
        }
        .navigationBarBackButtonHiddenCompat()
        .task {
            if let r { pdf = EmergencyKit.pdf(secretKey: r.secretKey, server: r.account.server, username: r.account.username) }
        }
    }
}

struct LabeledRow: View {
    let label: String
    let value: String
    var mono = true
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.subheadline).foregroundStyle(Palette.muted)
            Text(value).font(mono ? .body.monospaced() : .body).foregroundStyle(Palette.fg)
        }
        .accessibilityElement(children: .combine)
    }
}

extension View {
    func navigationBarBackButtonHiddenCompat() -> some View { navigationBarBackButtonHidden(true) }
}

struct BiometricsStep: View {
    @EnvironmentObject var flow: Flow
    @EnvironmentObject var model: AppModel
    @AppStorage(Prefs.biometrics) private var biometrics = true

    var body: some View {
        let name = Biometrics.name ?? "your device passcode"
        StepPage(title: Biometrics.name.map { "Unlock with \($0)" } ?? "Unlock with your passcode", subtitle: "Open Plaintext with \(name) instead of typing your password each time. Your password never leaves your head; the keys stay in this device's keychain.") {
            HStack {
                Spacer()
                Image(systemName: Biometrics.icon).font(.system(size: 72, weight: .light)).foregroundStyle(Palette.accent).padding(.vertical, 24)
                Spacer()
            }
            .accessibilityHidden(true)
        } actions: {
            if Biometrics.available {
                Button("Turn on \(Biometrics.name ?? "passcode unlock")") { done(true) }.buttonStyle(PrimaryButtonStyle())
            }
            Button("Not now") { done(false) }.buttonStyle(SecondaryButtonStyle())
        }
        .navigationBarBackButtonHiddenCompat()
    }

    private func done(_ on: Bool) {
        // One setting for every account: "Not now" on an added account leaves the
        // others as they are (turning it off would end their stored sessions).
        let adding = model.known.count > 1
        let turnedOn = on && !biometrics
        if on || !adding { biometrics = on }
        if let r = flow.signup {
            model.added(r.account, unlock: r.unlock, secretKey: r.secretKey)
        } else if let l = flow.login {
            model.added(l.account, unlock: l.unlock, secretKey: flow.secretKey)
        }
        if adding && turnedOn { model.biometricsChanged() }
        flow.finish()
    }
}

struct UsernameStep: View {
    @EnvironmentObject var flow: Flow
    @State private var scanning = false

    var body: some View {
        StepPage(title: "Sign in", subtitle: "On a device where you're already signed in, open Settings → Add a device and scan its code here. Or type your Secret Key from your Emergency Kit.") {
            Field(label: "Username") {
                TextField("alex", text: $flow.username).plainInput().textContentType(.username)
            }
        } actions: {
            Button { scanning = true } label: { Label("Scan from another device", systemImage: "qrcode.viewfinder") }
                .buttonStyle(PrimaryButtonStyle())
            Button("Enter Secret Key") { flow.path.append(.secretKey) }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(!validUsername(username: flow.username.lowercased()))
        }
        .sheet(isPresented: $scanning) {
            CodeScanner(title: "Scan from another device", prompt: "On your other device, open Settings → Add a device.") { code in
                guard let d = parseDeviceCode(code: code) else { return "That isn't a Plaintext sign-in code." }
                (flow.server, flow.username, flow.secretKey) = (d.server, d.username, d.secretKey)
                scanning = false
                flow.path.append(.password)
                return nil
            }
        }
    }
}

struct SecretKeyStep: View {
    @EnvironmentObject var flow: Flow
    @State private var error: String?

    var body: some View {
        StepPage(title: "Enter your Secret Key", subtitle: "It's on your Emergency Kit and starts with A1. Dashes and capitals don't matter.") {
            Field(label: "Secret Key") {
                TextField("A1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX", text: $flow.secretKey, axis: .vertical)
                    .plainInput()
                    .font(.body.monospaced())
                    .padding(.vertical, 12)
                    .onSubmit(next)
            }
            if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
        } actions: {
            Button("Continue", action: next).buttonStyle(PrimaryButtonStyle()).disabled(flow.secretKey.count < 10)
        }
    }

    private func next() {
        do {
            flow.secretKey = try normalizeSecretKey(secretKey: flow.secretKey)
            error = nil
            flow.path.append(.password)
        } catch {
            self.error = errorText(error)
        }
    }
}

struct PasswordStep: View {
    @EnvironmentObject var flow: Flow
    @EnvironmentObject var model: AppModel
    @State private var busy = false
    @State private var error: String?
    @FocusState private var focused: Bool

    var body: some View {
        StepPage(title: "Enter your password", subtitle: "\(flow.username)@\(flow.server.components(separatedBy: "://").last ?? flow.server)") {
            Field(label: "Password") {
                SecureField("Password", text: $flow.password).textContentType(.password).focused($focused).onSubmit(signIn)
            }
            if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
        } actions: {
            Button(action: signIn) {
                if busy { ProgressView().tint(Palette.accentFg) } else { Text("Sign in") }
            }
            .buttonStyle(PrimaryButtonStyle())
            .disabled(flow.password.isEmpty || busy)
        }
        .onAppear { focused = true }
    }

    private func signIn() {
        guard !flow.password.isEmpty else { return }
        error = nil
        busy = true
        let (server, sk, pw) = (flow.server, flow.secretKey, flow.password)
        Task {
            defer { busy = false }
            do {
                let l = try await model.call { try $0.login(server: server, secretKey: sk, password: pw) }
                flow.login = l
                model.remember(l.account, secretKey: sk)
                flow.password = ""
                flow.path.append(.biometrics)
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
