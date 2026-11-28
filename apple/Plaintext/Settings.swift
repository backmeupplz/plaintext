import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(Prefs.autoLockMinutes) private var autoLock = 10
    @AppStorage(Prefs.clipboardSeconds) private var clipboard = 90
    @AppStorage(Prefs.biometrics) private var biometrics = true
    @AppStorage(Prefs.hideOnShare) private var hideOnShare = true
    @AppStorage(Prefs.linkPage) private var linkPage = defaultLinkPage()
    @AppStorage(Prefs.sortRecent) private var sortRecent = false
    @State private var adding = false
    @State private var importing = false

    var body: some View {
        Form {
            Section("Accounts") {
                ForEach(model.known) { k in
                    NavigationLink { AccountSettings(known: k) } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(k.username).foregroundStyle(Palette.fg)
                                Text(k.host).font(.caption.monospaced()).foregroundStyle(Palette.muted)
                            }
                            Spacer()
                            if model.account(k.id) == nil { Text("Locked").font(.caption).foregroundStyle(Palette.warn) }
                            if model.account(k.id)?.pending == true { Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(Palette.muted).accessibilityLabel("Changes waiting to sync") }
                        }
                    }
                }
                Button { adding = true } label: { Label("Add account", systemImage: "plus") }
            }
            Section {
                Picker("Auto-lock", selection: $autoLock) {
                    Text("Immediately").tag(0)
                    Text("After 1 minute").tag(1)
                    Text("After 5 minutes").tag(5)
                    Text("After 10 minutes").tag(10)
                    Text("After 1 hour").tag(60)
                    Text("After 8 hours").tag(480)
                }
                if Biometrics.available {
                    Toggle("Unlock with \(Biometrics.name ?? "device password")", isOn: $biometrics)
                        .onChange(of: biometrics) { _, _ in model.biometricsChanged() }
                }
                Picker("Clear copied secrets", selection: $clipboard) {
                    Text("After 30 seconds").tag(30)
                    Text("After 90 seconds").tag(90)
                    Text("After 5 minutes").tag(300)
                }
                Toggle("Hide while sharing the screen", isOn: $hideOnShare)
                Button("Lock now") { model.lock() }
            } header: {
                Text("Security")
            } footer: {
                Text("Plaintext also locks when this device locks.")
            }
            Section("Items") {
                Toggle("Sort by recently changed", isOn: $sortRecent).onChange(of: sortRecent) { _, _ in model.reload() }
                Button { importing = true } label: { Label("Import from 1Password, Bitwarden or CSV", systemImage: "square.and.arrow.down") }
                NavigationLink { VaultsView() } label: { Label("Vaults and sharing", systemImage: "person.2") }
                NavigationLink { AgentsView() } label: { Label("Agents", systemImage: "cpu") }
            }
            Section {
                TextField("Link page", text: $linkPage).plainInput().font(.body.monospaced())
                if linkPage != defaultLinkPage() { Button("Use getplaintext.org") { linkPage = defaultLinkPage() } }
            } header: {
                Text("Share links")
            } footer: {
                Text("The page that opens shared links. If you host your own copy, put its address here; never host it on your vault server.")
            }
            Section("About") {
                LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")
                Link("Source code", destination: URL(string: "https://github.com/backmeupplz/plaintext")!)
                Link("getplaintext.org", destination: URL(string: "https://getplaintext.org")!)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
        .navigationTitle("Settings")
        .sheet(isPresented: $adding) {
            Onboarding(adding: true) { adding = false }
                #if os(macOS)
                .frame(width: 520, height: 640)
                #endif
        }
        .sheet(isPresented: $importing) { ImportView() }
    }
}

struct AccountSettings: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let known: KnownAccount
    @State private var sessions: [SessionData] = []
    @State private var users: [UserData] = []
    @State private var invite: String?
    @State private var deviceCode: String?
    @State private var kit: Data?
    @State private var savingKit = false
    @State private var changing = false
    @State private var confirmSignOut = false
    @State private var password = ""
    @State private var busy = false

    private var info: AccountInfo? { model.account(known.id) }
    @State private var open = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Username", value: known.username)
                LabeledContent("Server") { Text(known.server).font(.callout.monospaced()).textSelection(.enabled) }
                if let info {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Your fingerprint").font(.caption).foregroundStyle(Palette.muted)
                        Text(info.fingerprint).font(.callout.monospaced()).textSelection(.enabled)
                    }
                    if info.admin { Label("Server admin", systemImage: "person.badge.shield.checkmark").foregroundStyle(Palette.muted) }
                }
            }
            if info == nil {
                Section("Locked") {
                    SecureField("Password", text: $password).onSubmit(unlock)
                    Button("Unlock", action: unlock).disabled(password.isEmpty || busy)
                }
            } else {
                Section {
                    Button { deviceCode = try? model.core.addDeviceCode(account: known.id, secretKey: Keychain.secretKey(for: known) ?? "") } label: {
                        Label("Add a device", systemImage: "qrcode")
                    }
                    Button {
                        if let sk = Keychain.secretKey(for: known) { kit = EmergencyKit.pdf(secretKey: sk, server: known.server, username: known.username) }
                    } label: { Label("Emergency Kit", systemImage: "doc.text") }
                    if let kit {
                        Button { savingKit = true } label: { Label("Save the kit as PDF", systemImage: "square.and.arrow.down") }
                            .kitExporter(isPresented: $savingKit, pdf: kit, username: known.username)
                        Button { EmergencyKit.print(kit) } label: { Label("Print the kit", systemImage: "printer") }
                    }
                    Button { changing = true } label: { Label("Change password", systemImage: "key") }
                }
                Section("Devices") {
                    ForEach(sessions, id: \.id) { s in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(s.device).foregroundStyle(Palette.fg)
                                Text(s.current ? "This device" : "Since \(date(seconds: s.created))").font(.caption).foregroundStyle(Palette.muted)
                            }
                            Spacer()
                            if !s.current {
                                Button("Sign out", role: .destructive) { end(s) }.buttonStyle(.borderless)
                            }
                        }
                    }
                }
                if info?.admin == true || open {
                    Section {
                        Button { makeInvite() } label: { Label("Invite someone", systemImage: "person.badge.plus") }
                        if let invite {
                            QRImage(text: invite).frame(maxWidth: 200).frame(maxWidth: .infinity)
                            Text(invite).font(.caption.monospaced())
                            ShareLink(item: invite) { Label("Share invite", systemImage: "square.and.arrow.up") }
                            Button { model.copy(invite, what: "Invite") } label: { Label("Copy invite", systemImage: "doc.on.doc") }
                        }
                        if info?.admin == true {
                            ForEach(users.filter { $0.username != known.username }, id: \.username) { u in
                                HStack {
                                    Text(u.username).foregroundStyle(u.disabled ? Palette.muted : Palette.fg)
                                    if u.isAgent { Text("agent of \(u.owner ?? "")").font(.caption).foregroundStyle(Palette.muted) }
                                    Spacer()
                                    if u.disabled { Text("Disabled").font(.caption).foregroundStyle(Palette.muted) } else {
                                        Button("Disable", role: .destructive) { disable(u.username) }.buttonStyle(.borderless)
                                    }
                                }
                            }
                        }
                    } header: {
                        Text("People")
                    } footer: {
                        Text("An invite works once. It carries your fingerprint, so the person you invite and you are verified to each other.")
                    }
                }
            }
            Section {
                Button("Sign out of this account", role: .destructive) { confirmSignOut = true }
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
        .navigationTitle(known.name)
        .inlineTitle()
        .task { await load() }
        .sheet(isPresented: Binding(get: { deviceCode != nil }, set: { if !$0 { deviceCode = nil } })) { AddDeviceSheet(code: deviceCode ?? "") }
        .sheet(isPresented: $changing) { ChangePassword(known: known) }
        .confirmationDialog("Sign out of \(known.name)?", isPresented: $confirmSignOut, titleVisibility: .visible) {
            Button("Sign out", role: .destructive) {
                model.signOut(known.id)
                dismiss()
            }
        } message: {
            Text("This device forgets the account and its copies. You'll need your Emergency Kit to sign in again.")
        }
    }

    private func load() async {
        guard info != nil else { return }
        let server = known.server
        open = (try? await Task.detached { try serverInfo(server: server) }.value)?.open ?? false
        sessions = (try? await model.call { [known] in try $0.sessions(account: known.id) }) ?? []
        if info?.admin == true { users = (try? await model.call { [known] in try $0.users(account: known.id) }) ?? [] }
    }

    private func unlock() {
        busy = true
        let pw = password
        Task {
            defer { busy = false }
            do {
                try await model.unlock(known, password: pw)
                password = ""
                await load()
            } catch { model.show(error) }
        }
    }

    private func end(_ s: SessionData) {
        Task {
            do { try await model.call { [known] in try $0.endSession(account: known.id, id: s.id) }; await load() } catch { model.show(error) }
        }
    }

    private func makeInvite() {
        Task {
            do { invite = try await model.call { [known] in try $0.invite(account: known.id) } } catch { model.show(error) }
        }
    }

    private func disable(_ u: String) {
        Task {
            do { try await model.call { [known] in try $0.disableUser(account: known.id, username: u) }; await load() } catch { model.show(error) }
        }
    }
}

struct AddDeviceSheet: View {
    let code: String
    @Environment(\.dismiss) private var dismiss
    @State private var shown = false
    #if os(iOS)
    @State private var captured = UIScreen.main.isCaptured
    #else
    private let captured = false
    #endif

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Text("On the new device, choose Sign in, then Scan from another device. This code holds your Secret Key, so only show it to your own devices.")
                    .foregroundStyle(Palette.muted)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                if captured {
                    Note(text: "The code stays hidden while your screen is recorded or shared.", icon: "eye.slash")
                } else if shown {
                    // It holds the Secret Key: shown for a minute at a time.
                    QRImage(text: code).frame(maxWidth: 260)
                        .task {
                            try? await Task.sleep(for: .seconds(60))
                            shown = false
                        }
                } else {
                    Button("Show the code") { shown = true }.buttonStyle(PrimaryButtonStyle()).frame(maxWidth: 260)
                }
                Spacer()
            }
            .padding(24)
            .background(Palette.bg)
            #if os(iOS)
            .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in captured = UIScreen.main.isCaptured }
            #else
            .background(NoCapture())
            #endif
            .navigationTitle("Add a device")
            .inlineTitle()
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        #if os(macOS)
        .frame(width: 420, height: 480)
        #endif
    }
}

struct ChangePassword: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let known: KnownAccount
    @State private var old = ""
    @State private var new = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                SecureField("Current password", text: $old).textContentType(.password)
                Section {
                    SecureField("New password", text: $new).textContentType(.newPassword)
                    StrengthMeter(password: new)
                } footer: {
                    Text("Your other devices sign in again with the new password. Your Secret Key stays the same.")
                }
                if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
            }
            .formStyle(.grouped)
            .navigationTitle("Change password")
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Change", action: change).disabled(old.isEmpty || passwordStrength(password: new).level < 1 || busy)
                }
            }
        }
        #if os(macOS)
        .frame(width: 420, height: 320)
        #endif
    }

    private func change() {
        guard let sk = Keychain.secretKey(for: known) else { return }
        let (o, n) = (old, new)
        busy = true
        Task {
            defer { busy = false }
            do {
                try await model.call { [known] in try $0.changePassword(account: known.id, secretKey: sk, oldPassword: o, newPassword: n) }
                model.flash("Password changed")
                dismiss()
            } catch { self.error = errorText(error) }
        }
    }
}

struct ImportView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var format = ImportFormat.onePux
    @State private var account = ""
    @State private var into = ""
    @State private var picking = false
    @State private var busy = false
    @State private var done: UInt32?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("From", selection: $format) {
                        Text("1Password (.1pux)").tag(ImportFormat.onePux)
                        Text("Bitwarden (.json)").tag(ImportFormat.bitwarden)
                        Text("CSV (Chrome, Firefox, Safari, others)").tag(ImportFormat.csv)
                    }
                    if model.accounts.count > 1 {
                        Picker("Account", selection: $account) {
                            ForEach(model.accounts, id: \.id) { Text(accountLabel($0)).tag($0.id) }
                        }
                        .onChange(of: account) { _, _ in into = "" }
                    }
                    Picker("Into", selection: $into) {
                        Text("Vaults with the same names").tag("")
                        ForEach(model.vaults.filter { $0.accountId == account && $0.role != nil && $0.role != .reader }, id: \.id) { Text($0.name).tag($0.id) }
                    }
                } footer: {
                    Text("Export unencrypted from your old password manager, import here, then delete the export file.")
                }
                if busy { HStack { ProgressView().controlSize(.small); Text("Importing…") } }
                if let done { Label("Imported \(done) items.", systemImage: "checkmark.circle.fill").foregroundStyle(Palette.accent) }
                if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
            }
            .formStyle(.grouped)
            .navigationTitle("Import")
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(done == nil ? "Cancel" : "Done") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Choose file…") {
                        #if DEBUG
                        // UI tests can't drive the system file picker: they name the file instead.
                        if let p = ProcessInfo.processInfo.environment["PT_IMPORT_FILE"] { return load(URL(fileURLWithPath: p)) }
                        #endif
                        picking = true
                    }
                    .disabled(busy || account.isEmpty)
                }
            }
            .onAppear { if account.isEmpty { account = model.accounts.first?.id ?? "" } }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.data, .json, .commaSeparatedText, .zip]) { r in
                guard case .success(let url) = r else { return }
                load(url)
            }
        }
        #if os(macOS)
        .frame(width: 480, height: 360)
        #endif
    }

    private func load(_ url: URL) {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else { error = "Couldn't read that file."; return }
        let (a, f, v) = (account, format, into.isEmpty ? nil : into)
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                let r = try await model.call { try $0.importItems(account: a, format: f, data: data, vault: v) }
                done = r.items
                error = r.warning
                model.reload()
            } catch { self.error = errorText(error) }
        }
    }
}
