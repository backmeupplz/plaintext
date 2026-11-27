import SwiftUI

func roleName(_ r: Role?) -> String {
    switch r {
    case .owner: return "Can manage"
    case .writer: return "Can edit"
    case .reader: return "Can view"
    case nil: return "Access ended"
    }
}

func accountLabel(_ a: AccountInfo?) -> String {
    guard let a else { return "" }
    return "\(a.username)@\(a.server.components(separatedBy: "://").last ?? a.server)"
}

/// Initials in small circles: who a vault is shared with.
struct Avatars: View {
    let names: [String]
    var body: some View {
        HStack(spacing: -6) {
            ForEach(names.prefix(4), id: \.self) { n in
                Circle().fill(Palette.surface).overlay(Circle().stroke(Palette.bg, lineWidth: 2))
                    .overlay(Text(n.prefix(1).uppercased()).font(.caption2.weight(.semibold)).foregroundStyle(Palette.muted))
                    .frame(width: 22, height: 22)
            }
            if names.count > 4 { Text("+\(names.count - 4)").font(.caption2).foregroundStyle(Palette.muted).padding(.leading, 8) }
        }
        .accessibilityLabel("Shared with \(names.joined(separator: ", "))")
    }
}

struct VaultsView: View {
    @EnvironmentObject var model: AppModel
    @State private var creating: String?
    @State private var name = ""

    var body: some View {
        List {
            ForEach(model.accounts, id: \.id) { a in
                Section {
                    ForEach(model.vaults.filter { $0.accountId == a.id }, id: \.key) { v in
                        NavigationLink { VaultDetail(account: v.accountId, vault: v.id) } label: {
                            HStack(spacing: 12) {
                                Image(systemName: v.members.count > 1 ? "person.2.fill" : "lock.fill").foregroundStyle(Palette.accent).frame(width: 28)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(v.name).foregroundStyle(Palette.fg)
                                    Text("\(v.itemCount) items · \(roleName(v.role))").font(.subheadline).foregroundStyle(Palette.muted)
                                }
                                Spacer()
                                if v.members.count > 1 { Avatars(names: v.members) }
                            }
                            .frame(minHeight: 52)
                        }
                        .listRowBackground(Palette.surface)
                    }
                    Button { creating = a.id } label: { Label("New vault", systemImage: "plus") }
                        .listRowBackground(Palette.surface)
                } header: {
                    Text(model.accounts.count > 1 ? accountLabel(a) : "Vaults")
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
        .navigationTitle("Vaults")
        .alert("New vault", isPresented: Binding(get: { creating != nil }, set: { if !$0 { creating = nil } })) {
            TextField("Name", text: $name)
            Button("Create") { create() }
            Button("Cancel", role: .cancel) { name = "" }
        }
    }

    private func create() {
        guard let a = creating, !name.isEmpty else { return }
        let n = name
        name = ""
        Task {
            do {
                _ = try await model.call { try $0.createVault(account: a, name: n) }
                model.reload()
            } catch { model.show(error) }
        }
    }
}

struct VaultDetail: View {
    @EnvironmentObject var model: AppModel
    let account: String
    let vault: String
    @State private var members: [MemberInfo] = []
    @State private var sharing = false
    @State private var removing: MemberInfo?
    @State private var working: String?
    @State private var renaming = false
    @State private var newName = ""

    private var info: VaultInfo? { model.vault(account: account, id: vault) }
    private var owner: Bool { info?.role == .owner }

    var body: some View {
        List {
            Section {
                ForEach(members, id: \.username) { m in
                    HStack(spacing: 12) {
                        Circle().fill(Palette.code).frame(width: 36, height: 36)
                            .overlay(Text(m.username.prefix(1).uppercased()).font(.headline).foregroundStyle(Palette.muted))
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 4) {
                                Text(m.isMe ? "\(m.username) (you)" : m.username).foregroundStyle(Palette.fg)
                                if m.verified && !m.isMe {
                                    Image(systemName: "checkmark.seal.fill").foregroundStyle(Palette.accent).font(.caption).accessibilityLabel("Verified")
                                }
                            }
                            Text([roleName(m.role), m.expires.map { "until \(date(seconds: $0))" }].compactMap { $0 }.joined(separator: " · "))
                                .font(.subheadline).foregroundStyle(Palette.muted)
                        }
                        Spacer()
                        if !m.isMe && !m.verified {
                            NavigationLink { VerifyView(account: account, username: m.username) } label: { Text("Verify").foregroundStyle(Palette.warn) }
                                .fixedSize()
                        }
                    }
                    .frame(minHeight: 52)
                    .listRowBackground(Palette.surface)
                    .swipeActions {
                        if owner && !m.isMe { Button("Remove", role: .destructive) { removing = m } }
                    }
                    .contextMenu {
                        if !m.isMe { NavigationLink("Verify…") { VerifyView(account: account, username: m.username) } }
                        if owner && !m.isMe { Button("Remove from vault", role: .destructive) { removing = m } }
                    }
                }
                if owner {
                    Button { sharing = true } label: { Label("Share vault", systemImage: "person.badge.plus") }.listRowBackground(Palette.surface)
                }
            } header: {
                Text("Members")
            } footer: {
                if let working { HStack { ProgressView().controlSize(.small); Text(working) } }
            }
            if owner {
                Section {
                    NavigationLink("Activity") { AuditView(account: account, vault: vault) }
                    Button("Rename vault") { newName = info?.name ?? ""; renaming = true }
                }
                .listRowBackground(Palette.surface)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
        .navigationTitle(info?.name ?? "Vault")
        .task { await load() }
        .sheet(isPresented: $sharing, onDismiss: { Task { await load() } }) { ShareVaultSheet(account: account, vault: vault) }
        .confirmationDialog("Remove \(removing?.username ?? "")?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("Remove", role: .destructive) { if let m = removing { remove(m) } }
        } message: {
            Text("The vault gets a new key, so they can't open anything added from now on. Anything they already saw may still be on their devices.")
        }
        .alert("Rename vault", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Save") {
                let n = newName
                Task {
                    do { try await model.call { try $0.renameVault(account: account, vault: vault, name: n) }; model.reload() } catch { model.show(error) }
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func load() async {
        do { members = try await model.call { try $0.members(account: account, vault: vault) } } catch { model.show(error) }
    }

    private func remove(_ m: MemberInfo) {
        working = "Replacing the vault key…"
        Task {
            defer { working = nil }
            do {
                try await model.call { try $0.revoke(account: account, vault: vault, username: m.username) }
                model.reload()
                await load()
                model.flash("Removed \(m.username)")
            } catch { model.show(error) }
        }
    }
}

struct ShareVaultSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let account: String
    let vault: String
    @State private var username = ""
    @State private var role = Role.writer
    @State private var expiry = 0
    @State private var found: String?
    @State private var foundVerified = false
    @State private var people: [UserData] = []
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        TextField("Their username", text: $username).plainInput().onSubmit(lookUp)
                        Button("Find", action: lookUp).disabled(username.isEmpty || busy)
                    }
                    if let found {
                        VStack(alignment: .leading, spacing: 4) {
                            Label(foundVerified ? "Verified" : "Not verified yet", systemImage: "checkmark.seal")
                                .foregroundStyle(foundVerified ? Palette.accent : Palette.warn)
                                .font(.subheadline)
                            Text(found).font(.caption.monospaced()).foregroundStyle(Palette.muted)
                        }
                    }
                    if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
                } header: {
                    Text("Person")
                } footer: {
                    Text("People are found by their exact username on \(accountLabel(model.account(account)).components(separatedBy: "@").last ?? "this server").")
                }
                if !people.isEmpty {
                    Section("Everyone on this server") {
                        ForEach(people.filter { !$0.isAgent && !$0.disabled && $0.username != model.account(account)?.username }, id: \.username) { p in
                            Button { username = p.username; lookUp() } label: {
                                HStack { Text(p.username).foregroundStyle(Palette.fg); if p.verified { Image(systemName: "checkmark.seal.fill").foregroundStyle(Palette.accent) } }
                            }
                        }
                    }
                }
                Section("Access") {
                    Picker("Role", selection: $role) {
                        Text("Can view").tag(Role.reader)
                        Text("Can edit").tag(Role.writer)
                        Text("Can manage").tag(Role.owner)
                    }
                    Picker("Expires", selection: $expiry) {
                        Text("Never").tag(0)
                        Text("In a day").tag(86_400)
                        Text("In a week").tag(604_800)
                        Text("In 30 days").tag(2_592_000)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Share vault")
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Share", action: share).disabled(username.isEmpty || busy) }
            }
            .task {
                // Browsing is for invite-only servers; hosted servers list nobody.
                people = (try? await model.call { try $0.users(account: account) }) ?? []
            }
        }
        #if os(macOS)
        .frame(width: 460, height: 520)
        #endif
    }

    private func lookUp() {
        let u = username.lowercased().trimmingCharacters(in: .whitespaces)
        guard !u.isEmpty else { return }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                found = try await model.call { try $0.fingerprint(account: account, username: u) }
                foundVerified = (try? await model.call { $0.isVerified(account: account, username: u) }) ?? false
            } catch {
                found = nil
                self.error = errorText(error)
            }
        }
    }

    private func share() {
        let (u, r) = (username.lowercased().trimmingCharacters(in: .whitespaces), role)
        let exp: UInt64? = expiry == 0 ? nil : UInt64(Date().timeIntervalSince1970) + UInt64(expiry)
        busy = true
        Task {
            defer { busy = false }
            do {
                try await model.call { try $0.shareVault(account: account, vault: vault, username: u, role: r, expires: exp) }
                model.reload()
                model.flash("Shared with \(u)")
                dismiss()
            } catch { self.error = errorText(error) }
        }
    }
}

/// Both fingerprints and a QR to scan: proof the server didn't swap a key.
struct VerifyView: View {
    @EnvironmentObject var model: AppModel
    let account: String
    let username: String
    @State private var theirs = ""
    @State private var mine = ""
    @State private var myCode = ""
    @State private var verified = false
    @State private var scanning = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("This makes sure your server can't swap their key for its own. Compare the numbers in person or on a call, or scan each other's code.")
                    .foregroundStyle(Palette.muted)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 6) {
                    Text("\(username)'s fingerprint").font(.subheadline.weight(.medium)).foregroundStyle(Palette.muted)
                    CodeBlock(text: theirs, size: .title3)
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text("Your fingerprint").font(.subheadline.weight(.medium)).foregroundStyle(Palette.muted)
                    CodeBlock(text: mine, size: .title3)
                }
                if !myCode.isEmpty {
                    QRImage(text: myCode).frame(maxWidth: 220).frame(maxWidth: .infinity)
                    Text("Let \(username) scan this.").font(.footnote).foregroundStyle(Palette.muted).frame(maxWidth: .infinity)
                }
                if verified {
                    Label("\(username) is verified", systemImage: "checkmark.seal.fill").foregroundStyle(Palette.accent).font(.headline)
                } else {
                    Button { scanning = true } label: { Label("Scan their code", systemImage: "qrcode.viewfinder") }.buttonStyle(PrimaryButtonStyle())
                    Button("The numbers match") { mark() }.buttonStyle(SecondaryButtonStyle())
                }
            }
            .padding(24)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
        .background(Palette.bg)
        .navigationTitle("Verify \(username)")
        .inlineTitle()
        .task {
            theirs = (try? await model.call { try $0.fingerprint(account: account, username: username) }) ?? ""
            mine = model.account(account)?.fingerprint ?? ""
            myCode = (try? model.core.myVerifyCode(account: account)) ?? ""
            verified = (try? await model.call { $0.isVerified(account: account, username: username) }) ?? false
        }
        .sheet(isPresented: $scanning) {
            CodeScanner(title: "Scan their code", prompt: "Ask \(username) to open Verify on their device.") { code in
                do {
                    let who = try await model.call { try $0.verifyScanned(account: account, code: code) }
                    if who == username { verified = true }
                    model.flash("\(who) is verified")
                    return nil
                } catch { return errorText(error) }
            }
        }
    }

    private func mark() {
        Task {
            do {
                try await model.call { try $0.markVerified(account: account, username: username) }
                verified = true
            } catch { model.show(error) }
        }
    }
}

struct AuditView: View {
    @EnvironmentObject var model: AppModel
    let account: String
    let vault: String
    @State private var entries: [AuditData] = []

    var body: some View {
        List(Array(entries.enumerated()), id: \.offset) { _, e in
            VStack(alignment: .leading, spacing: 2) {
                Text("\(e.username) \(e.action)").foregroundStyle(Palette.fg)
                Text(date(seconds: e.ts)).font(.caption).foregroundStyle(Palette.muted)
            }
            .listRowBackground(Palette.surface)
        }
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
        .navigationTitle("Activity")
        .task { do { entries = try await model.call { try $0.audit(account: account, vault: vault) } } catch { model.show(error) } }
    }
}

/// Send one item to a person, sealed to their key, or make a link.
struct ShareItemSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @AppStorage(Prefs.linkPage) private var linkPage = defaultLinkPage()
    let ref: ItemRef
    let title: String
    @State private var mode = 0
    @State private var username = ""
    @State private var personExpiry = 0
    @State private var linkExpiry = 86_400
    @State private var oneView = false
    @State private var link: String?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Picker("", selection: $mode) {
                    Text("Send to a person").tag(0)
                    Text("Create a link").tag(1)
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                if mode == 0 {
                    Section {
                        TextField("Their username", text: $username).plainInput()
                        Picker("Expires", selection: $personExpiry) {
                            Text("Never").tag(0)
                            Text("In a day").tag(86_400)
                            Text("In a week").tag(604_800)
                        }
                    } footer: {
                        Text("It lands in their Inbox, encrypted to their key. Attachments stay in your vault.")
                    }
                } else if let link {
                    Section {
                        Text(link).font(.footnote.monospaced()).lineLimit(4)
                        ShareLink(item: link) { Label("Share link", systemImage: "square.and.arrow.up") }
                        Button { model.copy(link, what: "Link") } label: { Label("Copy link", systemImage: "doc.on.doc") }
                    } footer: {
                        Text("Anyone with this link can see this item until it expires.")
                    }
                } else {
                    Section {
                        Picker("Expires", selection: $linkExpiry) {
                            Text("In an hour").tag(3_600)
                            Text("In a day").tag(86_400)
                            Text("In a week").tag(604_800)
                            Text("In 30 days").tag(2_592_000)
                        }
                        Toggle("Only one view", isOn: $oneView)
                    } footer: {
                        Text("Anyone with this link can see this item until it expires. The key is in the link itself, so the server can't read it.")
                    }
                }
                if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
            }
            .formStyle(.grouped)
            .navigationTitle("Share \(title)")
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(link == nil ? "Cancel" : "Done") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if mode == 0 { Button("Send", action: send).disabled(username.isEmpty || busy) } else if link == nil { Button("Create", action: create).disabled(busy) }
                }
            }
        }
        #if os(macOS)
        .frame(width: 460, height: 380)
        #endif
    }

    private func send() {
        let u = username.lowercased().trimmingCharacters(in: .whitespaces)
        let exp: UInt64? = personExpiry == 0 ? nil : UInt64(Date().timeIntervalSince1970) + UInt64(personExpiry)
        busy = true
        Task {
            defer { busy = false }
            do {
                try await model.call { try $0.sendItem(account: ref.account, vault: ref.vault, id: ref.item, to: u, expires: exp) }
                model.flash("Sent to \(u)")
                dismiss()
            } catch { self.error = errorText(error) }
        }
    }

    private func create() {
        let (page, exp, one) = (linkPage, UInt64(linkExpiry), oneView)
        busy = true
        Task {
            defer { busy = false }
            do { link = try await model.call { try $0.createLink(account: ref.account, vault: ref.vault, id: ref.item, page: page, expiresIn: exp, oneView: one) } } catch { self.error = errorText(error) }
        }
    }
}
