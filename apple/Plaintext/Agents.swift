import SwiftUI

struct AgentsView: View {
    @EnvironmentObject var model: AppModel
    @State private var agents: [String: [AgentInfo]] = [:]
    @State private var creating: String?
    @State private var disabling: (String, String)?

    var body: some View {
        List {
            Section {
                Text("An agent is an account for a script or an AI assistant. It reaches only the vaults you give it, and asks you here when it needs more.")
                    .font(.subheadline).foregroundStyle(Palette.muted)
            }
            .listRowBackground(Color.clear)
            ForEach(model.accounts, id: \.id) { a in
                Section(model.accounts.count > 1 ? accountLabel(a) : "Your agents") {
                    ForEach(agents[a.id] ?? [], id: \.name) { ag in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Label(ag.name, systemImage: "cpu").font(.body.weight(.medium)).foregroundStyle(Palette.fg)
                                Spacer()
                                Toggle("On", isOn: Binding(get: { !ag.disabled }, set: { if !$0 { disabling = (a.id, ag.name) } }))
                                    .labelsHidden()
                                    .disabled(ag.disabled)
                                    .accessibilityLabel(ag.disabled ? "\(ag.name) is off" : "Turn off \(ag.name)")
                            }
                            ForEach(ag.access, id: \.vaultId) { x in
                                Text("\(x.vaultName): \(roleName(x.role).lowercased())\(x.expires.map { ", until \(date(seconds: $0))" } ?? "")")
                                    .font(.subheadline).foregroundStyle(Palette.muted)
                            }
                            Text(ag.lastActive.map { "Last active \(date(seconds: $0))" } ?? "Not used yet").font(.caption).foregroundStyle(Palette.muted)
                        }
                        .padding(.vertical, 4)
                        .listRowBackground(Palette.surface)
                    }
                    Button { creating = a.id } label: { Label("New agent", systemImage: "plus") }.listRowBackground(Palette.surface)
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
        .navigationTitle("Agents")
        .task { await load() }
        .refreshable { await load() }
        .sheet(item: Binding(get: { creating.map { IdBox(id: $0) } }, set: { creating = $0?.id }), onDismiss: { Task { await load() } }) { NewAgent(account: $0.id) }
        .confirmationDialog("Turn off \(disabling?.1 ?? "")?", isPresented: Binding(get: { disabling != nil }, set: { if !$0 { disabling = nil } }), titleVisibility: .visible) {
            Button("Turn off", role: .destructive) {
                guard let (a, name) = disabling else { return }
                Task {
                    do { try await model.call { try $0.disableUser(account: a, username: name) }; await load() } catch { model.show(error) }
                }
            }
        } message: {
            Text("Its key stops working everywhere. This can't be undone; make a new agent if you need one again.")
        }
    }

    private func load() async {
        for a in model.accounts {
            do { agents[a.id] = try await model.call { try $0.agents(account: a.id) } } catch { model.show(error) }
        }
    }
}

struct IdBox: Identifiable { let id: String }

/// Name → vault and role → expiry → the key, shown once.
struct NewAgent: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let account: String
    @State private var name = ""
    @State private var vault = ""
    @State private var role = Role.reader
    @State private var expiry = 0
    @State private var key: String?
    @State private var busy = false
    @State private var error: String?

    private var server: String { model.account(account)?.server ?? "" }

    var body: some View {
        NavigationStack {
            Form {
                if let key {
                    Section {
                        Text(key).font(.callout.monospaced()).textSelection(.enabled)
                        Button { model.copy(key, what: "Agent key") } label: { Label("Copy", systemImage: "doc.on.doc") }
                    } header: {
                        Text("Agent key")
                    } footer: {
                        Text("This is the only time it's shown. Store it where the agent runs; anyone with it acts as \(name.lowercased()).")
                    }
                    Section("Use it") {
                        Text("PLAINTEXT_SERVER=\(server) PLAINTEXT_AGENT_KEY=… plaintext run --env API_TOKEN=\"Item/password\" -- ./deploy.sh")
                            .font(.caption.monospaced()).textSelection(.enabled)
                        Text("For an AI assistant, add the MCP server: command plaintext, argument mcp, with the same two variables.")
                            .font(.caption).foregroundStyle(Palette.muted)
                    }
                } else {
                    Section("Name") {
                        TextField("deploy-bot", text: $name).plainInput()
                    }
                    Section("Access") {
                        Picker("Vault", selection: $vault) {
                            ForEach(model.vaults.filter { $0.accountId == account && $0.role == .owner }, id: \.id) { Text($0.name).tag($0.id) }
                        }
                        Picker("Role", selection: $role) {
                            Text("Can view").tag(Role.reader)
                            Text("Can edit").tag(Role.writer)
                        }
                        Picker("Expires", selection: $expiry) {
                            Text("Never").tag(0)
                            Text("In a day").tag(86_400)
                            Text("In a week").tag(604_800)
                            Text("In 30 days").tag(2_592_000)
                        }
                    }
                    if let error { Note(text: error, icon: "exclamationmark.circle", color: Palette.danger) }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("New agent")
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(key == nil ? "Cancel" : "Done") { dismiss() } }
                if key == nil {
                    ToolbarItem(placement: .confirmationAction) { Button("Create", action: create).disabled(!validUsername(username: name.lowercased()) || vault.isEmpty || busy) }
                }
            }
            .onAppear { vault = model.vaults.first { $0.accountId == account && $0.role == .owner && !$0.isDefault }?.id ?? model.vaults.first { $0.accountId == account && $0.role == .owner }?.id ?? "" }
        }
        .interactiveDismissDisabled(key != nil)
        #if os(macOS)
        .frame(width: 480, height: 460)
        #endif
    }

    private func create() {
        let (n, v, r) = (name, vault, role)
        let exp: UInt64? = expiry == 0 ? nil : UInt64(Date().timeIntervalSince1970) + UInt64(expiry)
        busy = true
        Task {
            defer { busy = false }
            do {
                key = try await model.call { try $0.createAgent(account: account, name: n, vault: v, role: r, expires: exp) }
                model.reload()
            } catch { self.error = errorText(error) }
        }
    }
}
