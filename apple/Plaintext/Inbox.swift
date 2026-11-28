import SwiftUI

struct InboxView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let empty = model.accounts.allSatisfy { (model.inbox[$0.id] ?? []).isEmpty }
        Group {
            if empty {
                VStack(spacing: 12) {
                    Image(systemName: "tray").font(.system(size: 40, weight: .light)).foregroundStyle(Palette.accent)
                    Text("Items people send you and your agents' requests show up here.").multilineTextAlignment(.center).foregroundStyle(Palette.muted).frame(maxWidth: 300)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Palette.bg)
            } else {
                List {
                    ForEach(model.accounts, id: \.id) { a in
                        let entries = model.inbox[a.id] ?? []
                        if !entries.isEmpty {
                            Section(model.accounts.count > 1 ? accountLabel(a) : "") {
                                ForEach(Array(entries.enumerated()), id: \.offset) { _, e in
                                    InboxRow(account: a.id, entry: e).listRowBackground(Palette.surface)
                                }
                            }
                        }
                    }
                }
                .scrollContentBackground(.hidden)
                .background(Palette.bg)
            }
        }
        .navigationTitle("Inbox")
        .refreshable { await model.syncAll() }
    }
}

struct InboxRow: View {
    @EnvironmentObject var model: AppModel
    let account: String
    let entry: InboxEntry
    @State private var granting = false
    @State private var sendingItem = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: entry.fromAgentOfMine ? "cpu" : "person.crop.circle").foregroundStyle(Palette.muted)
                Text(entry.from).font(.subheadline.weight(.semibold)).foregroundStyle(Palette.fg)
                if entry.verified { Image(systemName: "checkmark.seal.fill").font(.caption).foregroundStyle(Palette.accent).accessibilityLabel("Verified") }
                if entry.fromAgentOfMine { Text("your agent").font(.caption).foregroundStyle(Palette.muted) }
                Spacer()
                if let e = entry.expires { Text("until \(date(seconds: e))").font(.caption).foregroundStyle(Palette.muted) }
            }
            switch entry.content {
            case .item(let item):
                HStack(spacing: 12) {
                    Monogram(title: item.title, size: 36)
                    VStack(alignment: .leading) {
                        Text(item.title).foregroundStyle(Palette.fg)
                        Text(kindName(item.kind)).font(.caption).foregroundStyle(Palette.muted)
                    }
                }
                HStack {
                    Menu("Save to vault") {
                        ForEach(model.vaults.filter { $0.accountId == account && $0.role != nil && $0.role != .reader }, id: \.key) { v in
                            Button(v.name) { save(into: v.id) }
                        }
                    }
                    .fixedSize()
                    Spacer()
                    Button("Dismiss", role: .destructive, action: dismissMessage)
                }
                .buttonStyle(.borderless)
            case .request(let text):
                Text(text).foregroundStyle(Palette.fg).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 16) {
                    // Only your own agents ask for access; from anyone else it's a lure.
                    if entry.fromAgentOfMine {
                        Button("Give access to a vault…") { granting = true }
                        Button("Send an item…") { sendingItem = true }
                    }
                    Spacer()
                    Button("Dismiss", role: .destructive, action: dismissMessage)
                }
                .buttonStyle(.borderless)
                .font(.subheadline)
            case .unreadable(let reason):
                Note(text: reason)
            }
        }
        .padding(.vertical, 6)
        .confirmationDialog("Give \(entry.from) access to", isPresented: $granting) {
            ForEach(model.vaults.filter { $0.accountId == account && $0.role == .owner }, id: \.key) { v in
                Button("\(v.name) (can view)") { grant(v.id) }
            }
        }
        .sheet(isPresented: $sendingItem) { PickItemSheet(account: account, to: entry.from) }
    }

    private func save(into vault: String) {
        Task {
            do {
                _ = try await model.call { try $0.saveFromInbox(account: account, message: entry.id, vault: vault) }
                await model.syncAll()
                model.flash("Saved")
            } catch { model.show(error) }
        }
    }

    private func grant(_ vault: String) {
        Task {
            do {
                try await model.call { try $0.shareVault(account: account, vault: vault, username: entry.from, role: .reader, expires: nil) }
                try await model.call { try $0.dismissMessage(account: account, message: entry.id) }
                await model.syncAll()
                model.flash("\(entry.from) can view it now")
            } catch { model.show(error) }
        }
    }

    private func dismissMessage() {
        Task {
            do {
                try await model.call { try $0.dismissMessage(account: account, message: entry.id) }
                await model.syncAll()
            } catch { model.show(error) }
        }
    }
}

/// Pick one item of an account to send someone.
struct PickItemSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let account: String
    let to: String
    @State private var query = ""

    var body: some View {
        NavigationStack {
            List(model.core.items(account: account, vault: nil, query: query, archived: false), id: \.key) { s in
                Button {
                    Task {
                        do {
                            try await model.call { try $0.sendItem(account: account, vault: s.vaultId, id: s.id, to: to, expires: nil) }
                            model.flash("Sent \(s.title) to \(to)")
                            dismiss()
                        } catch { model.show(error) }
                    }
                } label: { ItemRow(item: s) }
                .buttonStyle(.plain)
            }
            .searchable(text: $query)
            .navigationTitle("Send to \(to)")
            .inlineTitle()
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        #if os(macOS)
        .frame(width: 420, height: 480)
        #endif
    }
}
