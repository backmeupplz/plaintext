import SwiftUI

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.horizontalSizeClass) private var size

    var body: some View {
        Group {
            if Device.isPhone || size == .compact {
                PhoneHome()
            } else {
                SplitHome()
            }
        }
        .sheet(item: $model.editor) { req in
            ItemEditor(request: req)
                #if os(macOS)
                .frame(minWidth: 560, minHeight: 640)
                #endif
        }
    }
}

// MARK: Phone

struct PhoneHome: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        TabView {
            NavigationStack {
                ItemList()
                    .navigationDestination(for: ItemRef.self) { ItemDetail(ref: $0) }
            }
            .tabItem { Label("Items", systemImage: "key.horizontal") }
            NavigationStack {
                WatchtowerView()
                    .navigationDestination(for: ItemRef.self) { ItemDetail(ref: $0) }
            }
            .tabItem { Label("Watchtower", systemImage: "binoculars") }
            .badge(model.watch.count)
            NavigationStack { InboxView() }
                .tabItem { Label("Inbox", systemImage: "tray") }
                .badge(model.inboxCount)
            NavigationStack { SettingsView() }
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
    }
}

/// The phone's vault picker: All vaults, Favorites, then each account's vaults.
struct VaultMenu: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Menu {
            Picker("Show", selection: $model.nav) {
                Label("All items", systemImage: "square.stack").tag(Nav?.some(.all))
                Label("Favorites", systemImage: "star").tag(Nav?.some(.favorites))
            }
            ForEach(model.accounts, id: \.id) { a in
                Section(model.accounts.count > 1 ? "\(a.username)@\(a.server.components(separatedBy: "://").last ?? "")" : "Vaults") {
                    Picker("Vaults", selection: $model.nav) {
                        ForEach(model.vaults.filter { $0.accountId == a.id }, id: \.key) { v in
                            Label(v.name, systemImage: v.members.count > 1 ? "person.2" : "lock").tag(Nav?.some(.vault(account: v.accountId, id: v.id)))
                        }
                    }
                }
            }
            Section {
                Picker("More", selection: $model.nav) {
                    Label("Archive", systemImage: "archivebox").tag(Nav?.some(.archive))
                }
            }
        } label: {
            HStack(spacing: 4) {
                Text(title).font(.headline)
                Image(systemName: "chevron.down").font(.caption.weight(.semibold))
            }
            .foregroundStyle(Palette.fg)
        }
        .accessibilityLabel("Vault: \(title)")
    }

    var title: String { model.navTitle }
}

// MARK: Mac and iPad

struct SplitHome: View {
    @EnvironmentObject var model: AppModel
    @State var columns = NavigationSplitViewVisibility.all

    var body: some View {
        NavigationSplitView(columnVisibility: $columns) {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 200, ideal: 230)
        } content: {
            Group {
                switch model.nav ?? .all {
                case .watchtower: WatchtowerView()
                case .inbox: InboxView()
                case .agents: AgentsView()
                case .vaults: VaultsView()
                default: ItemList()
                }
            }
            .navigationSplitViewColumnWidth(min: 280, ideal: 340)
        } detail: {
            NavigationStack {
                if let s = model.summary(model.selection) {
                    ItemDetail(ref: s.ref).id(s.key)
                } else {
                    VStack(spacing: 12) {
                        Wordmark(size: 28).opacity(0.5)
                        Text(model.items.isEmpty ? " " : "Select an item").foregroundStyle(Palette.muted)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Palette.bg)
                }
            }
        }
    }
}

struct Sidebar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List(selection: $model.nav) {
            Section {
                Label("All items", systemImage: "square.stack").tag(Nav.all)
                Label("Favorites", systemImage: "star").tag(Nav.favorites)
            }
            ForEach(model.accounts, id: \.id) { a in
                Section(model.accounts.count > 1 ? "\(a.username)@\(a.server.components(separatedBy: "://").last ?? "")" : "Vaults") {
                    ForEach(model.vaults.filter { $0.accountId == a.id }, id: \.key) { v in
                        Label {
                            HStack {
                                Text(v.name)
                                Spacer()
                                Text("\(v.itemCount)").foregroundStyle(Palette.muted).font(.caption)
                            }
                        } icon: {
                            Image(systemName: v.members.count > 1 ? "person.2" : "lock")
                        }
                        .tag(Nav.vault(account: v.accountId, id: v.id))
                    }
                }
            }
            if !model.tags.isEmpty {
                Section("Tags") {
                    ForEach(model.tags, id: \.self) { t in Label(t, systemImage: "tag").tag(Nav.tag(t)) }
                }
            }
            Section {
                Label("Watchtower", systemImage: "binoculars").badge(model.watch.count).tag(Nav.watchtower)
                Label("Inbox", systemImage: "tray").badge(model.inboxCount).tag(Nav.inbox)
                Label("Vaults and sharing", systemImage: "person.2").tag(Nav.vaults)
                Label("Agents", systemImage: "cpu").tag(Nav.agents)
                Label("Archive", systemImage: "archivebox").tag(Nav.archive)
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .background(Palette.surface)
        .navigationTitle("Plaintext")
        .toolbar {
            #if os(iOS)
            ToolbarItem(placement: .topBarLeading) {
                NavigationLink { SettingsView() } label: { Image(systemName: "gearshape") }.accessibilityLabel("Settings")
            }
            #endif
        }
    }
}

// MARK: Items

struct ItemList: View {
    @EnvironmentObject var model: AppModel
    @FocusState private var searchFocused: Bool
    @State private var importing = false

    private var split: Bool { !Device.isPhone }

    var body: some View {
        let favorites = model.nav == .all && model.query.isEmpty ? model.items.filter(\.favorite) : []
        let rest = favorites.isEmpty ? model.items : model.items.filter { !$0.favorite }
        Group {
            if model.items.isEmpty {
                EmptyItems(importing: $importing)
            } else {
                List(selection: split ? $model.selection : .constant(nil)) {
                    if !favorites.isEmpty {
                        Section("Favorites") { ForEach(favorites, id: \.key) { row($0) } }
                    }
                    Section(favorites.isEmpty ? "" : "All items") { ForEach(rest, id: \.key) { row($0) } }
                }
                #if os(iOS)
                .listStyle(.insetGrouped)
                #endif
                .scrollContentBackground(.hidden)
                .background(Palette.bg)
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            if split { searchField }
        }
        .modifier(PhoneSearch(enabled: !split, query: $model.query))
        .refreshable { await model.syncAll() }
        .navigationTitle(split ? model.navTitle : "")
        .toolbar {
            #if os(iOS)
            if !split { ToolbarItem(placement: .principal) { VaultMenu() } }
            #endif
            ToolbarItem(placement: .primaryAction) {
                Button { model.newItem() } label: { Image(systemName: "plus") }
                    .accessibilityLabel("New item")
                    .disabled(model.accounts.isEmpty)
            }
            if model.syncing {
                ToolbarItem(placement: .status) { ProgressView().controlSize(.small) }
            }
        }
        .onChange(of: model.focusSearch) { _, f in
            if f { searchFocused = true; model.focusSearch = false }
        }
        .onChange(of: searchFocused) { _, f in model.searching = f }
        .sheet(isPresented: $importing) { ImportView() }
    }

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(Palette.muted)
            TextField("Search", text: $model.query)
                .textFieldStyle(.plain)
                .plainInput()
                .focused($searchFocused)
            if !model.query.isEmpty {
                Button { model.query = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(Palette.muted)
                    .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 10)
        .frame(height: 34)
        .background(Palette.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Palette.bg)
        .onAppear { searchFocused = true }
    }

    @ViewBuilder
    private func row(_ s: ItemSummary) -> some View {
        Group {
            if split {
                ItemRow(item: s)
            } else {
                NavigationLink(value: s.ref) { ItemRow(item: s) }
            }
        }
        .tag(s.key)
        .listRowBackground(Palette.surface)
        .contextMenu { QuickActions(item: s) }
        .swipeActions(edge: .leading) {
            if s.hasPassword {
                Button { model.copyField(s.ref, "password") } label: { Label("Copy password", systemImage: "key") }.tint(Palette.accent)
            }
        }
        .swipeActions(edge: .trailing) {
            if model.canEdit(s.ref) {
            Button { model.setFlags(s.ref, favorite: !s.favorite, archived: s.archived) } label: {
                Label(s.favorite ? "Unfavorite" : "Favorite", systemImage: s.favorite ? "star.slash" : "star")
            }
            .tint(.yellow)
            Button { model.setFlags(s.ref, favorite: s.favorite, archived: !s.archived) } label: {
                Label(s.archived ? "Unarchive" : "Archive", systemImage: "archivebox")
            }
            .tint(Palette.muted)
            }
        }
    }
}

private struct PhoneSearch: ViewModifier {
    let enabled: Bool
    @Binding var query: String
    func body(content: Content) -> some View {
        if enabled { content.searchable(text: $query, prompt: "Search") } else { content }
    }
}

struct QuickActions: View {
    @EnvironmentObject var model: AppModel
    let item: ItemSummary

    var body: some View {
        if item.hasUsername { Button { model.copyField(item.ref, "username") } label: { Label("Copy username", systemImage: "person") } }
        if item.hasPassword { Button { model.copyField(item.ref, "password") } label: { Label("Copy password", systemImage: "key") } }
        if item.hasTotp { Button { model.copyField(item.ref, "totp") } label: { Label("Copy one-time code", systemImage: "clock") } }
        if model.canEdit(item.ref) {
            Divider()
            Button { model.setFlags(item.ref, favorite: !item.favorite, archived: item.archived) } label: {
                Label(item.favorite ? "Remove from Favorites" : "Add to Favorites", systemImage: "star")
            }
            Button { model.edit(item.ref) } label: { Label("Edit", systemImage: "pencil") }
            Button(role: .destructive) { model.delete(item.ref, title: item.title) } label: { Label("Delete", systemImage: "trash") }
        }
    }
}

struct ItemRow: View {
    @EnvironmentObject var model: AppModel
    let item: ItemSummary

    var body: some View {
        HStack(spacing: 12) {
            Monogram(title: item.title)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(item.title.isEmpty ? "Untitled" : item.title).font(.body.weight(.medium)).foregroundStyle(Palette.fg).lineLimit(1)
                    if item.favorite { Image(systemName: "star.fill").font(.caption2).foregroundStyle(.yellow).accessibilityLabel("Favorite") }
                }
                Text(secondary).font(.subheadline).foregroundStyle(Palette.muted).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .frame(minHeight: 52)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }

    private var secondary: String {
        if case .vault = model.nav ?? .all { return item.subtitle }
        let multi = model.accounts.count > 1 || model.vaults.count > 1
        guard multi else { return item.subtitle }
        return [item.subtitle, item.vaultName].filter { !$0.isEmpty }.joined(separator: " · ")
    }
}

struct EmptyItems: View {
    @EnvironmentObject var model: AppModel
    @Binding var importing: Bool

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: model.query.isEmpty ? "key.horizontal" : "magnifyingglass").font(.system(size: 40, weight: .light)).foregroundStyle(Palette.accent)
            if model.query.isEmpty {
                Text("Add your first login, or import from 1Password or Bitwarden.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(Palette.muted)
                    .frame(maxWidth: 300)
                VStack(spacing: 10) {
                    Button("Add a login") { model.newItem() }.buttonStyle(PrimaryButtonStyle())
                    Button("Import") { importing = true }.buttonStyle(SecondaryButtonStyle())
                }
                .frame(maxWidth: 280)
            } else {
                Text("Nothing matches “\(model.query)”.").foregroundStyle(Palette.muted)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.bg)
    }
}
