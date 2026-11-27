import SwiftUI

struct WatchtowerView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(Prefs.breachCheck) private var breachCheck = false
    @State private var checking = false
    @State private var fixing: ItemRef?

    private func items(_ f: Finding) -> [WatchItem] { model.watch.filter { $0.findings.contains(f) } }
    private var breachedItems: [ItemSummary] { model.core.items(account: nil, vault: nil, query: "", archived: false).filter { model.breached[$0.key] != nil } }

    var body: some View {
        List {
            Section {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 96), spacing: 10)], spacing: 10) {
                    stat("Weak", items(.weak).count)
                    stat("Reused", items(.reused).count)
                    stat("Breached", breachCheck ? breachedItems.count : nil)
                    stat("Unsecured", items(.unsecured).count)
                    stat("No 2FA", items(.noTwoFactor).count)
                }
                .padding(.vertical, 6)
            }
            .listRowBackground(Color.clear)
            Section {
                Toggle("Check for breached passwords", isOn: $breachCheck)
                    .onChange(of: breachCheck) { _, on in if on { check() } else { model.breached = [:] } }
                if checking { HStack { ProgressView().controlSize(.small); Text("Checking…").foregroundStyle(Palette.muted) } }
            } footer: {
                Text("Plaintext asks Have I Been Pwned about each password. Only the first 5 characters of its hash leave this device, never the password.")
            }
            .listRowBackground(Palette.surface)
            group("Breached", breachedItems.map { s in WatchItem(accountId: s.accountId, vaultId: s.vaultId, id: s.id, title: s.title, subtitle: "Seen in \(model.breached[s.key] ?? 0) breaches", findings: [], reusedWith: 0) })
            group("Weak passwords", items(.weak))
            group("Reused passwords", items(.reused))
            group("Unsecured websites", items(.unsecured))
            group("Two-factor available", items(.noTwoFactor))
            if model.watch.isEmpty && breachedItems.isEmpty {
                Section {
                    Label("Nothing to fix. Nice.", systemImage: "checkmark.shield").foregroundStyle(Palette.accent)
                }
                .listRowBackground(Palette.surface)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
        .navigationTitle("Watchtower")
        .task { if breachCheck && model.breached.isEmpty { check() } }
    }

    private func stat(_ label: String, _ n: Int?) -> some View {
        VStack(spacing: 2) {
            Text(n.map(String.init) ?? "–").font(.title2.weight(.semibold).monospacedDigit()).foregroundStyle((n ?? 0) > 0 ? Palette.warn : Palette.fg)
            Text(label).font(.caption).foregroundStyle(Palette.muted)
        }
        .frame(maxWidth: .infinity, minHeight: 64)
        .background(Palette.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private func group(_ title: String, _ list: [WatchItem]) -> some View {
        if !list.isEmpty {
            Section(title) {
                ForEach(list, id: \.id) { w in
                    let ref = ItemRef(account: w.accountId, vault: w.vaultId, item: w.id)
                    HStack {
                        Group {
                            if Device.isPhone {
                                NavigationLink(value: ref) { row(w) }
                            } else {
                                Button { model.nav = .all; model.selection = ref.id } label: { row(w) }.buttonStyle(.plain)
                            }
                        }
                        if title != "Two-factor available" && title != "Unsecured websites" {
                            Button("Change") { fix(ref) }.buttonStyle(.borderless).font(.subheadline)
                        }
                    }
                    .listRowBackground(Palette.surface)
                }
            }
        }
    }

    private func row(_ w: WatchItem) -> some View {
        HStack(spacing: 12) {
            Monogram(title: w.title, size: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(w.title).foregroundStyle(Palette.fg)
                Text(w.reusedWith > 0 ? "Used in \(w.reusedWith) other \(w.reusedWith == 1 ? "item" : "items")" : w.subtitle).font(.caption).foregroundStyle(Palette.muted)
            }
            Spacer(minLength: 0)
        }
        .frame(minHeight: 48)
        .contentShape(Rectangle())
    }

    /// Open the site and the item in edit mode with a fresh password.
    private func fix(_ ref: ItemRef) {
        guard var data = try? model.core.item(account: ref.account, vault: ref.vault, id: ref.item) else { return }
        data.password = generatePassword(recipe: .random(length: 20, digits: true, symbols: true))
        if let u = data.urls.first, let url = URL(string: u.contains("://") ? u : "https://\(u)") {
            #if os(iOS)
            UIApplication.shared.open(url)
            #else
            NSWorkspace.shared.open(url)
            #endif
        }
        model.editor = EditorRequest(account: ref.account, vault: ref.vault, item: ref.item, data: data)
    }

    private func check() {
        checking = true
        Task {
            await model.runBreachCheck()
            checking = false
        }
    }
}

/// The inline Watchtower note on an item.
struct WatchBanner: View {
    let item: WatchItem
    var breached: UInt64?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let b = breached { Note(text: "This password appeared in \(b) data breaches. Change it.") }
            ForEach(item.findings, id: \.self) { f in
                switch f {
                case .weak: Note(text: "This password is easy to guess. Change it.")
                case .reused: Note(text: "This password is reused in \(item.reusedWith) other \(item.reusedWith == 1 ? "item" : "items"). Change it.")
                case .unsecured: Note(text: "This website address doesn't use https.")
                case .noTwoFactor: Note(text: "This site offers two-factor authentication. Add a one-time code.", icon: "lock.badge.clock")
                }
            }
        }
        .listRowBackground(Palette.surface)
    }
}

#if os(iOS)
import UIKit
#else
import AppKit
#endif
