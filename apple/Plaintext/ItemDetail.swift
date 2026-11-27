import SwiftUI
import UniformTypeIdentifiers

struct ItemDetail: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openURL) private var openURL
    let ref: ItemRef
    @State private var data: ItemData?
    @State private var largeType: String?
    @State private var sharing = false
    @State private var moving = false
    @State private var exportFile: ExportFile?
    @State private var attaching = false
    @State private var busy = false

    private var summary: ItemSummary? { model.summary(ref.id) }
    private var vault: VaultInfo? { model.vault(ref) }
    private var canEdit: Bool { vault?.role.map { $0 != .reader } ?? false }
    private var findings: WatchItem? { model.watch.first { $0.accountId == ref.account && $0.vaultId == ref.vault && $0.id == ref.item } }

    var body: some View {
        Group {
            if let d = data {
                List {
                    header(d)
                    if let f = findings { Section { WatchBanner(item: f, breached: model.breached[ref.id]) } }
                    Section {
                        if !d.username.isEmpty { FieldRow(label: "username", value: d.username, kind: "text", largeType: $largeType) }
                        if !d.password.isEmpty { FieldRow(label: "password", value: d.password, kind: "concealed", largeType: $largeType) }
                        if !d.totp.isEmpty { TotpRow(spec: d.totp) }
                        ForEach(Array(d.urls.enumerated()), id: \.offset) { i, u in
                            FieldRow(label: i == 0 ? "website" : "website \(i + 1)", value: u, kind: "url", largeType: $largeType)
                        }
                    }
                    ForEach(Array(d.sections.enumerated()), id: \.offset) { _, s in
                        let fields = s.fields.filter { !$0.value.isEmpty }
                        if !fields.isEmpty {
                            Section(s.title) {
                                ForEach(Array(fields.enumerated()), id: \.offset) { _, f in
                                    FieldRow(label: f.label, value: f.value, kind: f.kind, largeType: $largeType)
                                }
                            }
                        }
                    }
                    if !d.notes.isEmpty {
                        Section("Notes") {
                            // Plain text: a link in a shared note never acts on its own.
                            Text(verbatim: d.notes)
                                .textSelection(.enabled)
                                .foregroundStyle(Palette.fg)
                        }
                    }
                    if !d.tags.isEmpty {
                        Section("Tags") {
                            Text(d.tags.map { "#\($0)" }.joined(separator: "  ")).foregroundStyle(Palette.accent)
                        }
                    }
                    if !d.files.isEmpty || canEdit {
                        Section("Attachments") {
                            ForEach(d.files, id: \.id) { f in
                                Button { download(f) } label: {
                                    HStack {
                                        Label(f.name, systemImage: "paperclip").foregroundStyle(Palette.fg)
                                        Spacer()
                                        Text(ByteCountFormatter.string(fromByteCount: Int64(f.size), countStyle: .file)).foregroundStyle(Palette.muted).font(.caption)
                                    }
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    if canEdit { Button(role: .destructive) { removeFile(f) } label: { Label("Remove", systemImage: "trash") } }
                                }
                                .swipeActions {
                                    if canEdit { Button(role: .destructive) { removeFile(f) } label: { Label("Remove", systemImage: "trash") } }
                                }
                            }
                            if canEdit {
                                Button { attaching = true } label: {
                                    if busy { ProgressView() } else { Label("Add attachment", systemImage: "plus") }
                                }
                                .disabled(busy)
                            }
                        }
                    }
                    if !d.passwordHistory.isEmpty {
                        Section("Password history") {
                            ForEach(Array(d.passwordHistory.enumerated()), id: \.offset) { _, p in
                                FieldRow(label: "until \(date(p.changed))", value: p.password, kind: "concealed", largeType: $largeType)
                            }
                        }
                    }
                    if !d.history.isEmpty {
                        Section("Earlier versions") {
                            ForEach(Array(d.history.enumerated()), id: \.offset) { i, v in
                                HStack {
                                    VStack(alignment: .leading) {
                                        Text(v.title).foregroundStyle(Palette.fg)
                                        Text(date(v.updated)).font(.caption).foregroundStyle(Palette.muted)
                                    }
                                    Spacer()
                                    if canEdit { Button("Restore") { restore(i) }.buttonStyle(.borderless) }
                                }
                            }
                        }
                    }
                    Section {
                        Text("Created \(date(d.created)) · Updated \(date(d.updated))").font(.footnote).foregroundStyle(Palette.muted)
                    }
                    .listRowBackground(Color.clear)
                }
                #if os(iOS)
                .listStyle(.insetGrouped)
                #endif
                .scrollContentBackground(.hidden)
                .background(Palette.bg)
            } else {
                Text("This item is no longer here.").foregroundStyle(Palette.muted).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(data?.title ?? "")
        .inlineTitle()
        .toolbar { toolbar }
        .onAppear(perform: load)
        .onChange(of: model.items.map(\.updated)) { _, _ in load() }
        .onChange(of: model.editor == nil) { _, _ in load() }
        .sheet(item: Binding(get: { largeType.map { LargeTypeText(text: $0) } }, set: { largeType = $0?.text })) { LargeType(text: $0.text) }
        .sheet(isPresented: $sharing) { ShareItemSheet(ref: ref, title: data?.title ?? "") }
        .sheet(isPresented: $moving) { MoveSheet(ref: ref) }
        .fileExporter(isPresented: Binding(get: { exportFile != nil }, set: { if !$0 { exportFile = nil } }), document: exportFile, contentType: .data, defaultFilename: exportFile?.name) { _ in exportFile = nil }
        .fileImporter(isPresented: $attaching, allowedContentTypes: [.item]) { r in
            if case .success(let url) = r { attach(url) }
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            if canEdit { Button("Edit") { model.edit(ref) }.keyboardShortcut("e") }
            Menu {
                if let s = summary {
                    if canEdit {
                        Button { model.setFlags(ref, favorite: !s.favorite, archived: s.archived) } label: {
                            Label(s.favorite ? "Remove from Favorites" : "Add to Favorites", systemImage: s.favorite ? "star.slash" : "star")
                        }
                    }
                    Button { sharing = true } label: { Label("Share…", systemImage: "square.and.arrow.up") }
                    if canEdit {
                        Button { moving = true } label: { Label("Move to vault…", systemImage: "folder") }
                        Button { model.setFlags(ref, favorite: s.favorite, archived: !s.archived) } label: {
                            Label(s.archived ? "Unarchive" : "Archive", systemImage: "archivebox")
                        }
                        Divider()
                        Button(role: .destructive) { model.delete(ref, title: s.title) } label: { Label("Delete", systemImage: "trash") }
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .accessibilityLabel("More actions")
        }
    }

    private func header(_ d: ItemData) -> some View {
        Section {
            HStack(spacing: 14) {
                Monogram(title: d.title, size: 56)
                VStack(alignment: .leading, spacing: 4) {
                    Text(d.title.isEmpty ? "Untitled" : d.title).font(.title2.bold()).foregroundStyle(Palette.fg)
                    Label("\(vault?.name ?? "") · \(kindName(d.kind))", systemImage: kindIcon(d.kind))
                        .font(.subheadline)
                        .foregroundStyle(Palette.muted)
                }
            }
            .padding(.vertical, 6)
        }
        .listRowBackground(Color.clear)
    }

    private func load() {
        data = try? model.core.item(account: ref.account, vault: ref.vault, id: ref.item)
    }

    private func restore(_ i: Int) {
        Task {
            do {
                try await model.call { [ref] in try $0.restoreVersion(account: ref.account, vault: ref.vault, id: ref.item, index: UInt32(i)) }
                model.reload()
                load()
                model.flash("Version restored")
            } catch { model.show(error) }
        }
    }

    private func attach(_ url: URL) {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        let data: Data
        do { data = try Data(contentsOf: url) } catch { model.show(error); return }
        let name = url.lastPathComponent
        busy = true
        Task {
            defer { busy = false }
            do {
                try await model.call { [ref] in try $0.attachFile(account: ref.account, vault: ref.vault, id: ref.item, name: name, data: data) }
                model.reload()
                load()
                model.flash("Attached \(name)")
            } catch { model.show(error) }
        }
    }

    private func removeFile(_ f: FileData) {
        Task {
            do {
                try await model.call { [ref] in try $0.removeFile(account: ref.account, vault: ref.vault, id: ref.item, file: f.id) }
                model.reload()
                load()
                model.flash("Removed \(f.name)", icon: "trash")
            } catch { model.show(error) }
        }
    }

    private func download(_ f: FileData) {
        Task {
            do {
                let bytes = try await model.call { [ref] in try $0.downloadFile(account: ref.account, vault: ref.vault, id: ref.item, file: f.id) }
                exportFile = ExportFile(name: f.name, data: bytes)
            } catch { model.show(error) }
        }
    }
}

func date(_ ms: UInt64) -> String {
    guard ms > 0 else { return "—" }
    return Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .abbreviated, time: .shortened)
}

func date(seconds: UInt64) -> String {
    Date(timeIntervalSince1970: Double(seconds)).formatted(date: .abbreviated, time: .shortened)
}

struct ExportFile: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    static var writableContentTypes: [UTType] { [.data, .pdf] }
    var name: String
    var data: Data
    init(name: String, data: Data) { (self.name, self.data) = (name, data) }
    init(configuration: ReadConfiguration) throws { (name, data) = ("", configuration.file.regularFileContents ?? Data()) }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

private struct LargeTypeText: Identifiable {
    var text: String
    var id: String { text }
}

/// Label above value. Concealed values show dots with reveal, copy and Large type.
struct FieldRow: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openURL) private var openURL
    let label: String
    let value: String
    let kind: String
    @Binding var largeType: String?
    @State private var revealed = false

    private var secret: Bool { ["concealed", "ssh_key", "card_number"].contains(kind) }
    private var mono: Bool { secret || ["otp", "card_number"].contains(kind) }

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(label).font(.caption).foregroundStyle(Palette.muted)
                Group {
                    if secret && !revealed {
                        Text(String(repeating: "•", count: min(max(value.count, 8), 16))).accessibilityLabel("Hidden")
                    } else if kind == "url" {
                        Text(value).foregroundStyle(Palette.accent)
                    } else {
                        Text(value)
                    }
                }
                .font(mono ? .body.monospaced() : .body)
                .foregroundStyle(Palette.fg)
                .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            if secret {
                Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye") }
                    .accessibilityLabel(revealed ? "Hide \(label)" : "Reveal \(label)")
                Button { largeType = value } label: { Image(systemName: "textformat.size") }
                    .accessibilityLabel("Show \(label) in large type")
            }
            Button { model.copy(value, what: label.prefix(1).uppercased() + label.dropFirst()) } label: { Image(systemName: "doc.on.doc") }
                .accessibilityLabel("Copy \(label)")
        }
        .buttonStyle(.borderless)
        .foregroundStyle(Palette.accent)
        .frame(minHeight: 44)
        .contentShape(Rectangle())
        .onTapGesture {
            if kind == "url", let u = URL(string: value.contains("://") ? value : "https://\(value)") { openURL(u) } else { model.copy(value, what: label.prefix(1).uppercased() + label.dropFirst()) }
        }
        .listRowBackground(Palette.surface)
    }
}

/// The current code with a countdown ring; the next code in the last 5 seconds.
struct TotpRow: View {
    @EnvironmentObject var model: AppModel
    let spec: String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if let c = totpCode(spec: spec) {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("one-time code").font(.caption).foregroundStyle(Palette.muted)
                        Text(grouped(c.code)).font(.title3.monospaced().weight(.semibold)).foregroundStyle(Palette.fg)
                        if c.remaining <= 5 {
                            Text("Next: \(grouped(c.next))").font(.caption.monospaced()).foregroundStyle(Palette.muted)
                        }
                    }
                    Spacer()
                    ZStack {
                        Circle().stroke(Palette.line, lineWidth: 3)
                        Circle()
                            .trim(from: 0, to: CGFloat(c.remaining) / CGFloat(max(c.period, 1)))
                            .stroke(c.remaining <= 5 ? Palette.warn : Palette.accent, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                            .animation(.linear(duration: 1), value: c.remaining)
                        Text("\(c.remaining)").font(.caption2.monospacedDigit()).foregroundStyle(Palette.muted)
                    }
                    .frame(width: 30, height: 30)
                    .accessibilityLabel("\(c.remaining) seconds left")
                    Button { model.copy(c.code, what: "One-time code") } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .foregroundStyle(Palette.accent)
                        .accessibilityLabel("Copy one-time code")
                }
                .frame(minHeight: 52)
                .contentShape(Rectangle())
                .onTapGesture { model.copy(c.code, what: "One-time code") }
            } else {
                FieldRow(label: "one-time code", value: "That one-time code setup isn't valid.", kind: "text", largeType: .constant(nil))
            }
        }
        .listRowBackground(Palette.surface)
    }

    private func grouped(_ s: String) -> String {
        s.count == 6 ? "\(s.prefix(3)) \(s.suffix(3))" : s
    }
}

/// One character per box, alternating tint, digits and symbols colored.
struct LargeType: View {
    let text: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 54), spacing: 6)], spacing: 6) {
                    ForEach(Array(text.enumerated()), id: \.offset) { i, ch in
                        VStack(spacing: 2) {
                            Text(String(ch))
                                .font(.system(size: 34, weight: .medium, design: .monospaced))
                                .foregroundStyle(ch.isNumber ? Palette.accent : (ch.isLetter ? Palette.fg : Palette.warn))
                            Text("\(i + 1)").font(.caption2).foregroundStyle(Palette.muted)
                        }
                        .frame(maxWidth: .infinity, minHeight: 72)
                        .background(i % 2 == 0 ? Palette.surface : Palette.code, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .accessibilityLabel("\(i + 1): \(String(ch))")
                    }
                }
                .padding(16)
            }
            .background(Palette.bg)
            .navigationTitle("Large type")
            .inlineTitle()
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        #if os(macOS)
        .frame(minWidth: 520, minHeight: 320)
        #endif
    }
}

struct MoveSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let ref: ItemRef
    @State private var busy = false

    var body: some View {
        NavigationStack {
            List {
                ForEach(model.accounts, id: \.id) { a in
                    Section(model.accounts.count > 1 ? "\(a.username)@\(a.server.components(separatedBy: "://").last ?? "")" : "") {
                        ForEach(model.vaults.filter { $0.accountId == a.id && $0.role != nil && $0.role != .reader && !($0.accountId == ref.account && $0.id == ref.vault) }, id: \.key) { v in
                            Button { move(to: v) } label: { Label(v.name, systemImage: "folder").foregroundStyle(Palette.fg) }
                        }
                    }
                }
            }
            .disabled(busy)
            .overlay { if busy { ProgressView() } }
            .navigationTitle("Move to vault")
            .inlineTitle()
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        #if os(macOS)
        .frame(width: 400, height: 420)
        #endif
    }

    private func move(to v: VaultInfo) {
        busy = true
        Task {
            defer { busy = false }
            do {
                let id = try await model.call { try $0.moveItem(account: ref.account, vault: ref.vault, id: ref.item, toAccount: v.accountId, toVault: v.id) }
                model.reload()
                model.selection = ItemRef(account: v.accountId, vault: v.id, item: id).id
                model.flash("Moved to \(v.name)")
                dismiss()
            } catch { model.show(error) }
        }
    }
}
