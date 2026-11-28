import SwiftUI

/// Add or edit an item: kind picker for new ones, built-in fields, sections,
/// the inline generator. Save is always visible; unsaved changes prompt.
struct ItemEditor: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let request: EditorRequest
    @State private var d: ItemData
    @State private var original: ItemData
    @State private var account: String
    @State private var vault: String
    @State private var pickingKind: Bool
    @State private var confirmDiscard = false
    @State private var scanning = false
    @State private var busy = false
    @State private var tagText: String
    @State private var reveal = true

    init(request: EditorRequest) {
        self.request = request
        _d = State(initialValue: request.data)
        _original = State(initialValue: request.data)
        _account = State(initialValue: request.account)
        _vault = State(initialValue: request.vault)
        _pickingKind = State(initialValue: request.item == nil)
        _tagText = State(initialValue: request.data.tags.joined(separator: ", "))
        _reveal = State(initialValue: request.item == nil)
    }

    private var dirty: Bool { d != original || tagText != original.tags.joined(separator: ", ") }
    private var hasLogin: Bool { ["login", "password"].contains(d.kind) || !d.username.isEmpty || !d.password.isEmpty }

    var body: some View {
        NavigationStack {
            Group {
                if pickingKind { KindPicker { kind in choose(kind) } } else { form }
            }
            .navigationTitle(request.item == nil ? "New \(kindName(d.kind))" : "Edit")
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { if dirty && !pickingKind { confirmDiscard = true } else { dismiss() } }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save).disabled(pickingKind || busy || d.title.trimmingCharacters(in: .whitespaces).isEmpty).keyboardShortcut("s")
                }
            }
            .confirmationDialog("Discard your changes?", isPresented: $confirmDiscard, titleVisibility: .visible) {
                Button("Discard changes", role: .destructive) { dismiss() }
                Button("Keep editing", role: .cancel) {}
            }
        }
        .interactiveDismissDisabled(dirty)
        .sheet(isPresented: $scanning) {
            CodeScanner(title: "Add a one-time code", prompt: "Scan the QR code the website shows when you turn on two-factor authentication.") { code in
                guard totpCode(spec: code) != nil else { return "That isn't a one-time code setup." }
                d.totp = code
                return nil
            }
        }
    }

    private var form: some View {
        Form {
            Section {
                TextField("Title", text: $d.title).font(.title3.weight(.semibold))
                if request.item == nil {
                    Picker("Vault", selection: Binding(get: { "\(account)/\(vault)" }, set: { v in
                        let p = v.split(separator: "/").map(String.init)
                        (account, vault) = (p[0], p[1])
                    })) {
                        ForEach(model.vaults.filter { $0.role != nil && $0.role != .reader }, id: \.key) { v in
                            Text(model.accounts.count > 1 ? "\(v.name) (\(model.account(v.accountId)?.username ?? ""))" : v.name).tag(v.key)
                        }
                    }
                }
            }
            if hasLogin {
                Section {
                    TextField("Username", text: $d.username).plainInput().textContentType(.username)
                    PasswordEditor(password: $d.password, reveal: $reveal)
                }
                Section("Websites") {
                    ForEach(d.urls.indices, id: \.self) { i in
                        HStack {
                            TextField("https://example.com", text: $d.urls.element(i, or: "")).plainInput().urlKeyboard()
                            Button { d.urls.remove(at: i) } label: { Image(systemName: "minus.circle.fill").foregroundStyle(Palette.danger) }
                                .buttonStyle(.borderless)
                                .accessibilityLabel("Remove website")
                        }
                    }
                    Button { d.urls.append("") } label: { Label("Add website", systemImage: "plus") }
                }
                Section("One-time code") {
                    TextField("Paste an otpauth:// link or the setup key", text: $d.totp).plainInput().font(.body.monospaced())
                    if !d.totp.isEmpty && totpCode(spec: d.totp) == nil { Note(text: "That isn't a valid one-time code setup.") }
                    Button { scanning = true } label: { Label("Scan QR code", systemImage: "qrcode.viewfinder") }
                }
            }
            ForEach(d.sections.indices, id: \.self) { si in
                Section {
                    TextField("Section name", text: $d.sections[si].title).font(.subheadline.weight(.semibold))
                    ForEach(d.sections[si].fields.indices, id: \.self) { fi in
                        FieldEditor(field: $d.sections[si].fields.element(fi, or: FieldData(label: "", kind: "text", value: "", extraJson: ""))) { d.sections[si].fields.remove(at: fi) }
                    }
                    .onMove { d.sections[si].fields.move(fromOffsets: $0, toOffset: $1) }
                    Menu {
                        ForEach(FieldEditor.kinds, id: \.0) { k in
                            Button(k.1) { d.sections[si].fields.append(FieldData(label: k.1, kind: k.0, value: "", extraJson: "")) }
                        }
                    } label: { Label("Add field", systemImage: "plus") }
                }
            }
            Section {
                Button { d.sections.append(SectionData(title: "", fields: [FieldData(label: "Label", kind: "text", value: "", extraJson: "")])) } label: {
                    Label("Add section", systemImage: "rectangle.stack.badge.plus")
                }
            }
            Section("Notes") {
                TextEditor(text: $d.notes).frame(minHeight: 100).font(.body)
            }
            Section("Tags") {
                TextField("work, finance", text: $tagText).plainInput()
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(Palette.bg)
    }

    private func choose(_ kind: String) {
        let title = d.title
        d = itemTemplate(kind: kind)
        d.title = title
        if kind == "login" || kind == "password" {
            d.password = generatePassword(recipe: .random(length: 20, digits: true, symbols: true))
        }
        original = d
        withAnimation { pickingKind = false }
    }

    private func save() {
        var data = d
        data.tags = tagText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        data.title = data.title.trimmingCharacters(in: .whitespaces)
        busy = true
        let (a, v, id) = (account, vault, request.item)
        Task {
            defer { busy = false }
            do {
                let newId = try await model.call { try $0.putItem(account: a, vault: v, id: id, item: data) }
                model.reload()
                model.selection = ItemRef(account: a, vault: v, item: newId).id
                model.flash("Saved")
                dismiss()
            } catch { model.show(error) }
        }
    }
}

/// Typing a title right away makes a login; otherwise pick a kind.
struct KindPicker: View {
    let pick: (String) -> Void

    var body: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 104), spacing: 12)], spacing: 12) {
                ForEach(itemKinds(), id: \.id) { k in
                    Button { pick(k.id) } label: {
                        VStack(spacing: 8) {
                            Image(systemName: kindIcon(k.id)).font(.title2).foregroundStyle(Palette.accent)
                            Text(k.name).font(.footnote.weight(.medium)).foregroundStyle(Palette.fg).multilineTextAlignment(.center).lineLimit(2)
                        }
                        .frame(maxWidth: .infinity, minHeight: 92)
                        .background(Palette.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(k.id == "login" ? Palette.accent : Palette.line))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(16)
        }
        .background(Palette.bg)
    }
}

/// The password field with the generator inline.
struct PasswordEditor: View {
    @Binding var password: String
    @Binding var reveal: Bool
    @State private var showOptions = false
    @AppStorage("gen.mode") private var mode = 0
    @AppStorage("gen.length") private var length = 20.0
    @AppStorage("gen.words") private var words = 4.0
    @AppStorage("gen.digits") private var digits = true
    @AppStorage("gen.symbols") private var symbols = true

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Group {
                    if reveal { TextField("Password", text: $password) } else { SecureField("Password", text: $password) }
                }
                .plainInput()
                .font(.body.monospaced())
                Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                    .accessibilityLabel(reveal ? "Hide password" : "Show password")
                Button(action: generate) { Image(systemName: "arrow.clockwise") }
                    .accessibilityLabel("Generate a new password")
                Button { withAnimation { showOptions.toggle() } } label: { Image(systemName: "slider.horizontal.3") }
                    .accessibilityLabel("Generator options")
            }
            .buttonStyle(.borderless)
            StrengthMeter(password: password)
            if showOptions {
                Picker("Kind", selection: $mode) {
                    Text("Random").tag(0)
                    Text("Words").tag(1)
                    Text("PIN").tag(2)
                }
                .pickerStyle(.segmented)
                .onChange(of: mode) { _, _ in generate() }
                if mode == 1 {
                    Stepper("\(Int(words)) words", value: $words, in: 3...10).onChange(of: words) { _, _ in generate() }
                } else {
                    HStack {
                        Text("Length \(Int(length))").monospacedDigit().frame(width: 96, alignment: .leading)
                        Slider(value: $length, in: mode == 2 ? 4...12 : 8...64, step: 1).onChange(of: length) { _, _ in generate() }
                    }
                }
                if mode == 0 {
                    Toggle("Digits", isOn: $digits).onChange(of: digits) { _, _ in generate() }
                    Toggle("Symbols", isOn: $symbols).onChange(of: symbols) { _, _ in generate() }
                }
            }
        }
    }

    private func generate() {
        let recipe: Recipe
        switch mode {
        case 1: recipe = .memorable(words: UInt32(words), separator: "-", capitalize: true)
        case 2: recipe = .pin(length: UInt32(min(length, 12)))
        default: recipe = .random(length: UInt32(length), digits: digits, symbols: symbols)
        }
        password = generatePassword(recipe: recipe)
        reveal = true
    }
}

struct FieldEditor: View {
    @Binding var field: FieldData
    let remove: () -> Void
    @State private var reveal = false

    static let kinds: [(String, String)] = [
        ("text", "Text"), ("concealed", "Password"), ("email", "Email"), ("url", "URL"), ("phone", "Phone"), ("date", "Date"),
        ("month_year", "Month and year"), ("address", "Address"), ("otp", "One-time code"), ("card_number", "Card number"), ("ssh_key", "SSH key"),
    ]

    private var secret: Bool { ["concealed", "ssh_key"].contains(field.kind) }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("Label", text: $field.label).font(.caption).foregroundStyle(Palette.muted)
                Menu {
                    Picker("Type", selection: $field.kind) {
                        ForEach(Self.kinds, id: \.0) { Text($0.1).tag($0.0) }
                        if !Self.kinds.contains(where: { $0.0 == field.kind }) { Text(field.kind).tag(field.kind) }
                    }
                    Button(role: .destructive, action: remove) { Label("Remove field", systemImage: "trash") }
                } label: {
                    Image(systemName: "ellipsis.circle").foregroundStyle(Palette.muted)
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .accessibilityLabel("Field options")
            }
            HStack {
                Group {
                    if secret && !reveal {
                        SecureField("Value", text: $field.value)
                    } else if field.kind == "ssh_key" || field.kind == "address" {
                        TextField("Value", text: $field.value, axis: .vertical)
                    } else {
                        TextField("Value", text: $field.value)
                    }
                }
                .plainInput()
                .font(secret || field.kind == "card_number" ? .body.monospaced() : .body)
                if secret {
                    Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(reveal ? "Hide" : "Reveal")
                }
            }
        }
    }
}

extension Binding {
    /// One element of an array, safe to read after it's removed: a row that
    /// SwiftUI is still tearing down reads its old index once more.
    func element<E>(_ i: Int, or fallback: E) -> Binding<E> where Value == [E] {
        Binding<E>(get: { i < wrappedValue.count ? wrappedValue[i] : fallback }, set: { if i < wrappedValue.count { wrappedValue[i] = $0 } })
    }
}
