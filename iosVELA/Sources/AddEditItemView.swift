import SwiftUI

/// Create or edit a vault item (login / card / note), with a password generator
/// for logins. The type picker is shown only when creating.
struct AddEditItemView: View {
    @ObservedObject var vm: VaultViewModel
    @Environment(\.dismiss) private var dismiss

    private let editing: VaultItem?

    @State private var kind: ItemKind
    @State private var name: String
    @State private var notes: String

    // login
    @State private var url: String
    @State private var username: String
    @State private var password: String
    @State private var totp: String
    @State private var genLength = 20.0
    @State private var genUppercase = true
    @State private var genSymbols = true

    // card
    @State private var cardholder: String
    @State private var number: String
    @State private var exp: String
    @State private var cvv: String
    @State private var pin: String

    // note
    @State private var content: String

    init(vm: VaultViewModel, editing: VaultItem? = nil) {
        self.vm = vm
        self.editing = editing
        _kind = State(initialValue: editing?.kind ?? .login)
        _name = State(initialValue: editing?.name ?? "")
        _notes = State(initialValue: editing?.notes ?? "")
        _url = State(initialValue: editing?.url ?? "")
        _username = State(initialValue: editing?.username ?? "")
        _password = State(initialValue: editing?.password ?? "")
        _totp = State(initialValue: editing?.totp ?? "")
        _cardholder = State(initialValue: editing?.cardholderName ?? "")
        _number = State(initialValue: editing?.number ?? "")
        _exp = State(initialValue: editing?.exp ?? "")
        _cvv = State(initialValue: editing?.cvv ?? "")
        _pin = State(initialValue: editing?.pin ?? "")
        _content = State(initialValue: editing?.content ?? "")
    }

    private var isEditing: Bool { editing != nil }

    private var canSave: Bool {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        switch kind {
        case .login: return !password.isEmpty
        case .creditCard: return !number.isEmpty
        case .secureNote: return !content.isEmpty
        default: return false
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                if !isEditing {
                    Section {
                        Picker("Type", selection: $kind) {
                            ForEach(ItemKind.creatable) { Text($0.displayName).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .accessibilityIdentifier("typePicker")
                    }
                }

                Section(kind == .secureNote ? "Note" : "Details") {
                    TextField(kind == .secureNote ? "Title" : "Name", text: $name)
                        .accessibilityIdentifier("nameField")
                    switch kind {
                    case .login: loginFields
                    case .creditCard: cardFields
                    case .secureNote: noteFields
                    default: EmptyView()
                    }
                }

                if kind == .login { generatorSection }

                if kind != .secureNote {
                    Section("Notes") {
                        TextField("Notes", text: $notes, axis: .vertical)
                            .accessibilityIdentifier("notesField")
                    }
                }
            }
            .navigationTitle(isEditing ? "Edit \(kind.displayName.lowercased())" : "Add \(kind.displayName.lowercased())")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .accessibilityIdentifier("cancelButton")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .accessibilityIdentifier("saveButton")
                        .disabled(!canSave)
                }
            }
        }
    }

    @ViewBuilder private var loginFields: some View {
        TextField("Website", text: $url)
            .keyboardType(.URL).textInputAutocapitalization(.never)
            .accessibilityIdentifier("urlField")
        TextField("Username or email", text: $username)
            .textInputAutocapitalization(.never)
            .accessibilityIdentifier("usernameField")
        SecureField("Password", text: $password)
            .accessibilityIdentifier("passwordField")
        TextField("TOTP secret (Base32 or otpauth://)", text: $totp)
            .textInputAutocapitalization(.never)
            .accessibilityIdentifier("totpField")
    }

    @ViewBuilder private var cardFields: some View {
        TextField("Cardholder name", text: $cardholder)
            .accessibilityIdentifier("cardholderField")
        TextField("Card number", text: $number)
            .keyboardType(.numberPad).font(.body.monospaced())
            .accessibilityIdentifier("cardNumberField")
        TextField("Expiry (MM/YY)", text: $exp)
            .accessibilityIdentifier("expField")
        SecureField("CVV", text: $cvv)
            .keyboardType(.numberPad)
            .accessibilityIdentifier("cvvField")
        SecureField("PIN (optional)", text: $pin)
            .keyboardType(.numberPad)
            .accessibilityIdentifier("pinField")
    }

    @ViewBuilder private var noteFields: some View {
        TextField("Content", text: $content, axis: .vertical)
            .lineLimit(4...12)
            .accessibilityIdentifier("contentField")
    }

    private var generatorSection: some View {
        Section("Password generator") {
            HStack {
                Text("Length")
                Spacer()
                Text("\(Int(genLength))").monospacedDigit().foregroundStyle(.secondary)
            }
            Slider(value: $genLength, in: 8...64, step: 1)
            Toggle("Uppercase", isOn: $genUppercase)
            Toggle("Symbols", isOn: $genSymbols)
            Button("Generate password") {
                password = PasswordGenerator.generate(length: Int(genLength), uppercase: genUppercase, symbols: genSymbols)
            }
            .accessibilityIdentifier("generateButton")
        }
    }

    private func save() {
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedNotes = notes.trimmingCharacters(in: .whitespaces)
        var item: VaultItem

        switch kind {
        case .login:
            item = VaultItem.newLogin(name: trimmedName, url: url.trimmingCharacters(in: .whitespaces),
                                      username: username.trimmingCharacters(in: .whitespaces),
                                      password: password, totp: totp)
            item.notes = trimmedNotes.isEmpty ? nil : trimmedNotes
        case .creditCard:
            item = VaultItem.newCard(name: trimmedName, number: number.trimmingCharacters(in: .whitespaces),
                                     exp: exp.trimmingCharacters(in: .whitespaces), cvv: cvv,
                                     pin: pin, cardholderName: cardholder,
                                     notes: trimmedNotes.isEmpty ? nil : trimmedNotes)
        case .secureNote:
            item = VaultItem.newNote(name: trimmedName, content: content)
        default:
            return
        }

        if let editing = editing {
            // Preserve identity/meta of the edited item.
            item.id = editing.id
            item.createdAt = editing.createdAt
            item.favorite = editing.favorite
            item.shared = editing.shared
            item.shareRecipient = editing.shareRecipient
            vm.update(item)
        } else {
            vm.add(item)
        }
        dismiss()
    }
}
