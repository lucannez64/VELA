import SwiftUI
import UIKit

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

    init(vm: VaultViewModel, editing: VaultItem? = nil, prefillPassword: String? = nil) {
        self.vm = vm
        self.editing = editing
        _kind = State(initialValue: editing?.kind ?? .login)
        _name = State(initialValue: editing?.name ?? "")
        _notes = State(initialValue: editing?.notes ?? "")
        _url = State(initialValue: editing?.url ?? "")
        _username = State(initialValue: editing?.username ?? "")
        _password = State(initialValue: editing?.password ?? prefillPassword ?? "")
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

    @Environment(\.ink) private var ink

    private var title: String {
        isEditing ? "Edit \(kind.displayName.lowercased())" : "New \(kind.displayName.lowercased())"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Capsule().fill(ink.faint.opacity(0.5)).frame(width: 32, height: 4)
                    .frame(maxWidth: .infinity)
                    .padding(.bottom, 14)
                HStack {
                    Text(title)
                        .font(InstrumentFont.display(22))
                        .tracking(-0.6)
                        .foregroundColor(ink.text)
                        .animation(nil, value: kind)
                    Spacer()
                    InstrumentIconButton(icon: .x, label: "Cancel", iconSize: 17) { dismiss() }
                        .accessibilityIdentifier("cancelButton")
                }
                .padding(.bottom, 14)

                if !isEditing {
                    HStack(spacing: 6) {
                        ForEach(ItemKind.creatable) { option in
                            InstrumentChip(text: option.displayName, selected: kind == option) {
                                withAnimation(.instrument(0.3)) { kind = option }
                            }
                        }
                    }
                    .accessibilityIdentifier("typePicker")
                    .padding(.bottom, 4)
                }

                EditorField(label: kind == .secureNote ? "Title" : "Name", text: $name, id: "nameField")

                Group {
                    switch kind {
                    case .login: loginFields
                    case .creditCard: cardFields
                    case .secureNote: noteFields
                    default: EmptyView()
                    }
                }
                .transition(.opacity)

                if kind != .secureNote {
                    EditorField(label: "Notes", text: $notes, id: "notesField", multiline: true)
                }

            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 16)
        }
        .scrollIndicators(.hidden)
        // Sticky save bar: rides above the keyboard so it is always reachable.
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 10) {
                InstrumentPill(text: isEditing ? "Save changes" : "Save item", icon: .check, style: .primary,
                               fullWidth: true, enabled: canSave) { save() }
                    .accessibilityIdentifier("saveButton")
                FineText("Encrypted on this device before it syncs.", size: 9)
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 10)
            .frame(maxWidth: .infinity)
            .background(ink.bg.opacity(0.96).ignoresSafeArea())
            .overlay(Rectangle().fill(ink.line).frame(height: 1), alignment: .top)
        }
        .scrollDismissesKeyboard(.interactively)
        .background(ink.bg.ignoresSafeArea())
        .presentationDragIndicator(.hidden)
    }

    @ViewBuilder private var loginFields: some View {
        EditorField(label: "Website", text: $url, id: "urlField", keyboard: .URL)
        EditorField(label: "Username or email", text: $username, id: "usernameField", keyboard: .emailAddress)
        EditorField(label: "Password", text: $password, id: "passwordField", secret: true, mono: true) {
            InstrumentIconButton(icon: .dice, label: "Generate password", size: 36, iconSize: 16, bordered: false, tint: ink.violet) {
                UIImpactFeedbackGenerator(style: .soft).impactOccurred()
                withAnimation(.instrument(0.25)) {
                    password = InstrumentGenerator.password(length: Int(genLength), upper: genUppercase, lower: true,
                                                            numbers: true, symbols: genSymbols)
                }
            }
            .accessibilityIdentifier("generateButton")
        }
        EditorField(label: "Authenticator key (optional)", text: $totp, id: "totpField", mono: true)
    }

    @ViewBuilder private var cardFields: some View {
        EditorField(label: "Cardholder name", text: $cardholder, id: "cardholderField")
        EditorField(label: "Card number", text: $number, id: "cardNumberField", keyboard: .numberPad, mono: true)
        HStack(spacing: 9) {
            EditorField(label: "Expiry (MM/YY)", text: $exp, id: "expField", keyboard: .numbersAndPunctuation, mono: true)
            EditorField(label: "Security code", text: $cvv, id: "cvvField", keyboard: .numberPad, secret: true, mono: true)
        }
        EditorField(label: "PIN (optional)", text: $pin, id: "pinField", keyboard: .numberPad, secret: true, mono: true)
    }

    @ViewBuilder private var noteFields: some View {
        EditorField(label: "Note", text: $content, id: "contentField", multiline: true)
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
            // Start from the stored item so fields this form doesn't show
            // (app links, folders, tags, custom fields) survive the edit.
            var updated = editing
            updated.name = item.name
            updated.notes = item.notes
            updated.url = item.url
            updated.username = item.username
            updated.password = item.password
            updated.totp = item.totp
            updated.number = item.number
            updated.exp = item.exp
            updated.cvv = item.cvv
            updated.pin = item.pin
            updated.cardholderName = item.cardholderName
            updated.title = item.title
            updated.content = item.content
            vm.update(updated)
        } else {
            vm.add(item)
        }
        dismiss()
    }
}

/// Sheet input: small mono label over a 48pt bordered box; violet when focused.
struct EditorField<Accessory: View>: View {
    let label: String
    @Binding var text: String
    let id: String
    var keyboard: UIKeyboardType = .default
    var secret: Bool = false
    var mono: Bool = false
    var multiline: Bool = false
    @ViewBuilder var accessory: () -> Accessory

    @Environment(\.ink) private var ink
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            MonoLabel(label)
            HStack(spacing: 4) {
                input
                    .font(mono ? InstrumentFont.mono(12) : InstrumentFont.body(12))
                    .foregroundColor(ink.text)
                    .tint(ink.violet)
                    .keyboardType(keyboard)
                    .textInputAutocapitalization(keyboard == .default && !secret && !mono ? TextInputAutocapitalization.sentences : TextInputAutocapitalization.never)
                    .disableAutocorrection(secret || mono || keyboard != .default)
                    .focused($focused)
                    .accessibilityLabel(label)
                    .accessibilityIdentifier(id)
                accessory()
            }
            .padding(.leading, 12)
            .padding(.trailing, 4)
            .padding(.vertical, multiline ? 12 : 0)
            .frame(minHeight: 48)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(ink.panel))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(focused ? ink.violet : ink.line2, lineWidth: 1))
            .animation(.easeOut(duration: 0.18), value: focused)
        }
        .padding(.top, 17)
    }

    @ViewBuilder private var input: some View {
        if secret {
            SecureField("", text: $text)
        } else if multiline {
            TextField("", text: $text, axis: .vertical).lineLimit(3...10)
        } else {
            TextField("", text: $text)
        }
    }
}

extension EditorField where Accessory == EmptyView {
    init(label: String, text: Binding<String>, id: String, keyboard: UIKeyboardType = .default,
         secret: Bool = false, mono: Bool = false, multiline: Bool = false) {
        self.label = label
        self._text = text
        self.id = id
        self.keyboard = keyboard
        self.secret = secret
        self.mono = mono
        self.multiline = multiline
        self.accessory = { EmptyView() }
    }
}
