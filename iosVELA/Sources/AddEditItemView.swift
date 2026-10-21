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

    @State private var firstName: String
    @State private var lastName: String
    @State private var ssn: String
    @State private var identityDetails: PreservedJSON

    // note
    @State private var content: String

    // richer fields (vault schema 2)
    @State private var folderID: String
    @State private var tagIDs: [String]
    @State private var customFields: [CustomFieldDraft]
    @State private var extraURLs: [AdditionalURLDraft]
    @State private var confirmEnable = false

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
        _firstName = State(initialValue: editing?.firstName ?? "")
        _lastName = State(initialValue: editing?.lastName ?? "")
        _ssn = State(initialValue: editing?.ssn ?? "")
        _identityDetails = State(initialValue: editing?.identityDetails ?? .object([:]))
        _folderID = State(initialValue: editing?.folderId ?? "")
        _tagIDs = State(initialValue: editing?.tagIds ?? [])
        _customFields = State(initialValue: editing?.customFieldDrafts ?? [])
        _extraURLs = State(initialValue: editing?.additionalURLDrafts ?? [])
    }

    private var isEditing: Bool { editing != nil }

    private var canSave: Bool {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        switch kind {
        case .login: return !password.isEmpty
        case .creditCard: return !number.isEmpty
        case .secureNote: return !content.isEmpty
        case .identity: return true
        default: return isEditing
        }
    }

    @Environment(\.ink) private var ink
    @FocusState private var focus: String?

    /// Return moves through the fields in this order.
    private var fieldOrder: [String] {
        switch kind {
        case .login: return ["nameField", "urlField", "usernameField", "passwordField", "totpField"]
        case .creditCard: return ["nameField", "cardholderField", "cardNumberField", "expField", "cvvField", "pinField"]
        default: return ["nameField", "contentField"]
        }
    }

    private var title: String {
        isEditing ? "Edit \(kind.displayName.lowercased())" : "New \(kind.displayName.lowercased())"
    }

    var body: some View {
        ScrollViewReader { proxy in
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

                EditorField(label: kind == .secureNote ? "Title" : "Name", text: $name, id: "nameField", focus: $focus, chain: fieldOrder)

                Group {
                    switch kind {
                    case .login: loginFields
                    case .creditCard: cardFields
                    case .secureNote: noteFields
                    case .identity:
                        EditorField(label: "First name", text: $firstName, id: "firstNameField", focus: $focus)
                        EditorField(label: "Last name", text: $lastName, id: "lastNameField", focus: $focus)
                        EditorField(label: "SSN", text: $ssn, id: "ssnField", focus: $focus, secret: true)
                        IdentityDetailsEditor(details: $identityDetails)
                    default: EmptyView()
                    }
                }
                .transition(.opacity)

                if kind != .secureNote {
                    EditorField(label: "Notes", text: $notes, id: "notesField", focus: $focus, chain: fieldOrder, multiline: true)
                }

                RichFieldsSection(
                    organization: vm.organization,
                    showWebsites: kind == .login,
                    folderID: $folderID,
                    tagIDs: $tagIDs,
                    customFields: $customFields,
                    extraURLs: $extraURLs,
                    onEnable: { confirmEnable = true }
                )

                if let error = vm.errorMessage {
                    Text(error)
                        .font(InstrumentFont.body(11))
                        .foregroundColor(ink.red)
                        .padding(.top, 16)
                        .accessibilityIdentifier("editorError")
                }

            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 16)
        }
        .scrollIndicators(.hidden)
        .onChange(of: focus) { field in
            guard let field else { return }
            // Wait for the keyboard, then bring the field above it.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                withAnimation(.instrument(0.3)) { proxy.scrollTo(field, anchor: .center) }
            }
        }
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
        }
        .scrollDismissesKeyboard(.interactively)
        .background(ink.bg.ignoresSafeArea())
        .presentationDragIndicator(.hidden)
        .alert("Turn on folders and custom fields?", isPresented: $confirmEnable) {
            Button("Turn on") { enableCollections() }
            Button("Not now", role: .cancel) {}
        } message: {
            Text("This upgrades your vault format. Other devices need an up-to-date VELA to sync changes afterwards.")
        }
        .onAppear { vm.errorMessage = nil }
    }

    @ViewBuilder private var loginFields: some View {
        EditorField(label: "Website", text: $url, id: "urlField", focus: $focus, chain: fieldOrder, keyboard: .URL)
        EditorField(label: "Username or email", text: $username, id: "usernameField", focus: $focus, chain: fieldOrder, keyboard: .emailAddress)
        EditorField(label: "Password", text: $password, id: "passwordField", focus: $focus, chain: fieldOrder, secret: true, mono: true) {
            InstrumentIconButton(icon: .dice, label: "Generate password", size: 36, iconSize: 16, bordered: false, tint: ink.violet) {
                UIImpactFeedbackGenerator(style: .soft).impactOccurred()
                withAnimation(.instrument(0.25)) {
                    password = InstrumentGenerator.password(length: Int(genLength), upper: genUppercase, lower: true,
                                                            numbers: true, symbols: genSymbols)
                }
            }
            .accessibilityIdentifier("generateButton")
        }
        EditorField(label: "Authenticator key (optional)", text: $totp, id: "totpField", focus: $focus, chain: fieldOrder, mono: true)
    }

    @ViewBuilder private var cardFields: some View {
        EditorField(label: "Cardholder name", text: $cardholder, id: "cardholderField", focus: $focus, chain: fieldOrder)
        EditorField(label: "Card number", text: $number, id: "cardNumberField", focus: $focus, chain: fieldOrder, keyboard: .numberPad, mono: true)
        HStack(spacing: 9) {
            EditorField(label: "Expiry (MM/YY)", text: $exp, id: "expField", focus: $focus, chain: fieldOrder, keyboard: .numbersAndPunctuation, mono: true)
            EditorField(label: "Security code", text: $cvv, id: "cvvField", focus: $focus, chain: fieldOrder, keyboard: .numberPad, secret: true, mono: true)
        }
        EditorField(label: "PIN (optional)", text: $pin, id: "pinField", focus: $focus, chain: fieldOrder, keyboard: .numberPad, secret: true, mono: true)
    }

    @ViewBuilder private var noteFields: some View {
        EditorField(label: "Note", text: $content, id: "contentField", focus: $focus, chain: fieldOrder, multiline: true)
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
        case .identity:
            let now = VaultClock.nowISO8601()
            item = VaultItem(firstName: firstName, lastName: lastName, ssn: ssn,
                             item_type: "identity", id: UUID().uuidString, name: trimmedName,
                             notes: trimmedNotes.isEmpty ? nil : trimmedNotes, createdAt: now, updatedAt: now)
            item.identityDetails = identityDetails
        default:
            guard let existing = editing else { return }
            item = existing
            item.name = trimmedName
            item.notes = trimmedNotes.isEmpty ? nil : trimmedNotes
        }

        applyRichFields(to: &item, original: editing)
        if hasRichDraft && !vm.organization.enabled {
            confirmEnable = true
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
            if kind == .identity {
                updated.firstName = item.firstName
                updated.lastName = item.lastName
                updated.ssn = item.ssn
                updated.identityDetails = item.identityDetails
            }
            updated.title = item.title
            updated.content = item.content
            updated.folderId = item.folderId
            updated.tagIds = item.tagIds
            updated.customFields = item.customFields
            if kind == .login { updated.additionalUrls = item.additionalUrls }
            if vm.update(updated) { dismiss() }
        } else {
            if vm.add(item) { dismiss() }
        }
    }

    private var hasRichDraft: Bool {
        !folderID.isEmpty || !tagIDs.isEmpty || !customFields.isEmpty || !extraURLs.isEmpty || (kind == .identity && !(identityDetails.objectValue ?? [:]).isEmpty)
    }

    /// Writes folder, tags, custom fields and other websites. Collections the
    /// item never had stay absent (nil) so older records are not rewritten.
    private func applyRichFields(to item: inout VaultItem, original: VaultItem?) {
        let keptFields = customFields.filter { !$0.isEditable || !$0.label.trimmingCharacters(in: .whitespaces).isEmpty }
        let keptURLs = extraURLs.filter { !$0.url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        if !folderID.isEmpty || original?.folderId != nil { item.folderId = folderID }
        if !tagIDs.isEmpty || original?.tagIds != nil { item.tagIds = tagIDs }
        if !keptFields.isEmpty || original?.customFields != nil { item.customFields = keptFields.map(\.record) }
        if kind == .login, !keptURLs.isEmpty || original?.additionalUrls != nil { item.additionalUrls = keptURLs.map(\.record) }
    }

    private func enableCollections() {
        do {
            try vm.enableCollections()
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } catch {
            vm.errorMessage = error.localizedDescription
        }
    }
}

/// Sheet input: small mono label over a 48pt bordered box; violet when focused.
struct EditorField<Accessory: View>: View {
    let label: String
    @Binding var text: String
    let id: String
    var focus: FocusState<String?>.Binding
    var chain: [String] = []
    var keyboard: UIKeyboardType = .default
    var secret: Bool = false
    var mono: Bool = false
    var multiline: Bool = false
    @ViewBuilder var accessory: () -> Accessory

    @Environment(\.ink) private var ink

    private var focused: Bool { focus.wrappedValue == id }

    private var next: String? {
        guard let index = chain.firstIndex(of: id), index + 1 < chain.count else { return nil }
        return chain[index + 1]
    }

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
                    .focused(focus, equals: id)
                    .submitLabel(next == nil ? .done : .next)
                    .onSubmit { focus.wrappedValue = next }
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
            .contentShape(Rectangle())
            .onTapGesture { focus.wrappedValue = id }
            .animation(.easeOut(duration: 0.18), value: focused)
        }
        .padding(.top, 17)
        .id(id)
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
    init(label: String, text: Binding<String>, id: String, focus: FocusState<String?>.Binding, chain: [String] = [],
         keyboard: UIKeyboardType = .default,
         secret: Bool = false, mono: Bool = false, multiline: Bool = false) {
        self.label = label
        self._text = text
        self.id = id
        self.focus = focus
        self.chain = chain
        self.keyboard = keyboard
        self.secret = secret
        self.mono = mono
        self.multiline = multiline
        self.accessory = { EmptyView() }
    }
}
