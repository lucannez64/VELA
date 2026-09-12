import SwiftUI
import UIKit

struct ItemDetailView: View {
    @ObservedObject var vm: VaultViewModel
    let item: VaultItem

    @Environment(\.dismiss) private var dismiss
    @State private var revealPassword = false
    @State private var revealSecret = false
    @State private var editing = false

    /// Always render the latest copy (so edits reflect immediately).
    private var current: VaultItem { vm.items.first { $0.id == item.id } ?? item }

    var body: some View {
        Form {
            Section {
                HStack(spacing: 16) {
                    FaviconImage(
                        url: current.kind == .login ? current.url : nil,
                        fallback: current.kind.systemImage,
                        size: 64,
                        cornerRadius: 14
                    )
                    VStack(alignment: .leading, spacing: 4) {
                        Text(current.name)
                            .font(.title2.bold())
                        Text(current.kind.displayName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textCase(.uppercase)
                    }
                    Spacer()
                }
                .padding(.vertical, 8)
            }
            .listRowBackground(Color.clear)

            switch current.kind {
            case .login: loginSection
            case .creditCard: cardSection
            case .secureNote: noteSection
            default: genericSection
            }

            if let notes = current.notes, !notes.isEmpty {
                Section("Notes") { Text(notes) }
            }

            // §1.1: where this item lives. Read-only; the Edit sheet owns
            // changing it.
            if current.folder != nil || !current.tagList.isEmpty {
                Section("Organization") {
                    if let folder = current.folder, !folder.isEmpty {
                        HStack {
                            Image(systemName: "folder").foregroundStyle(.secondary)
                            Text(folder)
                        }
                    }
                    if !current.tagList.isEmpty {
                        HStack {
                            ForEach(current.tagList, id: \.self) { tag in
                                Text(tag)
                                    .font(.caption)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 4)
                                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
                            }
                        }
                    }
                }
            }

            // §1.3: user-defined extra fields. Hidden values mask like a
            // password (revealed by tapping the row's copy — CopyButton is
            // deliberate: a hidden field is meant to be pasted, not read).
            if !current.customFieldList.isEmpty {
                Section("Custom Fields") {
                    ForEach(current.customFieldList, id: \.label) { field in
                        if field.isHidden {
                            secretRow(field.label, field.value)
                        } else {
                            copyRow(field.label, field.value)
                        }
                    }
                }
            }

            // §1.3: previous password values, masked; copying one is a
            // deliberate act (CopyButton per row).
            if !current.passwordHistoryList.isEmpty {
                Section("Password History (\(current.passwordHistoryList.count))") {
                    ForEach(Array(current.passwordHistoryList.enumerated()), id: \.offset) { _, entry in
                        secretRow("Replaced \(entry.changedAt.prefix(10))", entry.password)
                    }
                }
            }

            Section {
                Button(role: .destructive) {
                    vm.delete(current)
                    dismiss()
                } label: {
                    Label("Delete", systemImage: "trash")
                }
                .accessibilityIdentifier("deleteButton")
            }
        }
        .navigationTitle(current.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Edit") { editing = true }
                    .accessibilityIdentifier("editButton")
            }
        }
        .sheet(isPresented: $editing) {
            AddEditItemView(vm: vm, editing: current)
        }
    }

    // MARK: - Login

    @ViewBuilder private var loginSection: some View {
        Section("Login") {
            if let url = current.url, !url.isEmpty { copyRow("Website", url) }
            if let username = current.username, !username.isEmpty { copyRow("Username", username) }
            HStack {
                Text("Password").foregroundStyle(.secondary)
                Spacer()
                Text(revealPassword ? (current.password ?? "") : "••••••••").font(.body.monospaced())
                Button { revealPassword.toggle() } label: {
                    Image(systemName: revealPassword ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless).accessibilityIdentifier("revealButton")
                CopyButton(value: current.password ?? "")
            }
        }
        if let totp = current.totp, let generator = TOTP(string: totp) {
            Section("One-time code") { TOTPRow(totp: generator) }
        }
    }

    // MARK: - Card

    @ViewBuilder private var cardSection: some View {
        Section("Card") {
            if let holder = current.cardholderName, !holder.isEmpty { copyRow("Cardholder", holder) }
            HStack {
                Text("Number").foregroundStyle(.secondary)
                Spacer()
                Text(revealPassword ? (current.number ?? "") : current.maskedCardNumber).font(.body.monospaced())
                Button { revealPassword.toggle() } label: {
                    Image(systemName: revealPassword ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless).accessibilityIdentifier("revealButton")
                CopyButton(value: current.number ?? "")
            }
            if let exp = current.exp, !exp.isEmpty { field("Expiry", exp) }
            secretRow("CVV", current.cvv)
            if let pin = current.pin, !pin.isEmpty { secretRow("PIN", pin) }
        }
    }

    // MARK: - Note

    @ViewBuilder private var noteSection: some View {
        Section("Note") {
            Text(current.content ?? "").textSelection(.enabled)
        }
    }

    @ViewBuilder private var genericSection: some View {
        Section(current.kind.displayName) {
            if let email = current.email { field("Email", email) }
            if let filename = current.filename { field("File", filename) }
            // §1.3: the new item types, rendered from their wire fields.
            switch current.kind {
            case .address:
                if let name = current.full_name, !name.isEmpty { field("Name", name) }
                if let street = current.street, !street.isEmpty { field("Street", street) }
                if let city = current.city, !city.isEmpty { field("City", city) }
                if let state = current.state, !state.isEmpty { field("State", state) }
                if let zip = current.postal_code, !zip.isEmpty { field("Postal code", zip) }
                if let country = current.country, !country.isEmpty { field("Country", country) }
                if let phone = current.phone, !phone.isEmpty { copyRow("Phone", phone) }
            case .bankAccount:
                if let bank = current.bank_name, !bank.isEmpty { field("Bank", bank) }
                if let holder = current.holder, !holder.isEmpty { field("Holder", holder) }
                if let routing = current.routing_number, !routing.isEmpty { field("Routing", routing) }
                if let iban = current.iban, !iban.isEmpty { copyRow("IBAN", iban) }
                if let swift = current.swift, !swift.isEmpty { field("SWIFT", swift) }
            case .apiKey:
                if let url = current.url, !url.isEmpty { field("Service", url) }
                if let username = current.username, !username.isEmpty { field("Username", username) }
                if let key = current.api_key, !key.isEmpty { secretRow("API key", key) }
                if let expires = current.expires, !expires.isEmpty { field("Expires", expires) }
            case .sshKey:
                if let kind = current.kind, !kind.isEmpty { field("Key type", kind) }
                if let comment = current.comment, !comment.isEmpty { field("Comment", comment) }
                if let publicKey = current.public_key, !publicKey.isEmpty { copyRow("Public key", publicKey) }
                if let secretKey = current.private_key, !secretKey.isEmpty { secretRow("Private key", secretKey) }
                if let passphrase = current.passphrase, !passphrase.isEmpty { secretRow("Passphrase", passphrase) }
            default:
                EmptyView()
            }
        }
    }

    // MARK: - Rows

    private func field(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing)
        }
    }

    private func copyRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing)
            CopyButton(value: value)
        }
    }

    private func secretRow(_ label: String, _ value: String?) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(revealSecret ? (value ?? "") : "••••").font(.body.monospaced())
            Button { revealSecret.toggle() } label: {
                Image(systemName: revealSecret ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            CopyButton(value: value ?? "")
        }
    }
}

/// Copies a value to the clipboard with an expiration and no Handoff sync, so
/// a copied secret does not persist on the system clipboard or sync to the
/// user's other devices. Shared by `CopyButton` here and the user ID copy in
/// SettingsView.
enum Clipboard {
    static func copySecurely(_ value: String) {
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(20)]
        )
    }
}

/// Copies a value to the clipboard with brief feedback.
private struct CopyButton: View {
    let value: String
    @State private var copied = false

    var body: some View {
        Button {
            Clipboard.copySecurely(value)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { copied = false }
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
        }
        .buttonStyle(.borderless)
        .foregroundStyle(copied ? .green : .accentColor)
    }
}

/// Live RFC-6238 code with a countdown that refreshes every second.
private struct TOTPRow: View {
    let totp: TOTP

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = totp.code(at: context.date)
            let remaining = totp.secondsRemaining(at: context.date)
            HStack {
                Text(formatted(code)).font(.title3.monospaced().bold())
                Spacer()
                Text("\(remaining)s").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                CopyButton(value: code)
            }
        }
    }

    private func formatted(_ code: String) -> String {
        guard code.count == 6 else { return code }
        let mid = code.index(code.startIndex, offsetBy: 3)
        return code[..<mid] + " " + code[mid...]
    }
}
