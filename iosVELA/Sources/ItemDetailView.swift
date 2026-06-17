import SwiftUI

struct ItemDetailView: View {
    @ObservedObject var vm: VaultViewModel
    let item: VaultItem

    @Environment(\.dismiss) private var dismiss
    @State private var revealPassword = false

    var body: some View {
        Form {
            Section("Login") {
                field("Website", item.url)
                field("Username", item.username)
                HStack {
                    Text("Password").foregroundStyle(.secondary)
                    Spacer()
                    Text(revealPassword ? item.password : "••••••••")
                        .font(.body.monospaced())
                    Button {
                        revealPassword.toggle()
                    } label: {
                        Image(systemName: revealPassword ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("revealButton")
                }
                if let totp = item.totp, !totp.isEmpty {
                    field("TOTP", totp)
                }
            }
            Section {
                Button(role: .destructive) {
                    vm.delete(item)
                    dismiss()
                } label: {
                    Label("Delete", systemImage: "trash")
                }
                .accessibilityIdentifier("deleteButton")
            }
        }
        .navigationTitle(item.name)
        .navigationBarTitleDisplayMode(.inline)
    }

    private func field(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing)
        }
    }
}
