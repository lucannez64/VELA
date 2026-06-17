import SwiftUI

struct AddItemView: View {
    @ObservedObject var vm: VaultViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var url = ""
    @State private var username = ""
    @State private var password = ""
    @State private var totp = ""

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Login") {
                    TextField("Name", text: $name)
                        .accessibilityIdentifier("nameField")
                    TextField("Website", text: $url)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("urlField")
                    TextField("Username or email", text: $username)
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("usernameField")
                    SecureField("Password", text: $password)
                        .accessibilityIdentifier("passwordField")
                }
                Section("Two-factor (optional)") {
                    TextField("TOTP secret", text: $totp)
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("totpField")
                }
            }
            .navigationTitle("Add login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .accessibilityIdentifier("cancelButton")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        vm.addLogin(
                            name: name.trimmingCharacters(in: .whitespaces),
                            url: url.trimmingCharacters(in: .whitespaces),
                            username: username.trimmingCharacters(in: .whitespaces),
                            password: password,
                            totp: totp
                        )
                        dismiss()
                    }
                    .accessibilityIdentifier("saveButton")
                    .disabled(!canSave)
                }
            }
        }
    }
}
