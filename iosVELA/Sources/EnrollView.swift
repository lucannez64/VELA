import SwiftUI

/// Join an existing vault on this device using an enrollment code from a primary
/// device (the joining side of device enrollment). Mirrors Android's EnrollDevice.
struct EnrollView: View {
    @ObservedObject var vault: VaultViewModel
    @ObservedObject var account: AccountViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var serverURL = "https://vault.klyt.eu"
    @State private var code = ""
    @State private var usePassword = false
    @State private var password = ""
    @State private var confirm = ""

    private var canJoin: Bool {
        guard !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        if usePassword { return password.count >= 8 && password == confirm }
        return true
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("Server URL", text: $serverURL)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .accessibilityIdentifier("enrollServerField")
                }
                Section("Enrollment code") {
                    TextField("Paste the code from your other device", text: $code, axis: .vertical)
                        .lineLimit(2...5)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("enrollCodeField")
                }
                Section("Secure on this device") {
                    Toggle("Protect with password", isOn: $usePassword)
                    if usePassword {
                        SecureField("Password (8+)", text: $password)
                            .accessibilityIdentifier("enrollPasswordField")
                        SecureField("Confirm password", text: $confirm)
                    } else {
                        Text("This device will unlock with Face ID / Touch ID.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section {
                    Button("Join") {
                        account.joinWithCode(
                            serverURL: serverURL, code: code,
                            secure: usePassword ? .password : .biometric,
                            password: usePassword ? password : nil)
                    }
                    .disabled(!canJoin || account.busy)
                    .accessibilityIdentifier("joinButton")
                }
                if !account.status.isEmpty {
                    Section { Text(account.status).font(.callout).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Join device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onChange(of: vault.lockState) { state in
                if state == .unlocked { dismiss() } // joined successfully
            }
        }
        .preferredColorScheme(.dark)
    }
}
