import SwiftUI

struct WelcomeView: View {
    @ObservedObject var vm: VaultViewModel
    @ObservedObject var accountVM: AccountViewModel
    @State private var showingPassword = false
    @State private var showingEnroll = false
    @State private var showingRecover = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 72))
                    .foregroundStyle(.green)
                Text("VELA")
                    .font(.system(size: 40, weight: .bold))
                    .foregroundStyle(.white)
                Text("Your vault. No passwords.")
                    .font(.headline)
                    .foregroundStyle(.white.opacity(0.7))
                Label("Post-quantum · Zero-knowledge", systemImage: "checkmark.seal.fill")
                    .font(.subheadline)
                    .foregroundStyle(.green)
                Spacer()
                if let error = vm.errorMessage {
                    Text(error).font(.callout).foregroundStyle(.red)
                }
                Text("core \(VelaCoreFFI.version())")
                    .font(.caption.monospaced())
                    .foregroundStyle(.white.opacity(0.4))
                Button {
                    try? vm.createVault()
                } label: {
                    Text("Create new vault")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                }
                .background(.green)
                .foregroundStyle(.black)
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .accessibilityIdentifier("createVaultButton")
                .padding(.horizontal, 32)

                Button("Use a password instead") { showingPassword = true }
                    .font(.subheadline)
                    .foregroundStyle(.green)
                    .accessibilityIdentifier("createWithPasswordButton")

                Button("Join with an enrollment code") { showingEnroll = true }
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.7))
                    .accessibilityIdentifier("joinWithCodeButton")

                Button("Recover my account") { showingRecover = true }
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.7))
                    .accessibilityIdentifier("recoverAccountLink")
                    .padding(.bottom, 40)
            }
        }
        .sheet(isPresented: $showingPassword) {
            CreatePasswordView(vm: vm)
        }
        .sheet(isPresented: $showingEnroll) {
            EnrollView(vault: vm, account: accountVM)
        }
        .sheet(isPresented: $showingRecover) {
            RecoverAccountView(vault: vm, account: accountVM)
        }
    }
}

/// Sheet to create a password-protected vault.
private struct CreatePasswordView: View {
    @ObservedObject var vm: VaultViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirm = ""

    private var canCreate: Bool { password.count >= 8 && password == confirm }

    var body: some View {
        NavigationStack {
            Form {
                Section("Password") {
                    SecureField("Password (8+ chars)", text: $password)
                        .textContentType(.newPassword)
                        .accessibilityIdentifier("newPasswordField")
                    SecureField("Confirm password", text: $confirm)
                        .textContentType(.newPassword)
                        .accessibilityIdentifier("confirmPasswordField")
                }
                Section {
                    Text("Your vault is encrypted with this password. It can't be recovered if you forget it — set up recovery in Settings after creating.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Password vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        try? vm.createVault(password: password)
                        dismiss()
                    }
                    .disabled(!canCreate)
                    .accessibilityIdentifier("createPasswordVaultButton")
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
