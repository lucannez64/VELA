import SwiftUI

/// Shown when a vault exists on the device but the session is locked. Tapping
/// "Unlock" runs Face ID / Touch ID (Phase 2) and decrypts the vault.
struct UnlockView: View {
    @ObservedObject var vm: VaultViewModel
    @State private var password = ""

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: vm.unlockMode == .password ? "lock.fill" : "faceid")
                    .font(.system(size: 72))
                    .foregroundStyle(.green)
                Text("VELA")
                    .font(.system(size: 40, weight: .bold))
                    .foregroundStyle(.white)
                Text("Vault locked")
                    .font(.headline)
                    .foregroundStyle(.white.opacity(0.7))
                Spacer()
                if let error = vm.errorMessage {
                    Text(error).font(.callout).foregroundStyle(.red)
                }
                if vm.unlockMode == .password {
                    passwordControls
                } else {
                    biometricButton
                }
            }
        }
    }

    private var biometricButton: some View {
        Button {
            vm.unlock()
        } label: {
            Label("Unlock with Face ID", systemImage: "lock.open.fill")
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
        }
        .background(.green)
        .foregroundStyle(.black)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .accessibilityIdentifier("unlockButton")
        .padding(.horizontal, 32)
        .padding(.bottom, 40)
    }

    private var passwordControls: some View {
        VStack(spacing: 14) {
            SecureField("Password", text: $password)
                .textContentType(.password)
                .padding()
                .background(.white.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .foregroundStyle(.white)
                .accessibilityIdentifier("unlockPasswordField")
                .onSubmit { vm.unlock(password: password) }
            Button {
                vm.unlock(password: password)
            } label: {
                Text("Unlock")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
            }
            .background(.green)
            .foregroundStyle(.black)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .disabled(password.isEmpty)
            .accessibilityIdentifier("unlockButton")
        }
        .padding(.horizontal, 32)
        .padding(.bottom, 40)
    }
}
