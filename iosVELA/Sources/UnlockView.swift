import SwiftUI

/// Shown when a vault exists on the device but the session is locked. Tapping
/// "Unlock" runs Face ID / Touch ID (Phase 2) and decrypts the vault.
struct UnlockView: View {
    @ObservedObject var vm: VaultViewModel

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: "faceid")
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
        }
    }
}
