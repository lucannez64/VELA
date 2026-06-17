import SwiftUI

struct WelcomeView: View {
    @ObservedObject var vm: VaultViewModel

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
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
            }
        }
    }
}
