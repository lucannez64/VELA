import SwiftUI

struct ContentView: View {
    @State private var coreVersion = VelaCoreFFI.version()
    @State private var status = "Tap to verify the secure core"

    var body: some View {
        NavigationStack {
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

                    VStack(spacing: 8) {
                        Text(status)
                            .font(.callout)
                            .foregroundStyle(.white.opacity(0.85))
                            .multilineTextAlignment(.center)
                        Text("core \(coreVersion)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.white.opacity(0.4))
                    }

                    Button {
                        runCoreCheck()
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
            .navigationBarHidden(true)
        }
        .preferredColorScheme(.dark)
    }

    /// Phase 1 proof: exercise the Rust core live from the running iOS app.
    private func runCoreCheck() {
        let identity = VelaCoreFFI.generateIdentityJSON()
        if identity.contains("hybrid_ek_b64") {
            status = "Secure core OK — device identity generated 🔐"
        } else {
            status = "Core error: \(identity.prefix(80))"
        }
    }
}
