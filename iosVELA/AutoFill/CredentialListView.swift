import SwiftUI

/// Drives the AutoFill UI: biometric-unlock the shared vault, then surface the
/// logins that match the requested service.
@MainActor
final class CredentialListModel: ObservableObject {
    enum State {
        case loading
        case locked(String)       // message (no vault / auth failed / decrypt failed)
        case list([VaultItem])
    }

    @Published var state: State = .loading

    let queries: [String]
    private let repo: VaultRepository
    private let onPick: (VaultItem) -> Void
    let onCancel: () -> Void

    init(queries: [String],
         repo: VaultRepository = VaultRepository(),
         onPick: @escaping (VaultItem) -> Void,
         onCancel: @escaping () -> Void) {
        self.queries = queries
        self.repo = repo
        self.onPick = onPick
        self.onCancel = onCancel
    }

    func pick(_ item: VaultItem) { onPick(item) }

    func unlock() {
        state = .loading
        Task { @MainActor in
            guard repo.hasVault() else {
                state = .locked("No VELA vault on this device.")
                return
            }
            guard let context = await BiometricGate.authenticate(reason: "Unlock VELA to fill a password") else {
                state = .locked("Authentication failed.")
                return
            }
            do {
                let rms = try repo.loadRMS(context: context)
                let items = try repo.load(rms: rms).items
                state = .list(AutofillMatch.logins(items, matching: queries))
            } catch {
                state = .locked("Couldn't open the vault.")
            }
        }
    }
}

struct CredentialListView: View {
    @ObservedObject var model: CredentialListModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("VELA")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { model.onCancel() }
                    }
                }
        }
        .preferredColorScheme(.dark)
        .onAppear { model.unlock() }
    }

    @ViewBuilder
    private var content: some View {
        switch model.state {
        case .loading:
            ProgressView("Unlocking…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .locked(let message):
            VStack(spacing: 16) {
                Image(systemName: "lock.fill").font(.system(size: 44)).foregroundStyle(.green)
                Text(message).font(.callout).foregroundStyle(.secondary)
                Button("Try again") { model.unlock() }
                    .buttonStyle(.borderedProminent).tint(.green)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .list(let logins):
            if logins.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "magnifyingglass").font(.system(size: 40)).foregroundStyle(.secondary)
                    Text("No matching logins").font(.headline)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(logins) { login in
                    Button { model.pick(login) } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(login.name).font(.body).foregroundStyle(.primary)
                            Text(login.subtitle).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }
}
