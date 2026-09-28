import SwiftUI

/// Drives the AutoFill UI: biometric-unlock the shared vault, then surface the
/// credentials the request asked for — or, for iOS 18 text insertion, the card
/// values the user can insert.
@MainActor
final class CredentialListModel: ObservableObject {
    enum State {
        case loading
        case locked(String)       // message (no vault / auth failed / decrypt failed)
        case credentials([VaultItem])
        case texts([CardInsertable])
    }

    @Published var state: State = .loading

    let queries: [String]
    /// iOS 18 "text to insert" mode: offer card values rather than credentials.
    let textInsertMode: Bool
    private let repo: VaultRepository
    private let onPick: (VaultItem) -> Void
    private let onInsert: (String) -> Void
    let onCancel: () -> Void

    init(queries: [String],
         textInsertMode: Bool = false,
         repo: VaultRepository = VaultRepository(),
         onPick: @escaping (VaultItem) -> Void = { _ in },
         onInsert: @escaping (String) -> Void = { _ in },
         onCancel: @escaping () -> Void) {
        self.queries = queries
        self.textInsertMode = textInsertMode
        self.repo = repo
        self.onPick = onPick
        self.onInsert = onInsert
        self.onCancel = onCancel
    }

    func pick(_ item: VaultItem) { onPick(item) }
    func insert(_ text: CardInsertable) { onInsert(text.value) }

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
                state = textInsertMode
                    ? .texts(CardInsert.insertables(from: items))
                    : .credentials(AutofillMatch.logins(items, matching: queries))
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
                .navigationTitle(model.textInsertMode ? "VELA – Insert" : "VELA")
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
        case .credentials(let logins):
            if logins.isEmpty {
                emptyState(icon: "magnifyingglass", message: "No matching logins")
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
        case .texts(let texts):
            if texts.isEmpty {
                emptyState(icon: "creditcard", message: "No cards saved")
            } else {
                List(texts) { text in
                    Button { model.insert(text) } label: {
                        Text(text.label).font(.body).foregroundStyle(.primary)
                    }
                }
            }
        }
    }

    private func emptyState(icon: String, message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: icon).font(.system(size: 40)).foregroundStyle(.secondary)
            Text(message).font(.headline)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
